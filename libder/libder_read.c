/*-
 * Copyright (c) 2024 Kyle Evans <kevans@FreeBSD.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libder_private.h"

enum libder_stream_type {
	LDST_NONE,
	LDST_FD,
	LDST_FILE,
};

struct libder_payload {
	bool			 payload_heap;
	uint8_t			*payload_data;
	size_t			 payload_size;
};

struct libder_stream {
	enum libder_stream_type	 stream_type;
	struct libder_ctx	*stream_ctx;
	uint8_t			*stream_buf;
	size_t			 stream_bufsz;

	size_t			 stream_offset;
	size_t			 stream_resid;
	size_t			 stream_consumed;
	size_t			 stream_last_commit;

	union {
		const uint8_t	*stream_src_buf;
		FILE		*stream_src_file;
		int		 stream_src_fd;
	};

	int			 stream_error;
	bool			 stream_eof;
};

static uint8_t *
payload_move(struct libder_payload *payload, size_t *sz)
{
	uint8_t *data;
	size_t datasz;

	data = NULL;
	datasz = payload->payload_size;
	if (payload->payload_heap) {
		data = payload->payload_data;
	} else if (datasz > 0) {
		data = malloc(datasz);
		if (data == NULL)
			return (NULL);

		memcpy(data, payload->payload_data, datasz);
	}

	payload->payload_heap = false;
	payload->payload_data = NULL;
	payload->payload_size = 0;

	*sz = datasz;
	return (data);
}

static void
payload_free(struct libder_payload *payload)
{

	if (!payload->payload_heap)
		return;

	free(payload->payload_data);

	payload->payload_heap = false;
	payload->payload_data = NULL;
	payload->payload_size = 0;
}

static bool
libder_stream_init(struct libder_ctx *ctx, struct libder_stream *stream)
{
	size_t buffer_size;

	stream->stream_ctx = ctx;
	stream->stream_error = 0;
	stream->stream_eof = false;
	stream->stream_offset = 0;
	stream->stream_consumed = 0;
	stream->stream_last_commit = 0;
	if (stream->stream_type == LDST_NONE) {
		assert(stream->stream_src_buf != NULL);
		assert(stream->stream_bufsz != 0);
		assert(stream->stream_resid != 0);

		return (true);
	}

	buffer_size = libder_get_buffer_size(ctx);
	assert(buffer_size != 0);

	stream->stream_buf = malloc(buffer_size);
	if (stream->stream_buf == NULL) {
		libder_set_error(ctx, LDE_NOMEM);
	} else {
		stream->stream_bufsz = buffer_size;
		stream->stream_resid = 0;	/* Nothing read yet */
	}

	return (stream->stream_buf != NULL);
}

static void
libder_stream_free(struct libder_stream *stream)
{
	free(stream->stream_buf);
}

static void
libder_stream_commit(struct libder_stream *stream)
{

	if (stream->stream_offset <= stream->stream_last_commit)
		return;

	stream->stream_consumed += stream->stream_offset - stream->stream_last_commit;
	stream->stream_last_commit = stream->stream_offset;
}

static bool
libder_stream_dynamic(const struct libder_stream *stream)
{

	return (stream->stream_type != LDST_NONE);
}

static bool
libder_stream_eof(const struct libder_stream *stream)
{

	/*
	 * We're not EOF until we're both EOF and have processed all of the data
	 * remaining in the buffer.
	 */
	return (stream->stream_eof && stream->stream_resid == 0);
}

static void
libder_stream_repack(struct libder_stream *stream)
{

	/*
	 * Nothing to do, data's already at the beginning.
	 */
	if (stream->stream_offset == 0)
		return;

	/*
	 * If there's data in-flight, we'll repack it back to the beginning so
	 * that we can store more with fewer calls to refill.  If there's no
	 * data in-flight, we naturally just reset the offset.
	 */
	if (stream->stream_resid != 0) {
		uint8_t *dst = &stream->stream_buf[0];
		uint8_t *src = &stream->stream_buf[stream->stream_offset];

		memmove(dst, src, stream->stream_resid);
	}

	stream->stream_last_commit -= stream->stream_offset;
	stream->stream_offset = 0;
}

static const uint8_t *
libder_stream_refill(struct libder_stream *stream, size_t req)
{
	size_t offset = stream->stream_offset;
	const uint8_t *src;
#ifndef NDEBUG
	const uint8_t *bufend;
#endif
	uint8_t *refill_buf;
	size_t bufleft, freadsz, needed, totalsz;
	ssize_t readsz;

	/*
	 * For non-streaming, we just fulfill requests straight out of
	 * the source buffer.
	 */
	if (stream->stream_type == LDST_NONE)
		src = stream->stream_src_buf;
	else
		src = stream->stream_buf;

	if (stream->stream_resid >= req) {
		stream->stream_offset += req;
		stream->stream_resid -= req;
		return (&src[offset]);
	}

	/* Cannot refill the non-streaming type. */
	if (stream->stream_type == LDST_NONE) {
		stream->stream_eof = true;
		return (NULL);
	}

	bufleft = stream->stream_bufsz - (stream->stream_offset + stream->stream_resid);

	/*
	 * If we can't fit all of our data in the remainder of the buffer, we'll
	 * try to repack it to just fit as much as we can in.
	 */
	if (req > bufleft && stream->stream_offset != 0) {
		libder_stream_repack(stream);

		bufleft = stream->stream_bufsz - stream->stream_resid;
		offset = stream->stream_offset;
	}

	refill_buf = &stream->stream_buf[offset + stream->stream_resid];
	needed = req - stream->stream_resid;

	assert(needed <= bufleft);

#ifndef NDEBUG
	bufend = &stream->stream_buf[stream->stream_bufsz];
#endif
	totalsz = 0;

	switch (stream->stream_type) {
	case LDST_FILE:
		assert(stream->stream_src_file != NULL);

		while (needed != 0) {
			assert(refill_buf + needed <= bufend);

			freadsz = fread(refill_buf, 1, needed, stream->stream_src_file);
			if (freadsz == 0) {
				/*
				 * Error always put us into EOF state.
				 */
				stream->stream_eof = true;
				if (ferror(stream->stream_src_file))
					stream->stream_error = 1;
				break;
			}

			stream->stream_resid += freadsz;
			refill_buf += freadsz;
			needed -= freadsz;
			totalsz += freadsz;
		}
		break;
	case LDST_FD:
		assert(stream->stream_src_fd >= 0);

		while (needed != 0) {
			assert(refill_buf + needed <= bufend);

			readsz = read(stream->stream_src_fd, refill_buf, needed);
			if (readsz <= 0) {
				stream->stream_eof = true;
				if (readsz < 0)
					stream->stream_error = errno;
				break;
			}

			stream->stream_resid += readsz;
			refill_buf += readsz;
			needed -= readsz;
			totalsz += readsz;
		}

		break;
	case LDST_NONE:
		assert(0 && "Unrecognized stream type");
		break;
	}

	/*
	 * For streaming types, we commit as soon as we refill the buffer because
	 * we can't just rewind.
	 */
	stream->stream_consumed += totalsz;
	stream->stream_last_commit += totalsz;

	if (needed != 0) {
		if (stream->stream_error != 0)
			libder_set_error(stream->stream_ctx, LDE_STREAMERR);
		return (NULL);
	} else {
		stream->stream_offset += req;
		stream->stream_resid -= req;
	}

	return (&stream->stream_buf[offset]);
}

static int
der_read_structure(struct libder_ctx *ctx, struct libder_stream *stream,
    int *type, struct libder_payload *payload, bool *varlen)
{
	const uint8_t *buf;
	size_t rsz, offset, resid;
	uint8_t bsz;

	rsz = 0;
	if ((buf = libder_stream_refill(stream, 2)) == NULL) {
		if (!libder_stream_eof(stream))
			libder_set_error(ctx, LDE_SHORTHDR);
		return (-1);
	}

	*type = *buf++;
	bsz = *buf++;

#define	LENBIT_LONG	0x80
	*varlen = false;
	if ((bsz & LENBIT_LONG) != 0) {
		/* Long or long form, bsz describes how many bytes we have. */
		bsz &= ~LENBIT_LONG;
		if (bsz != 0) {
			/* Long */
			if (bsz > sizeof(rsz)) {
				libder_set_error(ctx, LDE_LONGLEN);
				return (-1);	/* Only support up to long bytes. */
			} else if ((buf = libder_stream_refill(stream, bsz)) == NULL) {
				libder_set_error(ctx, LDE_SHORTHDR);
				return (-1);
			}

			rsz = 0;
			for (int i = 0; i < bsz; i++) {
				if (i != 0)
					rsz <<= 8;
				rsz |= *buf++;
			}
		} else {
			*varlen = true;
		}
	} else {
		/* Short form */
		rsz = bsz;
	}

	if (rsz != 0) {
		assert(!*varlen);

		/*
		 * If we're not running a dynamic stream, we can just use a
		 * pointer into the buffer.  The caller may copy the payload out
		 * anyways, but there's no sense in doing it up-front in case we
		 * hit an error in between then and now.
		 */
		if (!libder_stream_dynamic(stream)) {
			/*
			 * This is a little dirty, but the caller won't mutate
			 * the data -- it'll either strictly read it, or it will
			 * copy it out to a known-mutable region.
			 */
			payload->payload_data = (void *)libder_stream_refill(stream, rsz);
			payload->payload_heap = false;
			if (payload->payload_data == NULL) {
				libder_set_error(ctx, LDE_SHORTDATA);
				return (-1);
			}
		} else {
			uint8_t *payload_data;

			payload_data = NULL;

			offset = 0;
			resid = rsz;
			while (resid != 0) {
				uint8_t *next_data;
				size_t req;

				req = MIN(stream->stream_bufsz, resid);
				if ((buf = libder_stream_refill(stream, req)) == NULL) {
					free(payload_data);

					libder_set_error(ctx, LDE_SHORTDATA);
					return (-1);
				}

				next_data = realloc(payload_data, offset + req);
				if (next_data == NULL) {
					free(payload_data);

					libder_set_error(ctx, LDE_NOMEM);
					return (-1);
				}

				payload_data = next_data;
				next_data = NULL;

				memcpy(&payload_data[offset], buf, req);
				offset += req;
				resid -= req;
			}

			payload->payload_heap = true;
			payload->payload_data = payload_data;
		}

		payload->payload_size = rsz;
	}

	libder_stream_commit(stream);
	return (0);
}

static struct libder_object *
libder_read_object(struct libder_ctx *ctx, struct libder_stream *stream)
{
	struct libder_payload payload = { 0 };
	struct libder_object *child, **next, *obj;
	struct libder_stream memstream, *childstream;
	int error, type;
	bool varlen;

	/* Peel off one structure. */
	obj = NULL;
	error = der_read_structure(ctx, stream, &type, &payload, &varlen);
	if (error != 0) {
		assert(payload.payload_data == NULL);
		return (NULL);	/* Error already set, if needed. */
	}

	if (type == BT_NULL && (varlen || payload.payload_size != 0)) {
		libder_set_error(ctx, LDE_UNEXPECTED);
		goto out;
	}

	if (!BER_TYPE_CONSTRUCTED(type)) {
		uint8_t *payload_data;
		size_t payloadsz;

		/*
		 * Primitive types cannot use the indefinite form, they must
		 * have an encoded size.
		 */
		if (varlen) {
			libder_set_error(ctx, LDE_UNEXPECTED);
			goto out;
		}

		/*
		 * Copy the payload out now if it's not heap-allocated.
		 */
		payload_data = payload_move(&payload, &payloadsz);
		if (payload_data == NULL) {
			libder_set_error(ctx, LDE_NOMEM);
			return (NULL);
		}

		obj = libder_obj_alloc_internal(type, payloadsz, payload_data);
		if (obj == NULL) {
			free(payload_data);
			libder_set_error(ctx, LDE_NOMEM);
			goto out;
		}
		return (obj);
	}

	obj = libder_obj_alloc_internal(type, 0, NULL);
	if (obj == NULL) {
		libder_set_error(ctx, LDE_NOMEM);
		goto out;
	}

	if (varlen) {
		childstream = stream;
	} else {
		memstream = (struct libder_stream){
			.stream_type = LDST_NONE,
			.stream_bufsz = payload.payload_size,
			.stream_resid = payload.payload_size,
			.stream_src_buf = payload.payload_data,
		};

		childstream = &memstream;
	}

	/* Enumerate children */
	next = &obj->children;
	for (;;) {
		child = libder_read_object(ctx, childstream);
		if (child == NULL) {
			/*
			 * We may not know how much data we have, so this is our
			 * normal terminal condition.
			 */
			if (ctx->error != LDE_NONE) {
				/* Free everything and bubble the error up. */
				libder_obj_free(obj);
				obj = NULL;
			}
			break;
		}

		if (varlen && child->type == BT_RESERVED && child->length == 0) {
			/*
			 * This child is just a marker; free it, don't leak it,
			 * and stop here.
			 */
			libder_obj_free(child);
			/* Error detection */
			varlen = false;
			break;
		}

		*next = child;
		next = &child->next;
	}

	if (varlen) {
		libder_set_error(ctx, LDE_TRUNCVARLEN);
		libder_obj_free(obj);
		obj = NULL;
	}

out:
	payload_free(&payload);
	return (obj);
}

static struct libder_object *
libder_read_stream(struct libder_ctx *ctx, struct libder_stream *stream)
{
	struct libder_object *root;

	ctx->error = LDE_NONE;
	root = libder_read_object(ctx, stream);

	if (root != NULL)
		assert(stream->stream_consumed != 0);
	return (root);
}

/*
 * Read the DER-encoded `data` into `ctx`.
 *
 * Returns an object on success, or NULL on failure.  *datasz is updated to
 * indicate the number of bytes consumed either way -- it will only be updated
 * in the failure case if at least one object was valid.
 */
struct libder_object *
libder_read(struct libder_ctx *ctx, const uint8_t *data, size_t *datasz)
{
	struct libder_stream stream = {
		.stream_type = LDST_NONE,
		.stream_bufsz = *datasz,
		.stream_resid = *datasz,
		.stream_src_buf = data,
	};
	struct libder_object *root;

	ctx->error = LDE_NONE;
	if (!libder_stream_init(ctx, &stream))
		return (NULL);
	root = libder_read_stream(ctx, &stream);
	if (stream.stream_consumed != 0)
		*datasz = stream.stream_consumed;

	return (root);
}

/*
 * Ditto above, but with an fd.  *consumed is not ignored on entry, and returned
 * with the number of bytes read from fd if consumed is not NULL.  libder(3)
 * tries to not over-read if an invalid structure is detected.
 */
struct libder_object *
libder_read_fd(struct libder_ctx *ctx, int fd, size_t *consumed)
{
	struct libder_stream stream = {
		.stream_type = LDST_FD,
		.stream_src_fd = fd,
	};
	struct libder_object *root;

	root = NULL;
	ctx->error = LDE_NONE;
	if (!libder_stream_init(ctx, &stream))
		return (NULL);

	root = libder_read_stream(ctx, &stream);
	if (consumed != NULL && stream.stream_consumed != 0)
		*consumed = stream.stream_consumed;

	libder_stream_free(&stream);
	return (root);
}

/*
 * Ditto above, but with a FILE instead of an fd.
 */
struct libder_object *
libder_read_file(struct libder_ctx *ctx, FILE *fp, size_t *consumed)
{
	struct libder_stream stream = {
		.stream_type = LDST_FILE,
		.stream_src_file = fp,
	};
	struct libder_object *root;

	root = NULL;
	ctx->error = LDE_NONE;
	if (!libder_stream_init(ctx, &stream))
		return (NULL);

	root = libder_read_stream(ctx, &stream);
	if (consumed != NULL && stream.stream_consumed != 0)
		*consumed = stream.stream_consumed;

	libder_stream_free(&stream);
	return (root);
}
