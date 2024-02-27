/*-
 * Copyright (c) 2024 Kyle Evans <kevans@FreeBSD.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "libder.h"
#include "libder_private.h"

struct memory_write_data {
	uint8_t		*buf;
	size_t		 bufsz;
	size_t		 offset;
};

typedef bool (write_buffer_t)(void *, const uint8_t *, size_t);

static bool
libder_write_object_header(struct libder_ctx *ctx, struct libder_object *obj,
    write_buffer_t *write_buffer, void *cookie)
{
	size_t size;
	uint8_t sizelen, value;

	value = obj->type;
	if (!write_buffer(cookie, &value, sizeof(value)))
		return (false);

	size = obj->disk_size;
	sizelen = libder_size_length(size);

	if (sizelen == 1) {
		assert((size & ~0x7f) == 0);

		value = size;
		if (!write_buffer(cookie, &value, sizeof(value)))
			return (false);
	} else {
		/*
		 * Protocol supports at most 0x7f size bytes, but we can only
		 * do up to a size_t.
		 */
		uint8_t sizebuf[sizeof(size_t)], *sizep;

		sizelen--;	/* Remove the lead byte. */

		value = 0x80 | sizelen;
		if (!write_buffer(cookie, &value, sizeof(value)))
			return (false);

		sizep = &sizebuf[0];
		for (uint8_t i = 0; i < sizelen; i++)
			*sizep++ = (size >> ((sizelen - i - 1) * 8)) & 0xff;

		if (!write_buffer(cookie, &sizebuf[0], sizelen))
			return (false);
	}

	return (true);
}

static bool
libder_write_object_payload(struct libder_ctx *ctx, struct libder_object *obj,
    write_buffer_t *write_buffer, void *cookie)
{

	/* XXX Normalization */
	return (write_buffer(cookie, obj->payload, obj->length));
}

static bool
libder_write_object(struct libder_ctx *ctx, struct libder_object *obj,
    write_buffer_t *write_buffer, void *cookie)
{

	/* Write out this object's header first */
	if (!libder_write_object_header(ctx, obj, write_buffer, cookie))
		return (false);

	/* Write out the payload. */
	if (obj->children == NULL)
		return (libder_write_object_payload(ctx, obj, write_buffer, cookie));

	/* XXX Do we need to sort? */

	/* Recurse on each child. */
	for (struct libder_object *child = obj->children; child != NULL;
	    child = child->next) {
		if (!libder_write_object(ctx, child, write_buffer, cookie))
			return (false);
	}

	return (true);
}

static bool
memory_write(void *cookie, const uint8_t *data, size_t datasz)
{
	struct memory_write_data *mwrite = cookie;
	uint8_t *dst = &mwrite->buf[mwrite->offset];
	size_t left;

	/* Small buffers should have been rejected long before now. */
	left = mwrite->bufsz - mwrite->offset;
	assert(datasz <= left);

	memcpy(dst, data, datasz);
	mwrite->offset += datasz;
	return (true);
}

/*
 * Writes the object rooted at `root` to the buffer.  If `buf` == NULL and
 * `*bufsz` == 0, we'll allocate a buffer just large enough to hold the result
 * and pass the size back via `*bufsz`.  If a pre-allocated buffer is passed,
 * we may still update `*bufsz` if normalization made the buffer smaller.
 *
 * If the buffer is too small, *bufsz will be set to the size of buffer needed.
 */
uint8_t *
libder_write(struct libder_ctx *ctx, struct libder_object *root, uint8_t *buf,
    size_t *bufsz)
{
	struct memory_write_data mwrite = { 0 };
	size_t needed;

	/*
	 * We shouldn't really see buf == NULL with *bufsz != 0 or vice-versa.
	 * Combined, they mean that we should allocate whatever buffer size we
	 * need.
	 */
	if ((buf == NULL && *bufsz != 0) || (buf != NULL && *bufsz == 0))
		return (NULL);	/* XXX Surface error? */

	needed = libder_obj_disk_size(root, true);
	if (needed == 0)
		return (NULL);	/* Overflow */

	/* Allocate if we weren't passed a buffer. */
	if (*bufsz == 0) {
		*bufsz = needed;
		buf = malloc(needed);
		if (buf == NULL)
			return (NULL);
	} else if (needed > *bufsz) {
		*bufsz = needed;
		return (NULL);	/* Insufficient space */
	}

	/* Buffer large enough, write into it. */
	mwrite.buf = buf;
	mwrite.bufsz = *bufsz;
	if (!libder_write_object(ctx, root, &memory_write, &mwrite)) {
		free(buf);
		return (NULL);	/* XXX Error */
	}

	/*
	 * We don't normalize the in-memory representation of the tree, we do
	 * that as we're writing into the buffer.  It could be the case that we
	 * didn't need the full buffer as a result of normalization.
	 */
	*bufsz = mwrite.offset;

	return (buf);
}
