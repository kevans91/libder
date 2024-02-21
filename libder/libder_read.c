/*-
 * Copyright (c) 2024 Kyle Evans <kevans@FreeBSD.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "libder_private.h"

static int
der_read_structure(struct libder_ctx *ctx, const uint8_t **data, size_t *datasz,
    int *type, const uint8_t **payload, size_t *payloadsz, bool *varlen)
{
	const uint8_t *buf = *data;
	size_t insz = *datasz, rsz;
	uint8_t bsz;

	if (insz < 2) {
		libder_set_error(ctx, LDE_SHORTHDR);
		return (-1);
	}

	*type = *buf++;
	insz--;

	bsz = *buf++;
	insz--;

#define	LENBIT_LONG	0x80
	*varlen = false;
	if ((bsz & LENBIT_LONG) != 0) {
		/* Long or long form, bsz describes how many bytes we have. */
		bsz &= ~LENBIT_LONG;
		if (bsz != 0) {
			/* Long */
			if (insz < bsz) {
				libder_set_error(ctx, LDE_SHORTHDR);
				return (-1);
			} else if (bsz > sizeof(rsz)) {
				libder_set_error(ctx, LDE_LONGLEN);
				return (-1);	/* Only support up to 8 bytes. */
			}

			rsz = 0;
			for (int i = 0; i < bsz; i++) {
				if (i != 0)
					rsz <<= 8;
				rsz |= *buf++;
				insz--;
			}
		} else {
			*varlen = true;
		}
	} else {
		/* Short form */
		rsz = bsz;
	}

	if (rsz > insz) {
		libder_set_error(ctx, LDE_SHORTDATA);
		return (-1);
	}

	*payloadsz = rsz;
	if (payload != NULL) {
		if (rsz > 0)
			*payload = buf;
		else
			*payload = NULL;
	}

	buf += rsz;
	*datasz -= (buf - *data);

	*data = buf;

	return (0);
}

static struct libder_object *
libder_read_object(struct libder_ctx *ctx, const uint8_t **data, size_t *datasz)
{
	struct libder_object *child, **next, *obj;
	const uint8_t *childbuf, *payload;
	size_t childbufsz, payloadsz;
	int error, type;
	bool varlen;

	if (*datasz == 0)
		return (NULL);

	/* Peel off one structure. */
	error = der_read_structure(ctx, data, datasz, &type, &payload, &payloadsz,
	    &varlen);
	if (error != 0)
		return (NULL);	/* Error already set. */

	if (type == BT_NULL && (varlen || payloadsz != 0)) {
		libder_set_error(ctx, LDE_UNEXPECTED);
		return (NULL);
	}

	if (type != BT_SEQUENCE && type != BT_SET && !varlen) {
		obj = libder_obj_alloc_internal(type, payloadsz, payload);
		if (obj == NULL)
			libder_set_error(ctx, LDE_NOMEM);
		return (obj);
	}

	obj = libder_obj_alloc_internal(type, 0, NULL);
	if (obj == NULL) {
		libder_set_error(ctx, LDE_NOMEM);
		return (NULL);
	}

	/* Enumerate children */
	next = &obj->children;

	childbuf = payload;
	childbufsz = payloadsz;
	while (childbufsz != 0) {
		child = libder_read_object(ctx, &childbuf, &childbufsz);
		if (child == NULL) {
			assert(ctx->error != LDE_NONE);

			/* Free everything and bubble the error up. */
			libder_obj_free(obj);
			obj = NULL;

			break;
		}

		if (varlen && child->type == BT_RESERVED && child->length == 0) {
			/*
			 * This child is just a marker; free it, don't leak it,
			 * and stop here.
			 */
			libder_obj_free(child);

			break;
		}

		*next = child;
		next = &child->next;
	}

	return (obj);
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
	struct libder_object *root;
	size_t insz = *datasz;

	/* XXX Configurable max depth? */
	if (insz != 0) {
		root = libder_read_object(ctx, &data, &insz);
		if (root != NULL)
			assert(insz != *datasz);
		if (insz != *datasz)
			*datasz -= insz;
	}

	return (root);
}
