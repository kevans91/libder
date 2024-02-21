/*-
 * Copyright (c) 2024 Kyle Evans <kevans@FreeBSD.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "libder_private.h"

#undef	DER_CHILDREN
#undef	DER_NEXT

#define	DER_CHILDREN(obj)	((obj)->children)
#define	DER_NEXT(obj)		((obj)->next)

struct libder_object *
libder_obj_alloc(struct libder_ctx *ctx, int type, size_t length,
    const uint8_t *payload_in)
{
	struct libder_object *obj;
	uint8_t *payload;

	if ((length == 0 && payload != NULL) ||
	    (length != 0 && payload == NULL)) {
		libder_set_error(ctx, LDE_INVAL);
		return (NULL);
	}

	if (length > 0) {
		payload = malloc(length);
		if (payload == NULL) {
			libder_set_error(ctx, LDE_NOMEM);
			return (NULL);
		}

		memcpy(payload, payload_in, length);
	} else {
		payload = NULL;
	}

	obj = libder_obj_alloc_internal(type, length, payload);
	if (obj == NULL) {
		free(payload);
		libder_set_error(ctx, LDE_NOMEM);
	}

	return (obj);
}

/*
 * Returns an obj on success, NULL if out of memory.  `obj` takes ownership of
 * the payload on success.
 */
LIBDER_PRIVATE struct libder_object *
libder_obj_alloc_internal(int type, size_t length, uint8_t *payload)
{
	struct libder_object *obj;

	if (length != 0)
		assert(payload != NULL);
	else
		assert(payload == NULL);

	obj = malloc(sizeof(*obj));
	if (obj == NULL)
		return (NULL);

	obj->type = type;
	obj->length = length;
	obj->payload = payload;
	obj->children = obj->next = NULL;

	return (obj);
}

void
libder_obj_free(struct libder_object *obj)
{
	struct libder_object *child, *tmp;

	if (obj == NULL)
		return;

	DER_FOREACH_CHILD_SAFE(child, obj, tmp)
		libder_obj_free(child);

	free(obj->payload);
	free(obj);
}

struct libder_object *
libder_obj_child(const struct libder_object *obj, size_t idx)
{
	struct libder_object *cur;

	DER_FOREACH_CHILD(cur, obj) {
		if (idx-- == 0)
			return (cur);
	}

	return (NULL);
}

struct libder_object *
libder_obj_children(const struct libder_object *obj)
{

	return (obj->children);
}

struct libder_object *
libder_obj_next(const struct libder_object *obj)
{

	return (obj->next);
}

int
libder_obj_type(const struct libder_object *obj)
{

	return (obj->type);
}
