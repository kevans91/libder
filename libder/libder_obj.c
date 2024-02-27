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

LIBDER_PRIVATE size_t
libder_size_length(size_t sz)
{
	size_t nbytes;

	/*
	 * With DER, we use the smallest encoding necessary: less than 0x80
	 * can be encoded in one byte.
	 */
	if (sz < 0x80)
		return (1);

	/*
	 * We can support up to 0x7f size bytes, but we don't really have a way
	 * to represent that right now.  It's a good thing this function only
	 * takes a size_t, otherwise this would be a bit wrong.
	 */
	for (nbytes = 1; nbytes < sizeof(size_t); nbytes++) {
		if ((sz & ~((1ULL << 8 * nbytes) - 1)) == 0)
			break;
	}

	/* Add one for the lead byte describing the length of the length. */
	return (nbytes + 1);
}

/*
 * Returns the size on-disk.  If an object has children, we encode the size as
 * the sum of their lengths recursively.  Otherwise, we use the object's size.
 *
 * Returns 0 if the object size would overflow a size_t... perhaps we could
 * lift this restriction later.
 *
 * Note that the size of the object will be set/updated to simplify later write
 * calculations.
 */
LIBDER_PRIVATE size_t
libder_obj_disk_size(struct libder_object *obj, bool include_header)
{
	struct libder_object *walker;
	size_t disk_size, header_size;

	disk_size = obj->length;
	if (obj->children != NULL) {
		/* We should have rejected these. */
		assert(obj->length == 0);

		for (walker = obj->children; walker != NULL; walker = walker->next) {
			size_t child_size;

			child_size = libder_obj_disk_size(walker, true);
			if (SIZE_MAX - child_size < disk_size)
				return (0);	/* Overflow */
			disk_size += child_size;
		}
	}

	obj->disk_size = disk_size;

	/*
	 * Children always include the header above, we only include the header
	 * at the root if we're calculating how much space we need in total.
	 */
	if (include_header) {
		/* Size of the length + the tag */
		header_size = libder_size_length(disk_size) + 1;
		if (SIZE_MAX - header_size < disk_size)
			return (0);

		disk_size += header_size;
	}

	return (disk_size);
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

static void
libder_obj_dump_internal(const struct libder_object *obj, FILE *fp, int lvl)
{
	static char spacer[4096];

	/* Primitive, goofy, but functional. */
	if (spacer[0] == '\0')
		memset(spacer, ' ', sizeof(spacer));

	if (lvl == sizeof(spacer) / 2) {
		fprintf(fp, "%.*s...\n", lvl * 2, spacer);
		return;
	}

	if (obj->children == NULL) {
		fprintf(fp, "%.*sOBJECT[type=%x, size=%zx]\n", lvl * 2, spacer,
		    obj->type, obj->length);
		return;
	}

	fprintf(fp, "%.*sOBJECT[type=%x]\n", lvl * 2, spacer, obj->type);
	for (obj = obj->children; obj != NULL; obj = obj->next)
		libder_obj_dump_internal(obj, fp, lvl + 1);
}

void
libder_obj_dump(const struct libder_object *root, FILE *fp)
{

	libder_obj_dump_internal(root, fp, 0);
}
