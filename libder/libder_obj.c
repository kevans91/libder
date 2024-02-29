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
	obj->children = obj->next = obj->prev = NULL;
	obj->nchildren = 0;

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

LIBDER_PRIVATE bool
libder_is_valid_obj(uint32_t type, const uint8_t *payload, size_t payloadsz,
    bool varlen)
{

	if (payload != NULL) {
		assert(payloadsz > 0);
		assert(!varlen);
	} else {
		assert(payloadsz == 0);
	}

	switch (type) {
	case BT_NULL:
		return (payloadsz == 0 && !varlen);
	case BT_BITSTRING:
		if (payloadsz == 1 && payload[0] != 0)
			return (false);

		/* We can't have more than seven unused bits. */
		return (payloadsz < 2 || payload[0] < 8);
	default:
		break;
	}

	return (true);
}

LIBDER_PRIVATE bool
libder_obj_may_coalesce_children(const struct libder_object *obj)
{

	/* No clue about non-universal types. */
	if (BER_TYPE_CLASS(obj->type) != BC_UNIVERSAL)
		return (false);

	/* Constructed types don't have children. */
	if (!BER_TYPE_CONSTRUCTED(obj->type))
		return (false);

	/* Strip the constructed bit off. */
	switch (BER_TYPE(obj->type)) {
	case BT_OCTETSTRING:	/* Raw data types */
	case BT_BITSTRING:
		return (true);
	case BT_UTF8STRING:	/* String types */
	case BT_NUMERICSTRING:
	case BT_STRING:
	case BT_TELEXSTRING:
	case BT_VIDEOTEXSTRING:
	case BT_IA5STRING:
	case BT_GFXSTRING:
	case BT_VISSTRING:
	case BT_GENSTRING:
	case BT_UNIVSTRING:
	case BT_CHARSTRING:
	case BT_BMPSTRING:
		return (true);
	case BT_UTCTIME:	/* Time types */
	case BT_GENTIME:
		return (true);
	default:
		return (false);
	}
}

static size_t
libder_merge_bitstrings(uint8_t *buf, size_t offset, size_t bufsz,
    const struct libder_object *child)
{
	const uint8_t *rhs = child->payload;
	size_t rsz = child->disk_size, startoff = offset;
	uint8_t rhsunused, unused;

	rhsunused = (rhs != NULL ? rhs[0] : 0);

	/* We have no unused bits if the buffer's empty as of yet. */
	if (offset == 0)
		unused = 0;
	else
		unused = buf[0];

	/* Shave the lead byte off if we have one. */
	if (rsz > 1) {
		if (rhs != NULL)
			rhs++;
		rsz--;
	}

	if (unused == 0) {
		size_t extra = 0;

		/*
		 * In all cases we'll just write the unused byte separately,
		 * since we're copying way past it in the common case and can't
		 * just overwrite it as part of the memcpy().
		 */
		if (offset == 0) {
			offset = 1;
			extra++;
		}

		assert(rhsunused < 8);
		assert(offset + rsz <= bufsz);

		buf[0] = rhsunused;
		if (rhs == NULL)
			memset(&buf[offset], 0, rsz);
		else
			memcpy(&buf[offset], rhs, rsz);

		return (rsz + extra);
	}

	for (size_t i = 0; i < rsz; i++) {
		uint8_t bits, next;

		if (rhs == NULL)
			next = 0;
		else
			next = rhs[i];

		/* Rotate the leading bits into the byte before it. */
		assert(unused < 8);
		bits = next >> (8 - unused);
		buf[offset - 1] |= bits;

		next <<= unused;

		/*
		 * Copy the new valid bits in; we shift over the old unused
		 * amount up until the very last bit, then we have to recalculate
		 * because we may be dropping it entirely.
		 */
		if (i == rsz - 1) {
			assert(rhsunused < 8);

			/*
			 * Figure out how many unused bits we have between the two
			 * buffers, sum % 8 is the new # unused bits.  It will be
			 * somewhere in the range of [0, 14], and if it's at or
			 * higher than a single byte then that's a clear indicator
			 * that we shifted some unused bits into the previous byte and
			 * can just halt here.
			 */
			unused += rhsunused;
			buf[0] = unused % 8;
			if (unused >= 8)
				break;
		}

		assert(offset < bufsz);
		buf[offset++] = next;
	}

	return (offset - startoff);
}

LIBDER_PRIVATE bool
libder_obj_coalesce_children(struct libder_object *obj, struct libder_ctx *ctx)
{
	struct libder_object *child, *tmp;
	size_t new_size = 0, offset = 0;
	uint8_t *coalesced_data;
	unsigned int new_type;
	bool need_payload = false;

	if (!libder_obj_may_coalesce_children(obj))
		return (true);

	assert(BER_TYPE_CLASS(obj->type) == BC_UNIVERSAL);
	assert(BER_TYPE_CONSTRUCTED(obj->type));
	new_type = BER_TYPE(obj->type);
	for (child = obj->children; child != NULL; child = child->next) {
		/* Sanity check and coalesce our children. */
		if (BER_FULL_TYPE(child->type) != new_type) {
			libder_set_error(ctx, LDE_COALESCE_BADCHILD);
			return (false);
		}

		/* Recursively coalesce everything. */
		if (!libder_obj_coalesce_children(child, ctx))
			return (false);

		/*
		 * The child node will be disappearing anyways, so we stash the
		 * disk size sans header in its disk_size to reuse in the later
		 * loop.
		 */
		child->disk_size = libder_obj_disk_size(child, false);

		/*
		 * We strip the lead byte off of every element, and add it back
		 * in pre-allocation.
		 */
		if (new_type == BT_BITSTRING && child->disk_size > 1)
			child->disk_size--;

		new_size += child->disk_size;

		if (child->payload != NULL)
			need_payload = true;
	}

	if (new_size != 0 && need_payload) {
		if (new_type == BT_BITSTRING)
			new_size++;
		coalesced_data = malloc(new_size);
		if (coalesced_data == NULL) {
			libder_set_error(ctx, LDE_NOMEM);
			return (false);
		}
	} else {
		/*
		 * This would perhaps be a bit weird, but that's normalization
		 * for you.  We shouldn't really have a UTF-8 string that's
		 * composed of a series of zero-length UTF-8 strings, but
		 * weirder things have happened.
		 */
		coalesced_data = NULL;
	}

	/* Avoid leaking any children as we coalesce. */
	for (child = obj->children; child != NULL && (tmp = child->next, 1);
	    child = tmp) {
		if (child->disk_size != 0)
			assert(coalesced_data != NULL || !need_payload);
		if (child->disk_size != 0 && need_payload) {
			assert(coalesced_data != NULL);
			assert(offset + child->disk_size <= new_size);

			/*
			 * Bit strings are special, in that the first byte
			 * contains the number of unused bits at the end.  We
			 * need to trim that off when concatenating bit strings
			 */
			if (new_type == BT_BITSTRING) {
				offset += libder_merge_bitstrings(coalesced_data,
				    offset, new_size, child);
			} else {
				/*
				 * Write zeroes out if we don't have a payload.
				 */
				if (child->payload == NULL) {
					memset(&coalesced_data[offset], 0, child->disk_size);
					offset += child->disk_size;
				} else {
					memcpy(&coalesced_data[offset], child->payload,
					    child->disk_size);
					offset += child->disk_size;
				}
			}
		}

		libder_obj_free(child);
	}

	assert(offset <= new_size);

	/* Zap the children, we've absorbed their bodies. */
	obj->children = NULL;

	/* Finally, swap out the payload. */
	free(obj->payload);
	obj->length = offset;
	obj->payload = coalesced_data;
	obj->type = new_type;

	return (true);
}

static bool
libder_obj_normalize_bitstring(struct libder_object *obj)
{
	uint8_t *payload = obj->payload;
	size_t length = obj->length;
	uint8_t unused;

	if (payload == NULL || length < 2)
		return (true);

	unused = payload[0];
	if (unused == 0)
		return (true);

	/* Clear the unused bits completely. */
	payload[length - 1] &= ~((1 << unused) - 1);
	return (true);
}

static bool
libder_obj_normalize_boolean(struct libder_object *obj)
{
	uint8_t *payload = obj->payload;
	size_t length = obj->length;
	int sense = 0;

	/*
	 * Booleans must be collapsed down to a single byte, 0x00 or 0xff,
	 * indicating false or true respectively.
	 */
	if (length == 1 && (payload[0] == 0x00 || payload[0] == 0xff))
		return (true);

	for (size_t bpos = 0; bpos < length - 1; bpos++) {
		sense |= payload[bpos];
	}

	payload[0] = sense != 0 ? 0xff : 0x00;
	obj->length = 1;
	return (true);
}

static bool
libder_obj_normalize_integer(struct libder_object *obj)
{
	uint8_t *payload = obj->payload;
	size_t length = obj->length;
	size_t strip = 0;

	/*
	 * Strip any leading sign-extended looking bytes, but note that
	 * we can't strip a leading byte unless it matches the sign bit
	 * on the next byte.
	 */
	for (size_t bpos = 0; bpos < length - 1; bpos++) {
		if (payload[bpos] != 0 && payload[bpos] != 0xff)
			break;

		if (payload[bpos] == 0xff) {
			/* Only if next byte indicates signed. */
			if ((payload[bpos + 1] & 0x80) == 0)
				break;
		} else {
			/* Only if next byte indicates unsigned. */
			if ((payload[bpos + 1] & 0x80) != 0)
				break;
		}

		strip++;
	}

	if (strip != 0) {
		payload += strip;
		length -= strip;

		memmove(&obj->payload[0], payload, length);
		obj->length = length;
	}

	return (true);
}

static bool
libder_obj_normalize_set(struct libder_object *obj)
{

	if (obj->nchildren < 2)
		return (true);

	return (true);
}

LIBDER_PRIVATE bool
libder_obj_normalize(struct libder_object *obj, struct libder_ctx *ctx)
{
	uint8_t *payload = obj->payload;
	size_t length = obj->length;

	if (BER_TYPE_CONSTRUCTED(obj->type)) {
		/*
		 * For constructed types, we'll see if we can coalesce their
		 * children into them, then we'll proceed with whatever normalization
		 * rules we can apply to the children.
		 */
		if (DER_NORMALIZING(ctx, CONSTRUCTED) && !libder_obj_coalesce_children(obj, ctx))
			return (false);

		/*
		 * We may not be a constructed object anymore after the above coalescing
		 * happened, so we check it again here.  Constructed objects need not go
		 * any further, but the now-primitive coalesced types still need to be
		 * normalized.
		 */
		if (BER_TYPE_CONSTRUCTED(obj->type)) {
			for (struct libder_object *child = obj->children; child != NULL;
			    child = child->next) {
				if (!libder_obj_normalize(child, ctx))
					return (false);
			}

			/* Sets must be sorted. */
			if (obj->type != BT_SET)
				return (true);

			return (libder_obj_normalize_set(obj));
		}
	}

	/* We only have normalization rules for universal types. */
	if (BER_TYPE_CLASS(obj->type) != BC_UNIVERSAL)
		return (true);

	if (!libder_normalizing_type(ctx, obj->type))
		return (true);

	/*
	 * We are clear to normalize this object, check for some easy cases that
	 * don't need normalization.
	 */
	switch (obj->type) {
	case BT_BITSTRING:
	case BT_BOOLEAN:
	case BT_INTEGER:
		/*
		 * If we have a zero payload, then we need to encode them as a
		 * single zero byte.
		 */
		if (payload == NULL) {
			if (length != 1)
				obj->length = 1;

			return (true);
		}

		break;
	default:
		/*
		 * If we don't have a payload, we'll just leave it alone.
		 */
		if (payload == NULL)
			return (true);
		break;
	}

	switch (obj->type) {
	case BT_BITSTRING:
		return (libder_obj_normalize_bitstring(obj));
	case BT_BOOLEAN:
		return (libder_obj_normalize_boolean(obj));
	case BT_INTEGER:
		return (libder_obj_normalize_integer(obj));
	default:
		break;
	}

	return (true);
}
