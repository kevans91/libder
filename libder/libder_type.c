/*-
 * Copyright (c) 2024 Kyle Evans <kevans@FreeBSD.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdint.h>
#include <stdlib.h>

#include "libder_private.h"

uint8_t
libder_type_simple_abi(const struct libder_tag *type)
{

	return (libder_type_simple(type));
}

/*
 * We'll likely expose this in the form of libder_type_import(), which validates
 * and allocates a tag.
 */
LIBDER_PRIVATE struct libder_tag *
libder_type_alloc(void)
{

	return (calloc(1, sizeof(struct libder_tag)));
}

LIBDER_PRIVATE void
libder_type_release(struct libder_tag *type)
{

	if (type->tag_encoded) {
		free(type->tag_long);
		type->tag_long = NULL;

		/*
		 * Leaving type->tag_encoded set in case it helps us catch some
		 * bogus re-use of the type; we'd surface that as a null ptr
		 * deref as they think they should be using tag_long.
		 */
	}
}

LIBDER_PRIVATE void
libder_type_free(struct libder_tag *type)
{

	if (type == NULL)
		return;

	libder_type_release(type);
	free(type);
}

LIBDER_PRIVATE void
libder_normalize_type(struct libder_ctx *ctx, struct libder_tag *type)
{
	uint8_t tagval;

	if (!type->tag_encoded || !DER_NORMALIZING(ctx, TAGS))
		return;
	if (type->tag_size != 1 || (type->tag_long[0] & ~0x1f) != 0)
		return;

	tagval = type->tag_long[0];

	free(type->tag_long);
	type->tag_short = tagval;
	type->tag_encoded = false;
}
