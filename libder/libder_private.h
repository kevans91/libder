/*-
 * Copyright (c) 2024 Kyle Evans <kevans@FreeBSD.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <sys/param.h>

#include <assert.h>
#include <stdbool.h>

#include "libder.h"

#ifndef nitems
#define	nitems(x)	(sizeof((x)) / sizeof((x)[0]))
#endif
#ifndef MIN
#define	MIN(a,b) (((a)<(b))?(a):(b))
#endif
#ifndef MAX
#define	MAX(a,b) (((a)>(b))?(a):(b))
#endif

struct libder_ctx;
struct libder_object;

struct libder_ctx {
	uint64_t		 normalize;
	size_t			 buffer_size;
	enum libder_error	 error;
	int			 verbose;
};

struct libder_object {
	size_t			 length;
	size_t			 nchildren;
	size_t			 disk_size;
	uint8_t			*payload;	/* NULL for sequences */
	struct libder_object	*children;
	struct libder_object	*prev;
	struct libder_object	*next;
	unsigned int		 type;
};

#define	LIBDER_PRIVATE	__attribute__((__visibility__("hidden")))

#define	DER_NORMALIZING(ctx, bit)	\
    (((ctx)->normalize & (LIBDER_NORMALIZE_ ## bit)) != 0)

static inline bool
libder_normalizing_type(const struct libder_ctx *ctx, unsigned int type)
{
    assert(!BER_TYPE_CONSTRUCTED(type));
    assert(BER_TYPE_CLASS(type) == BC_UNIVERSAL);
    return ((ctx->normalize & ((1ULL << type) << 32ULL)) != 0);
}

size_t	 libder_get_buffer_size(struct libder_ctx *);
void	 libder_set_error(struct libder_ctx *, int, const char *, int);

#define	libder_set_error(ctx, error)	\
	libder_set_error((ctx), (error), __FILE__, __LINE__)

struct libder_object	*libder_obj_alloc_internal(int, size_t, uint8_t *);
size_t			 libder_size_length(size_t);
bool			 libder_is_valid_obj(uint32_t, const uint8_t *, size_t,
			    bool);
size_t			 libder_obj_disk_size(struct libder_object *, bool);
bool			 libder_obj_may_coalesce_children(const struct libder_object *);
bool			 libder_obj_coalesce_children(struct libder_object *, struct libder_ctx *);
bool			 libder_obj_normalize(struct libder_object *, struct libder_ctx *);
