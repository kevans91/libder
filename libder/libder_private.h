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

struct libder_tag {
	union {
		uint8_t		 tag_short;
		uint8_t		*tag_long;
	};
	size_t			 tag_size;
	enum libder_ber_class	 tag_class;
	bool			 tag_constructed;
	bool			 tag_encoded;
};

struct libder_object {
	struct libder_tag	*type;
	size_t			 length;
	size_t			 nchildren;
	size_t			 disk_size;
	uint8_t			*payload;	/* NULL for sequences */
	struct libder_object	*children;
	struct libder_object	*next;
};

#define	LIBDER_PRIVATE	__attribute__((__visibility__("hidden")))

#define	DER_NORMALIZING(ctx, bit)	\
    (((ctx)->normalize & (LIBDER_NORMALIZE_ ## bit)) != 0)

static inline bool
libder_normalizing_type(const struct libder_ctx *ctx, const struct libder_tag *type)
{
	assert(!type->tag_constructed);
	assert(type->tag_class == BC_UNIVERSAL);
	assert(type->tag_size <= sizeof(type->tag_short));

	return ((ctx->normalize & ((1ULL << type->tag_short) << 32ULL)) != 0);
}

/* All of the lower bits set. */
#define	BER_TYPE_LONG_MASK	0x1f

/*
 * Check if the type matches one of our universal types.
 */
static inline bool
libder_type_is(const struct libder_tag *type, uint8_t utype)
{

	assert(BER_TYPE_CLASS(utype) == BC_UNIVERSAL);
	if (type->tag_class != BC_UNIVERSAL)
		return (false);
	assert(type->tag_size <= sizeof(type->tag_short));
	if ((utype & BER_TYPE_CONSTRUCTED_MASK) != type->tag_constructed)
		return (false);

	utype &= ~BER_TYPE_CONSTRUCTED_MASK;
	return (utype == type->tag_short);
}

/*
 * We'll use this one a decent amount, so we'll keep it inline.  There's also
 * an _abi version that we expose as public interface via a 'libder_type_simple'
 * macro.
 */
#undef libder_type_simple

static inline uint8_t
libder_type_simple(const struct libder_tag *type)
{
	uint8_t encoded = 0;

	assert(!type->tag_encoded);
	if (type->tag_constructed)
		encoded |= BER_TYPE_CONSTRUCTED_MASK;

	encoded |= type->tag_short;
	return (encoded);
}

size_t	 libder_get_buffer_size(struct libder_ctx *);
void	 libder_set_error(struct libder_ctx *, int, const char *, int);

#define	libder_set_error(ctx, error)	\
	libder_set_error((ctx), (error), __FILE__, __LINE__)

struct libder_object	*libder_obj_alloc_internal(struct libder_tag *,
			    size_t, uint8_t *);
size_t			 libder_size_length(size_t);
bool			 libder_is_valid_obj(const struct libder_tag *,
			    const uint8_t *, size_t, bool);
size_t			 libder_obj_disk_size(struct libder_object *, bool);
bool			 libder_obj_may_coalesce_children(const struct libder_object *);
bool			 libder_obj_coalesce_children(struct libder_object *, struct libder_ctx *);
bool			 libder_obj_normalize(struct libder_object *, struct libder_ctx *);


struct libder_tag	*libder_type_alloc(void);
void			 libder_type_release(struct libder_tag *);
void			 libder_type_free(struct libder_tag *);
void			 libder_normalize_type(struct libder_ctx *, struct libder_tag *);
