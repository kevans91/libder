/*-
 * Copyright (c) 2024 Kyle Evans <kevans@FreeBSD.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <sys/param.h>

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
	enum libder_error	 error;
	int			 verbose;
};

struct libder_object {
	int			 type;
	size_t			 length;
	uint8_t			*payload;	/* NULL for sequences */
	struct libder_object	*children;
	struct libder_object	*next;
};

#define	LIBDER_PRIVATE	__attribute__((__visibility__("hidden")))

void	 libder_set_error(struct libder_ctx *, int, const char *, int);

#define	libder_set_error(ctx, error)	\
	libder_set_error((ctx), (error), __FILE__, __LINE__)

struct libder_object	*libder_obj_alloc_internal(int, size_t, uint8_t *);
