/*-
 * Copyright (c) 2024 Kyle Evans <kevans@FreeBSD.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <stdbool.h>

#include "libder.h"

#ifndef nitems
#define	nitems(x)	(sizeof((x)) / sizeof((x)[0]))
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

struct libder_object	*libder_obj_alloc_internal(int, size_t, const uint8_t *);
