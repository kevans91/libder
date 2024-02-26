/*-
 * Copyright (c) 2024 Kyle Evans <kevans@FreeBSD.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "libder_private.h"

#include <stdlib.h>
#include <unistd.h>

/*
 * Sets up the context, returns NULL on error.
 */
struct libder_ctx *
libder_open(void)
{
	struct libder_ctx *ctx;

	ctx = malloc(sizeof(*ctx));
	if (ctx == NULL)
		return (NULL);

	/* Initialize */
	ctx->error = LDE_NONE;
	ctx->buffer_size = 0;
	ctx->verbose = 0;

	return (ctx);
}

LIBDER_PRIVATE size_t
libder_get_buffer_size(struct libder_ctx *ctx)
{

	if (ctx->buffer_size == 0) {
		long psize;

		psize = sysconf(_SC_PAGESIZE);
		if (psize <= 0)
			psize = 4096;

		ctx->buffer_size = psize;
	}

	return (ctx->buffer_size);
}

void
libder_set_verbose(struct libder_ctx *ctx, int verbose)
{

	ctx->verbose = verbose;
}

void
libder_close(struct libder_ctx *ctx)
{

	if (ctx == NULL)
		return;

	free(ctx);
}

