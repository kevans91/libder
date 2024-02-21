/*-
 * Copyright (c) 2024 Kyle Evans <kevans@FreeBSD.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "libder_private.h"

#include <stdlib.h>

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
	ctx->verbose = 0;

	return (ctx);
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

