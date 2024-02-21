/*-
 * Copyright (c) 2024 Kyle Evans <kevans@FreeBSD.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>

#include "libder_private.h"

#undef libder_set_error

static const char libder_error_nodesc[] = "[Description not available]";

#define	DESCRIBE(err, msg)	{ LDE_ ## err, msg }
static const struct libder_error_desc {
	enum libder_error	 desc_error;
	const char		*desc_str;
} libder_error_descr[] = {
	DESCRIBE(NONE,		"No error"),
	DESCRIBE(NOMEM,		"Out of memory"),
	DESCRIBE(INVAL,		"Invalid parameter"),
	DESCRIBE(SHORTHDR,	"Header too short"),
	DESCRIBE(BADVARLEN,	"Bad variable length encoding"),
	DESCRIBE(LONGLEN,	"Encoded length too large (8 byte max)"),
	DESCRIBE(SHORTDATA,	"Payload not available (too short)"),
	DESCRIBE(GARBAGE,	"Garbage after encoded data"),
};

const char *
libder_get_error(struct libder_ctx *ctx)
{
	const struct libder_error_desc *desc;

	for (size_t i = 0; i < nitems(libder_error_descr); i++) {
		desc = &libder_error_descr[i];

		if (desc->desc_error == ctx->error)
			return (desc->desc_str);
	}

	return (libder_error_nodesc);
}

LIBDER_PRIVATE void
libder_set_error(struct libder_ctx *ctx, int error, const char *file, int line)
{
	ctx->error = error;

	if (ctx->verbose >= 2) {
		fprintf(stderr, "%s: [%s:%d]: %s (%d)\n",
		    __func__, file, line, libder_get_error(ctx), error);
	} else if (ctx->verbose >= 1) {
		fprintf(stderr, "%s: %s (%d)\n", __func__,
		    libder_get_error(ctx), error);
	}
}
