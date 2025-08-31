/*-
 * Copyright (c) 2025 Kyle Evans <kevans@FreeBSD.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libder.h>

static uint8_t
parse_type(const char *type, size_t typesz)
{
	char *endp;
	long val;

	/* For now, we only support numeric spec */
	errno = 0;
	val = strtol(type, &endp, 0);
	if (errno != 0) {
		err(1, "Type value %.*s", (int)typesz, type);
	} else if (*endp != ':') {
		errx(1, "Bad type value (only numeric accepted for now): %.*s",
		    (int)typesz, type);
	} else if (val < 0 || val > UCHAR_MAX) {
		errx(1, "Type value out of range (0-255): %.*s",
		    (int)typesz, type);
	}

	return ((uint8_t)val);
}

static uint8_t *
parse_payload(const char *val, size_t *osz)
{
	uint8_t *payload;
	size_t psz, valsz;

	if (*val == '\0') {
		*osz = 0;
		return (NULL);
	}

	/* No including the NUL terminator here. */
	valsz = strlen(val);
	payload = calloc(1, valsz);
	if (payload == NULL)
		err(1, "malloc");

	psz = 0;
	for (size_t idx = 0; idx < valsz; idx++) {
		char c = val[idx];

		if (c == '\\') {
			unsigned int hexconv;
			char n;

			if (idx == (valsz - 1)) {
				errx(1, "Malformed escape at end of val: %s",
				    val);
			}

			n = val[++idx];
			switch (n) {
			case 'x':
				if (idx + 2 >= valsz) {
					errx(1, "Malformed hex escape: %s",
					    val);
				}

				if (sscanf(&val[idx + 1], "%2x", &hexconv) != 1) {
					errx(1, "Malformed hex escape: %s",
					    val);
				}

				assert(hexconv <= UCHAR_MAX);
				payload[psz++] = hexconv;

				/* Advance to the end of the hex escape. */
				idx += 2;
				break;
			case '\\':
			default:
				payload[psz++] = n;
				continue;
			}
		} else {
			payload[psz++] = c;
		}
	}

	*osz = psz;
	return (payload);
}

static struct libder_object *
parse_tvpair(struct libder_ctx *ctx, const char *tval)
{
	struct libder_object *obj;
	uint8_t *payload;
	const char *val;
	size_t payloadsz;
	uint8_t type;

	val = strchr(tval, ':');
	if (val == NULL)
		errx(1, "Malformed description (missing :): %s", tval);

	type = parse_type(tval, val - tval);
	val++;	/* Skip the delimiter */

	payload = parse_payload(val, &payloadsz);
	assert(payload != NULL || payloadsz == 0);

	return (libder_obj_alloc_simple(ctx, type, payload, payloadsz));
}

static int
derbuild_object(struct libder_ctx *ctx, struct libder_object *container,
    int ndesc, const char *desc[])
{
	struct libder_object *lastobj = container;
	int i;

	for (i = 0; i < ndesc; i++) {
		const char *arg = desc[i];

		if (strcmp(arg, "{") == 0) {
			int consumed, nremain;

			i++;	/* Skip the opener */
			nremain = ndesc - i;
			consumed = derbuild_object(ctx, lastobj, nremain,
			    &desc[i]);
			assert(consumed <= nremain);

			/*
			 * Should have consumed at least a closing brace, even
			 * if we were given an empty child list for some reason.
			 */
			if (consumed == 0)
				errx(1, "Malformed child list (none consumed)");

			/*
			 * Skip to the last token, sanity check it, then let
			 * the loop advance.
			 */
			i += consumed - 1;
			if (strcmp(desc[i], "}") != 0)
				errx(1, "Malformed child list (missing closing brace)");

			continue;
		} else if (strcmp(arg, "}") == 0) {
			return (i + 1);
		}

		lastobj = parse_tvpair(ctx, desc[i]);
		if (lastobj == NULL)
			errx(1, "Bad description: %s\n", desc[i]);

		libder_obj_append(container, lastobj);
	}

	return (i);
}

int
main(int argc, char *argv[])
{
	FILE *fp;
	struct libder_ctx *ctx;
	struct libder_object *root;
	uint8_t *obuf = NULL;
	size_t obufsz, rootsz, writesz;
	int consumed;
	bool first = true;

	if (argc < 2) {
		fprintf(stderr, "usage: %s type:data ...\n", argv[0]);
		return (1);
	}

	argc--;
	argv++;

	ctx = libder_open();
	libder_set_verbose(ctx, 2);
	root = libder_obj_alloc_simple(ctx, BT_SEQUENCE, NULL, 0);
	assert(root != NULL);

	consumed = derbuild_object(ctx, root, argc, (const char **)argv);
	if (consumed != argc)
		errx(1, "malformed description, did not consume all arguments");

	obufsz = 0;
	obuf = libder_write(ctx, root, NULL, &obufsz);
	assert(obuf != NULL);
	assert(obufsz != 0);

	errno = 0;
	writesz = fwrite(obuf, 1, obufsz, stdout);
	if (writesz != obufsz)
		err(1, "fwrite");

	libder_close(ctx);

	return (0);
}
