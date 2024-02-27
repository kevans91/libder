/*-
 * Copyright (c) 2024 Kyle Evans <kevans@FreeBSD.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/socket.h>

#include <assert.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <libder.h>

#include "fuzzers.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t sz)
{
	libder_ctx ctx;
	libder_object obj;
	size_t readsz = sz;
	int ret;

	if (sz == 0)
		return (-1);

	ctx = libder_open();
	ret = -1;
	obj = libder_read(ctx, data, &readsz);
	if (obj == NULL || readsz != sz)
		goto out;

	if (obj != NULL) {
		uint8_t *buf = NULL;
		size_t bufsz = 0;

		/*
		 * If we successfully read it, then it shouldn't
		 * overflow.  We're letting libder allocate the buffer,
		 * so we shouldn't be able to hit the 'too small' bit.
		 *
		 * I can't imagine what other errors might happen, so
		 * we'll just assert on it.
		 */
		buf = libder_write(ctx, obj, buf, &bufsz);
		if (buf == NULL)
			goto out;

		assert(bufsz != 0);

		/*
		 * The normalization we apply should always (at the moment)
		 * result in a buffer no larger than the one we had initially
		 * constructed the object in, so let's make sure of that.  This
		 * assertion has already found one bug in variable length
		 * decoding.
		 */
		assert(bufsz <= readsz);

		free(buf);
	}

	ret = 0;

out:
	libder_obj_free(obj);
	libder_close(ctx);

	return (ret);
}
