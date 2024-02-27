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

	ret = 0;
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
		assert(buf != NULL);
		assert(bufsz != 0);

		free(buf);
	}


out:
	libder_obj_free(obj);
	libder_close(ctx);

	return (ret);
}
