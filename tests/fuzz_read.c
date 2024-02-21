/*-
 * Copyright (c) 2024 Kyle Evans <kevans@FreeBSD.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>

#include <stdio.h>

#include <libder.h>

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t sz)
{
	libder_ctx ctx;
	libder_object obj;
	int ret;

	ret = -1;

	if (sz == 0)
		return (-1);

	ctx = libder_open();
	do {
		size_t readsz;

		readsz = sz;
		obj = libder_read(ctx, data, &readsz);
		libder_obj_free(obj);

		if (obj != NULL)
			ret = 0;

		/*
		 * If we hit an entirely invalid segment of the buffer, we'll
		 * just skip a byte and try again.
		 */
		data += MAX(1, readsz);
		sz -= MAX(1, readsz);
	} while (sz != 0);

	libder_close(ctx);

	return (ret);
}
