/*-
 * Copyright (c) 2024 Kyle Evans <kevans@FreeBSD.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>

#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libder.h>

#include "fuzzers.h"

#define	LARGE_SIZE	(1024 * 64)

/* 64k */
#define	LARGE_SIZE_ENCODING	0x83, 0x01, 0x00, 0x00

#define	VARLEN_SEQ	BT_OCTETSTRING, 0x04, 0x01, 0x02, 0x03, 0x04
#define	VARLEN_CHILDREN	VARLEN_SEQ, VARLEN_SEQ, VARLEN_SEQ
static const uint8_t empty_seq[] = { BT_SEQUENCE, 0x00 };
static const uint8_t long_size[21] = { BT_OCTETSTRING, 0x83, 0x00, 0x00, 0x10 };
static const uint8_t large_octet[LARGE_SIZE + 5] = { BT_OCTETSTRING, LARGE_SIZE_ENCODING };
static const uint8_t varlen[] = { BT_SEQUENCE, 0x80,
    VARLEN_CHILDREN, 0x00, 0x00 };

#define	FUZZER_SEED(seq)	{ #seq, sizeof(seq), seq }
static const struct seed {
	const char	*seed_name;
	size_t		 seed_seqsz;
	const uint8_t	*seed_seq;
} seeds[] = {
	FUZZER_SEED(empty_seq),
	FUZZER_SEED(long_size),
	FUZZER_SEED(large_octet),
	FUZZER_SEED(varlen),
};

int
main(int argc, char *argv[])
{
	struct fuzz_params params;
	const struct seed *seed;
	char *name;
	int dirfd = -1, fd = -1;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <corpus-dir>\n", argv[0]);
		return (1);
	}

	dirfd = open(argv[1], O_SEARCH);
	if (dirfd == -1)
		err(1, "%s: open", argv[1]);

	memset(&params, 0, sizeof(params));

	for (int type = 0; type < STREAM_END; type++) {
		params.type = type;

		for (int buffered = 0; buffered < BUFFER_END; buffered++) {
			params.buftype = buffered;

			for (size_t i = 0; i < nitems(seeds); i++) {
				seed = &seeds[i];
				assert(asprintf(&name, "base_%d_%d_%s", type,
				    buffered, seed->seed_name) != -1);

				fd = openat(dirfd, name, O_RDWR | O_TRUNC | O_CREAT, 0644);
				assert(fd != -1);

				/* Write our params + seed */
				assert(write(fd, &params, sizeof(params)) == sizeof(params));
				assert(write(fd, seed->seed_seq, seed->seed_seqsz) == seed->seed_seqsz);

				free(name);
				close(fd);
				fd = -1;
			}

			if (type != STREAM_FILE)
				break;
		}
	}

	close(dirfd);
}
