/*-
 * Copyright (c) 2024 Kyle Evans <kevans@FreeBSD.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/stat.h>

#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libder.h>

/*
 * Note that the choice of secp112r1 is completely arbitrary.  I was mainly
 * shooting for something pretty weak to avoid people trying to "catch me"
 * checking in private key material, even though it's very incredibly clearly
 * just for a test case.
 */
static const uint8_t oid_secp112r1[] =
    { 0x2b, 0x81, 0x04, 0x00, 0x06 };

static const uint8_t privdata[] = { 0xa5, 0xf5, 0x2a, 0x56, 0x61, 0xe3, 0x58,
    0x76, 0x5c, 0x4f, 0xd6, 0x8d, 0x60, 0x54 };

static const uint8_t pubdata[] = { 0x00, 0x04, 0xae, 0x69, 0x41, 0x0d, 0x9c,
    0x9b, 0xf2, 0x34, 0xf6, 0x2d, 0x7c, 0x91, 0xe1, 0xc7, 0x7f, 0x23, 0xa0,
    0x84, 0x34, 0x5c, 0x38, 0x26, 0xd8, 0xcf, 0xbe, 0xf7, 0xdc, 0x8a };

static void
test_interface(libder_object root)
{
	const uint8_t *data;
	size_t datasz;
	libder_object keystring, oid;

	libder_tag objtype;

	/* Grab the oid first. */
	oid = libder_obj_child(root, 2);
	assert(oid != NULL);	/* Actually just the container... */
	assert(libder_type_simple(libder_obj_type(oid)) == 0xa0);

	oid = libder_obj_child(oid, 0);
	assert(oid != NULL);	/* Now *that*'s an OID. */
	assert(libder_type_simple(libder_obj_type(oid)) == BT_OID);
	data = libder_obj_data(oid, &datasz);
	assert(datasz == sizeof(oid_secp112r1));
	assert(memcmp(oid_secp112r1, data, datasz) == 0);

	keystring = libder_obj_child(root, 1);
	assert(keystring != NULL);

	objtype = libder_obj_type(keystring);
	assert(objtype != NULL);
	assert(libder_type_simple(objtype) == BT_OCTETSTRING);

	data = libder_obj_data(keystring, &datasz);
	assert(datasz == sizeof(privdata));
	assert(memcmp(privdata, data, datasz) == 0);
}

/* buf and bufszs are just our reference */
static void
test_construction(libder_ctx ctx, const uint8_t *buf, size_t bufsz)
{
	uint8_t *out;
	libder_object obj, oidp, pubp, root;
	libder_object keystring;
	libder_tag type;
	size_t outsz;
	uint8_t data;

	type = libder_type_alloc_simple(ctx, BT_SEQUENCE);
	assert(type != NULL);

	root = libder_obj_alloc(ctx, type, NULL, 0);
	assert(root != NULL);
	libder_type_free(type);

	type = libder_type_alloc_simple(ctx, BT_INTEGER);
	assert(type != NULL);

	data = 1;
	obj = libder_obj_alloc(ctx, type, &data, 1);
	assert(obj != NULL);
	assert(libder_obj_append(root, obj));
	libder_type_free(type);

	/* Private key material */
	type = libder_type_alloc_simple(ctx, BT_OCTETSTRING);
	assert(type != NULL);

	obj = libder_obj_alloc(ctx, type, privdata, sizeof(privdata));
	assert(obj != NULL);
	assert(libder_obj_append(root, obj));
	libder_type_free(type);

	/* Now throw in the OID and pubkey containers */
	type = libder_type_alloc_simple(ctx,
	    (BC_CONTEXT << 6) | BER_TYPE_CONSTRUCTED_MASK | 0);
	assert(type != NULL);

	oidp = libder_obj_alloc(ctx, type, NULL, 0);
	assert(oidp != NULL);
	assert(libder_obj_append(root, oidp));
	libder_type_free(type);

	type = libder_type_alloc_simple(ctx,
	    (BC_CONTEXT << 6) | BER_TYPE_CONSTRUCTED_MASK | 1);
	assert(type != NULL);

	pubp = libder_obj_alloc(ctx, type, NULL, 0);
	assert(pubp != NULL);
	assert(libder_obj_append(root, pubp));
	libder_type_free(type);

	/* Actually add the OID */
	type = libder_type_alloc_simple(ctx, BT_OID);
	assert(type != NULL);

	obj = libder_obj_alloc(ctx, type, oid_secp112r1, sizeof(oid_secp112r1));
	assert(obj != NULL);
	assert(libder_obj_append(oidp, obj));
	libder_type_free(type);

	/* Finally, add the pubkey */
	type = libder_type_alloc_simple(ctx, BT_BITSTRING);
	assert(type != NULL);

	obj = libder_obj_alloc(ctx, type, pubdata, sizeof(pubdata));
	assert(obj != NULL);
	assert(libder_obj_append(pubp, obj));
	libder_type_free(type);

	out = NULL;
	outsz = 0;
	out = libder_write(ctx, root, out, &outsz);
	assert(out != NULL);
	assert(outsz == bufsz);

	assert(memcmp(out, buf, bufsz) == 0);

	libder_obj_free(root);
	free(out);
}

int
main(int argc, char *argv[])
{
	struct stat sb;
	libder_ctx ctx;
	libder_object root;
	uint8_t *buf, *out;
	size_t bufsz, outsz, rootsz;
	ssize_t readsz;
	int error, fd;

	fd = open("repo.priv", O_RDONLY);
	assert(fd >= 0);

	error = fstat(fd, &sb);
	assert(error == 0);

	bufsz = sb.st_size;
	buf = malloc(bufsz);
	assert(buf != NULL);

	readsz = read(fd, buf, bufsz);
	close(fd);

	assert(readsz == bufsz);

	ctx = libder_open();
	rootsz = bufsz;
	libder_set_verbose(ctx, 2);
	root = libder_read(ctx, buf, &rootsz);

	assert(root != NULL);
	assert(rootsz == bufsz);

	test_interface(root);
	test_construction(ctx, buf, bufsz);

	outsz = 0;
	out = NULL;
	out = libder_write(ctx, root, out, &outsz);
	assert(out != NULL);
	assert(outsz == bufsz);

	assert(memcmp(buf, out, outsz) == 0);

	free(out);
	free(buf);
	libder_obj_free(root);
	libder_close(ctx);
}
