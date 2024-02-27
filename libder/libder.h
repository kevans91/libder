/*-
 * Copyright (c) 2024 Kyle Evans <kevans@FreeBSD.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

enum libder_ber_type {
	BT_RESERVED = 0x00,
	BT_BOOLEAN = 0x01,
	BT_INTEGER = 0x02,
	BT_BITSTRING = 0x03,
	BT_OCTETSTRING = 0x04,
	BT_NULL = 0x05,
	BT_OID = 0x06,
	BT_OBJDESC = 0x07,
	BT_EXTERNAL = 0x08,
	BT_REAL = 0x09,
	BT_ENUMERATED = 0x0a,
	BT_PDV = 0x0b,
	BT_UTF8STRING =  0x0c,
	BT_RELOID = 0x0d,

	/* 0x10, 011 not usable */

	BT_NUMERICSTRING = 0x012,
	BT_STRING = 0x13,
	BT_TELEXSTRING = 0x14,
	BT_VIDEOTEXSTRING = 0x15,
	BT_IA5STRING = 0x16,
	BT_UTCTIME = 0x17,
	BT_GENTIME = 0x18,
	BT_GFXSTRING = 0x19,
	BT_VISSTRING = 0x1a,
	BT_GENSTRING = 0x1b,
	BT_UNIVSTRING = 0x1c,
	BT_CHARSTRING = 0x1d,
	BT_BMPSTRING = 0x1e,

	BT_SEQUENCE = 0x30,
	BT_SET = 0x31,
};

enum libder_error {
	LDE_NONE = 0x00,
	LDE_NOMEM,		/* Out of memory */
	LDE_INVAL,		/* Invalid parameter */
	LDE_SHORTHDR,		/* Header too short */
	LDE_BADVARLEN,		/* Bad variable length encoding */
	LDE_LONGLEN,		/* Encoded length too large (8 byte max) */
	LDE_SHORTDATA,		/* Payload not available */
	LDE_GARBAGE,		/* Garbage after encoded data */
	LDE_UNEXPECTED,		/* Unexpected payload */
	LDE_STREAMERR,		/* Stream error */
};

typedef struct libder_ctx	*libder_ctx;
typedef struct libder_object	*libder_object;

libder_ctx		 libder_open(void);
const char		*libder_get_error(libder_ctx);
bool			 libder_has_error(libder_ctx);
libder_object		 libder_read(libder_ctx, const uint8_t *, size_t *);
libder_object		 libder_read_fd(libder_ctx, int, size_t *);
libder_object		 libder_read_file(libder_ctx, FILE *, size_t *);

uint8_t			*libder_write(libder_ctx, libder_object, uint8_t *,
			    size_t *);

void			 libder_close(libder_ctx);

#define	DER_CHILDREN(obj)	libder_obj_children(obj)
#define	DER_NEXT(obj)		libder_obj_next(obj)

#define	DER_FOREACH_CHILD(var, obj)	\
	for ((var) = DER_CHILDREN((obj));	\
	    (var);				\
	    (var) = DER_NEXT((var)))
#define	DER_FOREACH_CHILD_SAFE(var, obj, tvar)		\
	for ((var) = DER_CHILDREN((obj));		\
	    (var) && ((tvar) = DER_NEXT((var)), 1);	\
	    (var) = (tvar))

libder_object	 libder_obj_alloc(libder_ctx, int, size_t, const uint8_t *);
void		 libder_set_verbose(libder_ctx, int);
void		 libder_obj_free(libder_object);

libder_object	 libder_obj_child(const struct libder_object *, size_t);
libder_object	 libder_obj_children(const struct libder_object *);
libder_object	 libder_obj_next(const struct libder_object *);
int		libder_obj_type(const struct libder_object *);
