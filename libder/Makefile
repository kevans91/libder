
LIB=	der
SHLIB_MAJOR=	0
WARNS?=		3

SRCS=	libder.c \
	libder_error.c \
	libder_obj.c \
	libder_read.c

SANITIZERS=	address
SANITIZERS+=	undefined
# XXX
SANITIZERS+=	fuzzer-no-link

CFLAGS+=	-fsanitize=${SANITIZERS:ts,} -fPIC -g -O0
LDFLAGS+=	-fsanitize=${SANITIZERS:ts,}

.include <bsd.lib.mk>
