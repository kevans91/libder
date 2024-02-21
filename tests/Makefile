
PROGS=	fuzz_read
MAN=

LIBDER=	${.CURDIR}/../libder

SRCS.fuzz_read=	fuzz_read.c
LDADD.fuzz_read=	${LIBDER}/libder.a
LDADD.fuzz_read=	${LIBDER}/libder.a

CFLAGS.fuzz_read+=	-fsanitize=address,undefined,fuzzer -I${LIBDER}
LDFLAGS.fuzz_read+=	-fsanitize=address,undefined,fuzzer

.include <bsd.progs.mk>
