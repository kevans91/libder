
PROG=	derdump
MAN=

LIBDER=	${.CURDIR}/../libder

LDADD+=	${LIBDER}/libder.a
DPADD+=	${LIBDER}/libder.a

CFLAGS+=	-I${LIBDER}
CFLAGS+=	-fsanitize=address,undefined
LDFLAGS+=	-fsanitize=address,undefined

.include <bsd.prog.mk>
