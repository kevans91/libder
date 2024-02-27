
PROGS=	fuzz_stream \
	fuzz_write \
	make_corpus
MAN=
CSTD=	c11

LIBDER=	${.CURDIR}/../libder

LDADD+=	${LIBDER}/libder.a
DPADD+=	${LIBDER}/libder.a

LDADD.fuzz_stream+=	-pthread

CFLAGS+=	-I${LIBDER}

.for fuzzprog in ${PROGS:Mfuzz_*}
CFLAGS.${fuzzprog}+=	-fsanitize=address,undefined,fuzzer
# XXX Shouldn't link against libsys
LDFLAGS.${fuzzprog}+=	-fsanitize=address,undefined,fuzzer -lsys
.endfor

.include <bsd.progs.mk>
