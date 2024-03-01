
PROGS=	fuzz_stream \
	fuzz_write \
	make_corpus \
	test_pubkey
MAN=
CSTD=	c11

LIBDER=	${.CURDIR}/../libder

LDADD+=	${LIBDER}/libder.a
DPADD+=	${LIBDER}/libder.a

LDADD.fuzz_stream+=	-pthread

CFLAGS+=	-I${LIBDER}

.for fuzzprog in ${PROGS:Mfuzz_*}
SANITIZERS.${fuzzprog}+=	fuzzer
.endfor

.for allprog in ${PROGS}
SANITIZERS.${allprog}+=	address undefined
CFLAGS.${allprog}+=		-fsanitize=${SANITIZERS.${allprog}:ts,}
# XXX Shouldn't link against libsys
LDFLAGS.${allprog}+=		-fsanitize=${SANITIZERS.${allprog}:ts,} -lsys
.endfor

.include <bsd.progs.mk>
