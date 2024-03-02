SUBDIR+=	libder

SUBDIR+=	derdump
SUBDIR+=	tests

SUBDIR_DEPEND_derdump=	libder
SUBDIR_DEPEND_tests=	libder
SUBDIR_PARALLEL=

.include <bsd.subdir.mk>
