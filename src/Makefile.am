# Used to build Makefile.in

EXTRA_DIST = ha_awss3.h

# INCLUDES =  -DMYSQL_DYNAMIC_PLUGIN  -DDBUG_ON -DSAFE_MUTEX -DUNIV_MUST_NOT_INLINE -DEXTRA_DEBUG -DFORCE_INIT_OF_VARS -DSAFEMALLOC -DPEDANTIC_SAFEMALLOC -DSAFE_MUTEX $(MYSQL_INC) $(MYSQL_INC)/../extra/yassl/include $(MYSQL_INC)/../extra/yassl/taocrypt/include
INCLUDES =  -DMYSQL_DYNAMIC_PLUGIN  -DDBUG_ON -DSAFE_MUTEX -DUNIV_MUST_NOT_INLINE -DEXTRA_DEBUG -DFORCE_INIT_OF_VARS -DSAFEMALLOC -DPEDANTIC_SAFEMALLOC -DSAFE_MUTEX $(MYSQL_INC) $(LIBXML2_CFLAGS)

LIBS = -L/usr/local/lib -lcurl $(LIBXML2_LIBS)
LDADD =

noinst_HEADERS = ha_awss3.h hmac.h memxor.h sha1.h md5.h str_quotify.h str_percent.h

lib_LTLIBRARIES = libawss3_engine.la
libawss3_engine_la_SOURCES = ha_awss3.cc hmac-sha1.c memxor.c sha1.c md5.c str_quotify.c str_percent.c
libawss3_engine_la_LDFLAGS = -module
