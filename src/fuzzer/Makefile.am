bin_PROGRAMS = fuzzer dumb_fuzzer

fuzzer_SOURCES = fuzzer.c
fuzzer_LDADD = ../xen_helper/libxenhelper.la

dumb_fuzzer_SOURCES = dumb_fuzzer.c

AM_CPPFLAGS = $(CPPFLAGS) $(GLIB_CFLAGS)
AM_CFLAGS = -Werror -Wall -Wextra $(CFLAGS)
AM_CFLAGS += -Wno-missing-field-initializers
AM_LDFLAGS = $(LDFLAGS) $(GLIB_LIBS)
