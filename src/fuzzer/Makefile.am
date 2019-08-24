bin_PROGRAMS = fuzzer

fuzzer_SOURCES = fuzzer.c
fuzzer_LDADD = ../xen_helper/libxenhelper.la

AM_CPPFLAGS = $(CPPFLAGS) $(GLIB_CFLAGS)
AM_CFLAGS = -Werror -Wall -Wextra $(CFLAGS)
AM_CFLAGS += -Wno-missing-field-initializers
AM_LDFLAGS = $(LDFLAGS) $(GLIB_LIBS)
