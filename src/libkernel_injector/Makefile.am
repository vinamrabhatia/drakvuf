h_sources = kernel_injector.h private.h winscproto.h commonscproto.h
c_sources = kernel_injector.cpp 

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/src -I$(srcdir)
AM_CPPFLAGS += $(VMI_CFLAGS)
AM_CPPFLAGS += $(GLIB_CFLAGS)

AM_LDFLAGS =  $(LDFLAGS)
AM_LDFLAGS += $(VMI_LIBS)
AM_LDFLAGS += $(GLIB_LIBS)

AM_CFLAGS = $(CFLAGS)
if HARDENING
AM_CFLAGS += $(HARDEN_CFLAGS) -DHARDENING
endif

if SANITIZE
AM_CFLAGS += $(SANITIZE_CFLAGS)
AM_LDFLAGS += $(SANITIZE_LDFLAGS)
endif

# Note that -pg is incompatible with HARDENING
if DEBUG
AM_CFLAGS += -DDRAKVUF_DEBUG -Werror -Wall -Wextra -g -ggdb3
AM_CFLAGS += -Wno-missing-field-initializers
if !HARDENING
AM_CFLAGS += -pg
endif
endif

noinst_LTLIBRARIES= libkernelinjector.la
libkernelinjector_la_SOURCES= $(h_sources) $(c_sources)
libkernelinjector_la_LIBADD= ../xen_helper/libxenhelper.la
libkernelinjector_la_LIBADD+= ../libdrakvuf/libdrakvuf.la
