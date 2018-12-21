srcdir := $(CURDIR)
objdir := $(CURDIR)
mcount_srcdir := $(srcdir)/../
COMMON_DEPS := $(mcount_srcdir)utils/utils.h  $(mcount_srcdir)utils/debug.c $(mcount_srcdir)utils/utils.c
COMMON_DEPS += $(mcount_srcdir)utils/compiler.h
LIBLOADER_DEPS := $(wildcard $(srcdir)/*.h*) $(COMMON_DEPS)

include $(mcount_srcdir)/Makefile.include

CC := gcc
CFLAGS := -fPIC
COMMON_LDFLAGS := -lrt -ldl -pthread
COMMON_CFLAGS := -D_GNU_SOURCE $(CFLAGS) -I$(mcount_srcdir)
LIB_CFLAGS := $(COMMON_CFLAGS) $(COMMON_LDFLAGS)

all: libloader.so

libloader.so: libloader.c $(LIBLOADER_DEPS)
	$(QUIET_LINK)$(CC) -shared -o $@ $^ $(LIB_CFLAGS)

clean:
	$(RM) $(objdir)/*.o $(objdir)/*.so
