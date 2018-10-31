srcdir := $(CURDIR)
objdir := $(CURDIR)
mcount_srcdir := $(srcdir)/../
FASTTP_DEPS := $(wildcard $(srcdir)/*.h*)  $(wildcard $(srcdir)/include/dyntrace/*.h*)
FASTTP_DEPS += $(wildcard $(srcdir)/include/dyntrace/arch/*.h*) $(wildcard $(srcdir)/include/dyntrace/fasttp/*.h*)

include $(mcount_srcdir)/Makefile.include

GPP := g++
WRAPPER_INC := -I $(srcdir)/include -I $(mcount_srcdir) -I $(mcount_srcdir)/libmcount -I $(mcount_srcdir)/arch/aarch64/
CFLAGS := -std=gnu++17 -fPIC

all: fasttp_wrapper.o

fasttp_wrapper.o: fasttp_wrapper.cpp $(FASTTP_DEPS)
	$(QUIET_LINK)$(GPP) -c -o $@ $< $(WRAPPER_INC) $(CFLAGS)

clean:
	$(RM) $(objdir)/*.o $(objdir)/*.op
