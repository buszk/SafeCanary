#
# NSL DFT library (libdft tools)
#
# Columbia University, Department of Computer Science
# Network Security Lab
#
# Vasileios P. Kemerlis (vpk@cs.columbia.edu)
#
# NOTE: use this Makefile with Pin v2.12-56759, 
# 	or any version after that 
#

# variable definitions
CXXFLAGS	+= -Wall -Wno-unknown-pragmas			\
		   -c -fomit-frame-pointer -std=c++0x -O3	\
		   -fno-strict-aliasing -fno-stack-protector	\
		   -DBIGARRAY_MULTIPLIER=1 -DUSING_XED		\
		   -DTARGET_IA32 -DHOST_IA32 -DTARGET_LINUX	\
		   -m32 -fabi-version=2 -D_GLIBCXX_USE_CXX11_ABI=0
CXXFLAGS_SO	+= -Wl,--hash-style=sysv -Wl,-Bsymbolic -shared \
		   -Wl,-rpath=$(PIN_HOME)/ia32/runtime/cpplibs	\
		   -Wl,--version-script=$(PIN_HOME)/source/include/pin/pintool.ver -m32	\
		   -D_GLIBCXX_USE_CXX11_ABI=0
LIBS		+= -ldft -lpin -lxed -ldwarf -lelf -ldl		\
		   -lpindwarf -lpin
H_INCLUDE	+= -I../src -I.					\
		   -I$(PIN_HOME)/source/include/pin		\
		   -I$(PIN_HOME)/source/include/pin/gen		\
		   -I$(PIN_HOME)/extras/xed-ia32/include	\
		   -I$(PIN_HOME)/extras/components/include	\
		   -L/usr/lib/i386-linux-gnu
L_INCLUDE	+= -L../src					\
		   -L$(PIN_HOME)/extras/xed-ia32/lib		\
		   -L$(PIN_HOME)/ia32/runtime/cpplibs		\
		   -L$(PIN_HOME)/ia32/lib -L$(PIN_HOME)/ia32/lib-ext	\
		   -L/usr/lib/i386-linux-gnu
OBJS		= nullpin.o libdft.o libdft-dta.o safe-canary.o
SOBJS		= $(OBJS:.o=.so)

# phony targets
.PHONY: all sanity tools clean

# get system information
OS=$(shell uname -o | grep Linux$$)			# OS
ARCH=$(shell uname -m | grep 86$$)			# arch

# default target (build libdft only)
all: sanity tools

# sanity checks (i.e., PIN_HOME, OS, architecture)
sanity:
# check if PIN_HOME variable is defined
ifndef PIN_HOME
	$(error "PIN_HOME environment variable is not set")
endif
# check the OS (must be Linux)
ifeq ($(strip $(OS)),)
	$(error "This version of libdft is for Linux only")
endif
# Disable 32-bit check, instead add -m32 in CXXFLAGS
# check the architecture (must be x86, i386, i486, i686, ...)
#ifeq ($(strip $(ARCH)),)
#	$(error "This version of libdft is for x86 only")
#endif


# tools (nullpin, libdft, libdft-dta)
tools: $(SOBJS)

# nullpin
nullpin.so: nullpin.o
	$(CXX) $(CXXFLAGS_SO) $(L_INCLUDE) -o $(@) $(@:.so=.o) $(LIBS)
	strip -s $(@)
nullpin.o: nullpin.c ../src/branch_pred.h
	$(CXX) $(CXXFLAGS) $(H_INCLUDE) -o $(@) $(@:.o=.c)

# libdft
libdft.so: libdft.o
	$(CXX) $(CXXFLAGS_SO) $(L_INCLUDE) -o $(@) $(@:.so=.o) $(LIBS)
	strip -s $(@)
libdft.o: libdft.c ../src/branch_pred.h
	$(CXX) $(CXXFLAGS) $(H_INCLUDE) -o $(@) $(@:.o=.c)

# libdft-dta
libdft-dta.so: libdft-dta.o
	$(CXX) $(CXXFLAGS_SO) $(L_INCLUDE) -o $(@) $(@:.so=.o) $(LIBS)
	strip -s $(@)
libdft-dta.o: libdft-dta.c ../src/branch_pred.h
	$(CXX) $(CXXFLAGS) $(H_INCLUDE) -o $(@) $(@:.o=.c)

# safe-canary
safe-canary.so: safe-canary.o
	$(CXX) $(CXXFLAGS_SO) $(L_INCLUDE) -o $(@) $(@:.so=.o) $(LIBS)

safe-canary.o: safe-canary.c ../src/branch_pred.h
	$(CXX) $(CXXFLAGS) $(H_INCLUDE) -o $(@) $(@:.o=.c)
# clean (tools)
clean:
	rm -rf $(OBJS) $(SOBJS)
