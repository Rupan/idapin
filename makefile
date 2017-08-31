##
## PIN tools makefile for Linux
##
## For Windows instructions, refer to source/tools/nmake.bat and
## source/tools/Nmakefile
##
## To build the examples in this directory:
##
##   cd source/tools/ManualExamples
##   make all
##
## To build and run a specific example (e.g., inscount0)
##
##   cd source/tools/ManualExamples
##   make dir inscount0.test
##
## To build a specific example without running it (e.g., inscount0)
##
##   cd source/tools/ManualExamples
##   make dir obj-intel64/inscount0.so
##
## The example above applies to the Intel(R) 64 architecture.
## For the IA-32 architecture, use "obj-ia32" instead of
## "obj-intel64".
##

ifdef __X64__
    _HOST_ARCH=intel64
else
    _HOST_ARCH=ia32
endif

TARGET = $(_HOST_ARCH)

ifeq ($(TARGET),intel64)
    BITNESS = 64
endif

ifeq (${OS},Windows_NT)
  OS_NAME = windows
else
  OS_NAME = linux
endif

Goal: tools

ifneq ($(wildcard ../Config/makefile.config),)
  CONFIG_ROOT =../Config
  MAKECONF = $(CONFIG_ROOT)/makefile.config
else
  CONFIG_ROOT = ../../../../third_party/pin/src/$(OS_NAME)/source/tools/Config
  MAKECONF = makefile.config
endif

include $(MAKECONF)

ifneq ($(wildcard ../../../allmake.mak),)
  include ../../../allmake.mak
endif

##############################################################
#
# include *.config files
#
##############################################################

###
TEST_TOOL_ROOTS := idadbg
###

ifneq ($(wildcard ../../../objdir.mak),)
  include ../../../objdir.mak
  OUTDIR=objdir
endif

##############################################################
#
# Tools sets
#
##############################################################

TOOL_ROOTS = idadbg

OBJTOOLS := $(TOOL_ROOTS:%=$(F)%$(BITNESS)$(OBJ_SUFFIX))
TOOLS := $(TOOL_ROOTS:%=$(F)%$(BITNESS)$(PINTOOL_SUFFIX))

##############################################################
#
# build rules
#
##############################################################

ifdef __LINT__

tools: $(OBJTOOLS)

ifeq ($(TARGET),ia32)
  LINT_TARGET = /DTARGET_IA32 /DHOST_IA32
else
  LINT_TARGET = /DTARGET_IA32E /DHOST_IA32E
endif
LINT_FLAGS = /D__PIN__=1 /D__i386__ /DTARGET_WINDOWS $(LINT_TARGET) \
						 /D_WINDOWS_H_PATH_ \
             /I$(PIN_ROOT)/extras/crt \
             /I$(PIN_ROOT)/extras/crt/include \
             /I$(PIN_ROOT)/extras/crt/include/arch-x86 \
						 /I$(PIN_ROOT)/extras/crt/include/kernel/uapi \
						 /I$(PIN_ROOT)/extras/crt/include/kernel/uapi/asm-x86 \
             /I$(PIN_ROOT)/extras/xed-ia32/include/xed \
						 /FIinclude/msvc_compat.h \
             $(COMPONENT_INCLUDES)  /I$(MSSDK)/include \
             /I$(PIN_ROOT)/source/include/pin \
             /I$(PIN_ROOT)/source/include/pin/gen \
             /I$(PIN_ROOT)/extras \
             /I$(XED_ROOT)/include

OBJFLAGS = $(LINT_FLAGS) $(OBJSW)

else		# not lint

ifdef __PVS__
  tools: $(OBJTOOLS)
else
  tools: $(TOOLS)
endif

OBJFLAGS = $(TOOL_CXXFLAGS) $(COMP_OBJ)

$(TOOLS): $(OBJTOOLS)
	$(LINKER) $(TOOL_LDFLAGS) $(LINK_EXE)$@ $< $(TOOL_LPATHS) $(TOOL_LIBS)

endif

# add dependency on $(PIN_ROOT)/README to force rebuild in case of PIN upgrade
$(OBJTOOLS) : idadbg.cpp makefile $(MAKECONF) idadbg.h idadbg_local.h $(PIN_ROOT)/README | $(OUTDIR)
	$(CXX) $(OBJFLAGS)$@  $<

DISTNAME=idapin
DISTFILES=idadbg.cpp idadbg.h idadbg_local.h \
          makefile  makefile.config \
          IDADBG.sln IDADBG.vcxproj readme.txt

## make IDA PIN tool archive
distr: $(DISTNAME).zip

$(DISTNAME).zip: $(DISTFILES)
	mkdir -p $(DISTNAME)
	$(RM) $(DISTNAME)/*
	$(CP) $(DISTFILES) $(DISTNAME)
	zip -r $(DISTNAME).zip $(DISTNAME)/*
	$(RM) $(DISTNAME)/*

## cleaning
clean:
	-@rm -rf $(F) *.out *.log *.tested *.failed *.makefile.copy *.out.*.* *.o *.o64 $(DISTNAME).zip $(DISTNAME)

.PHONY: Goal tools clean distr
