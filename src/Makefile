# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

TARGET := xdp_pass
TARGET += xdp_iphash_to_cpu
TARGET += tc_classify

CMDLINE_TOOLS := xdp_iphash_to_cpu_cmdline

TC_TARGETS += tc_queue_mapping

LLC ?= llc
CLANG ?= clang
CC := gcc

LIBBPF_DIR = ../libbpf/src
LIBBPF_INSTALL := libbpf-install
LIBBPF_INSTDIR=../../$(LIBBPF_INSTALL)
LIBBPF_INC ?= $(LIBBPF_DIR)/$(LIBBPF_INSTDIR)/usr/include/

XDP_C = ${TARGET:=_kern.c} ${TC_TARGETS:=_kern.c}
XDP_OBJ = ${XDP_C:.c=.o}
USER_C = ${TARGET:=_user.c}
USER_OBJ = ${USER_C:.c=.o}
OBJECT_LIBBPF = $(LIBBPF_DIR)/libbpf.a $(LIBBPF_INSTDIR)

CFLAGS += -I$(LIBBPF_INC)
CFLAGS += -I../headers/
LDFLAGS ?= -L$(LIBBPF_DIR)

COMMON_USER_OBJ := common_user.o

LIBS = -l:libbpf.a -lelf -lz

all: llvm-check $(TARGET) $(XDP_OBJ) $(CMDLINE_TOOLS)

.PHONY: clean $(CLANG) $(LLC)

clean:
	cd $(LIBBPF_DIR) && $(MAKE) clean
	cd $(LIBBPF_DIR) && rm -r $(LIBBPF_INSTDIR)
	rm -f $(TARGET)
	rm -f $(XDP_OBJ)
	rm -f $(USER_OBJ)
	rm -f $(COMMON_USER_OBJ)
	rm -f *.ll
	rm -f *~

llvm-check: $(CLANG) $(LLC)
	@for TOOL in $^ ; do \
		if [ ! $$(command -v $${TOOL} 2>/dev/null) ]; then \
			echo "*** ERROR: Cannot find tool $${TOOL}" ;\
			exit 1; \
		else true; fi; \
	done

$(OBJECT_LIBBPF):
	@if [ ! -d $(LIBBPF_DIR) ]; then \
		echo "Error: Need libbpf submodule"; \
		echo "May need to run git submodule update --init"; \
		exit 1; \
	else \
		cd $(LIBBPF_DIR) && $(MAKE) all; \
		DESTDIR=$(LIBBPF_INSTDIR) $(MAKE) install_headers; \
	fi

$(COMMON_USER_OBJ): common_user.c common_user.h
	$(CC) -c -o $@ $< $(CFLAGS)

# Define dependencies to other files
#xdp_iphash_to_cpu_kern.o:  xdp_iphash_to_cpu_common.h
#xdp_iphash_to_cpu_cmdline: xdp_iphash_to_cpu_common.h
#xdp_iphash_to_cpu:         xdp_iphash_to_cpu_common.h

$(TARGET): %: %_user.c $(OBJECT_LIBBPF) Makefile $(COMMON_USER_OBJ)
	$(CC) -Wall $(CFLAGS) $(LDFLAGS) -o $@ $(COMMON_USER_OBJ) \
	 $< $(LIBS)

$(CMDLINE_TOOLS): %: %.c $(OBJECT_LIBBPF) Makefile $(COMMON_USER_OBJ)
	$(CC) -Wall $(CFLAGS) $(LDFLAGS) -o $@ $(COMMON_USER_OBJ) \
	 $< $(LIBS)

$(XDP_OBJ): %.o: %.c  common_kern_user.h shared_maps.h
	$(CLANG) -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    $(CFLAGS) \
	    -Wall \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -Werror \
	    -O2 -emit-llvm -c -g -o ${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}
