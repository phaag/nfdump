# Build against an installed nfdump. Prefers pkg-config; if pkg-config
# can't find it, falls back to the default install prefix (/usr/local).
# If nfdump isn't there either, the build fails - this example doesn't
# reach into the nfdump source tree at all, so it works identically
# whether or not you happen to be inside a checkout of it.
#
# Override on the command line, e.g.:
#   make PKG_CONFIG=/opt/local/bin/pkg-config
#   make PREFIX=/opt/nfdump               # force the fallback prefix

PKG_CONFIG  ?= pkg-config
HAVE_PKGCONFIG := $(shell $(PKG_CONFIG) --exists nfdump 2>/dev/null && echo yes)

CC     ?= cc
CFLAGS += -std=c17 -Wall

ifeq ($(HAVE_PKGCONFIG),yes)
# The installed library resolves its own dependencies at run time - no
# loader-path override needed.
CFLAGS  += $(shell $(PKG_CONFIG) --cflags nfdump)
LDFLAGS += $(shell $(PKG_CONFIG) --libs nfdump)
else
# pkg-config can't see nfdump (check PKG_CONFIG_PATH if you expected it
# to). Assume the default install prefix instead; if nfdump isn't there,
# compiling/linking below fails with a normal "file not found" error.
PREFIX ?= /usr/local
CFLAGS  += -I$(PREFIX)/include
LDFLAGS += -L$(PREFIX)/lib -lnfdump
endif

.PHONY: all run clean
all: read_flows

read_flows: read_flows.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Runs against $(FILE) - any nfcapd/sfcapd/nfdump-written file.
run: read_flows
ifndef FILE
	$(error usage: make run FILE=<flow-file>)
endif
	./read_flows $(FILE)

clean:
	rm -f read_flows
