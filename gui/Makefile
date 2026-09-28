CC ?= cc
PKG_CONFIG ?= pkg-config
PACKAGES = gtk+-3.0 polkit-agent-1 gio-unix-2.0
CPPFLAGS += $(shell $(PKG_CONFIG) --cflags $(PACKAGES))
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Werror -Wformat=2 -Wshadow -Wstrict-prototypes -Wmissing-prototypes -Wconversion
LDLIBS += $(shell $(PKG_CONFIG) --libs $(PACKAGES))
PREFIX ?= /usr/local

.PHONY: all check install clean
all: agent-keyring-approval

agent-keyring-approval: approval.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

test-approval: test-approval.c approval.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

# Tests create no polkit registration or real authentication sessions.
check: test-approval
	GDK_BACKEND=x11 NO_AT_BRIDGE=1 GSETTINGS_BACKEND=memory xvfb-run -a -s '-screen 0 1024x768x24 -nolisten tcp' ./test-approval

install: agent-keyring-approval
	install -Dm755 agent-keyring-approval $(DESTDIR)$(PREFIX)/libexec/agent-keyring-approval

clean:
	rm -f agent-keyring-approval test-approval
