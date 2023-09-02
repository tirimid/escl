INSTDIR := /usr/bin
CC := gcc
CFLAGS := -std=c99 -pedantic -D_DEFAULT_SOURCE -D_POSIX_C_SOURCE=200809
LIBS := -lcrypt

all: escl

install: all
	cp escl $(INSTDIR)
	chown root:root $(INSTDIR)/escl
	chmod u+s $(INSTDIR)/escl

uninstall:
	rm -f $(INSTDIR)/escl /etc/escl.conf

clean:
	rm escl

escl: escl.c
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)
