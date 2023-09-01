INSTDIR := /usr/bin
CC := gcc
CFLAGS := -std=c89 -pedantic -D_POSIX_C_SOURCE=200809
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
