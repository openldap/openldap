# contrib/slapd-modules/ppm/Makefile
# Copyright 2014 David Coutadeur, Paris. All Rights Reserved.
#

LDAP_SRC=../../..
LDAP_BUILD=$(LDAP_SRC)
LDAP_INC=-I$(LDAP_SRC)/include \
	 -I$(LDAP_SRC)/servers/slapd
LDAP_LIBS=-L$(LDAP_BUILD)/libraries/liblber/.libs \
	  -L$(LDAP_BUILD)/libraries/libldap/.libs
LDAP_LIB=-lldap -llber
CRACK_LIB=-lcrack

prefix=/usr/local
exec_prefix=$(prefix)
ldap_subdir=/openldap

libdir=$(exec_prefix)/lib
libexecdir=$(exec_prefix)/libexec
moduledir = $(libexecdir)$(ldap_subdir)
mandir = $(exec_prefix)/share/man
man5dir = $(mandir)/man5
etcdir = $(exec_prefix)/etc$(ldap_subdir)

CC=gcc
INSTALL = /usr/bin/install
PROGRAMS=ppm.so
TEST=ppm_test
EXAMPLE=ppm.example
TESTS=./unit_tests.sh
OPT=-g -O2 -Wall -fpic 						\
	-DCONFIG_FILE="\"$(etcdir)/$(EXAMPLE)\""		\
	-DCRACKLIB						\
	-DDEBUG

# don't link against cracklib if option -DCRACKLIB is not defined in OPT
ifeq (,$(findstring CRACKLIB,$(OPT)))
	CRACK_LIB=
endif




all: 	ppm $(TEST)

$(TEST): 
	$(CC) -g $(LDAP_INC) $(LDAP_LIBS) -Wl,-rpath=. -o $(TEST) ppm_test.c $(PROGRAMS) $(LDAP_LIB) $(CRACK_LIB)

ppm.o:
	$(CC) $(OPT) -c $(LDAP_INC) ppm.c

ppm: ppm.o
	$(CC) $(LDAP_INC) -shared -o $(PROGRAMS) ppm.o $(CRACK_LIB)

install: ppm
	$(INSTALL) -m 644 $(PROGRAMS) $(libdir)
	$(INSTALL) -m 755 $(TEST) $(libdir)
	$(INSTALL) -m 644 $(EXAMPLE) $(etcdir)/

.PHONY: clean

clean:
	$(RM) -f ppm.o $(PROGRAMS) ppm.lo $(TEST)
	$(RM) -rf .libs

test: ppm $(TEST)
	LDAP_SRC=$(LDAP_SRC) $(TESTS)


