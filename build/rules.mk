# $OpenLDAP$
## This work is part of OpenLDAP Software <http://www.openldap.org/>.
##
## Copyright 1998-2021 The OpenLDAP Foundation.
## All rights reserved.
##
## Redistribution and use in source and binary forms, with or without
## modification, are permitted only as authorized by the OpenLDAP
## Public License.
##
## A copy of this license is available in the file LICENSE in the
## top-level directory of the distribution or, alternatively, at
## <http://www.OpenLDAP.org/license.html>.
##---------------------------------------------------------------------------
#
# Makefile Template for Programs
#

all-no lint-no lint5-no depend-no: FORCE
	@echo "run configure with $(BUILD_OPT) to make $(BINBSE)"

all-common: all-$(BUILD_BIN)

depend-common: depend-$(BUILD_BIN)

lint: lint-$(BUILD_BIN)

lint5: lint5-$(BUILD_BIN)

all-local-bin:
all-yes: $(PROGRAMS) all-local-bin FORCE

clean-common: 	FORCE
	$(RM) $(PROGRAMS) $(XPROGRAMS) $(XSRCS) *.o *.lo a.out core *.core \
		    .libs/* *.exe

depend-local-bin:
depend-yes: depend-local-bin FORCE
	$(MKDEP) $(DEFS) $(DEFINES) $(SRCS)

lint-local-bin:
lint-yes: lint-local-bin FORCE
	$(LINT) $(DEFS) $(DEFINES) $(SRCS)

lint5-local-bin:
lint5: lint5-local-bin FORCE
	$(5LINT) $(DEFS) $(DEFINES) $(SRCS)

Makefile: $(top_srcdir)/build/rules.mk

