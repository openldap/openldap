#! /bin/sh
# $OpenLDAP$
## This work is part of OpenLDAP Software <http://www.openldap.org/>.
##
## Copyright 2022-2026 The OpenLDAP Foundation.
## All rights reserved.
##
## Redistribution and use in source and binary forms, with or without
## modification, are permitted only as authorized by the OpenLDAP
## Public License.
##
## A copy of this license is available in the file LICENSE in the
## top-level directory of the distribution or, alternatively, at
## <http://www.OpenLDAP.org/license.html>.

timer() {
	if [ -n "$STARTTIME" ]; then
		now=`date +%s`
		delta=`expr $now - $STARTTIME`
		date -u $DATEOPT$delta +%T
	fi
}

xml_escape() {
	sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'
}

junit_finalize() {
	[ -n "$JUNIT_OUTPUT" ] || return 0
	[ -f "$JUNIT_TMP" ] || return 0
	JUNIT_END=`date +%s`
	JUNIT_TOTAL=`grep -c '<testcase' "$JUNIT_TMP" 2>/dev/null`
	[ -z "$JUNIT_TOTAL" ] && JUNIT_TOTAL=0
	{
		echo '<?xml version="1.0" encoding="UTF-8"?>'
		printf '<testsuite name="%s" tests="%d" failures="%d" skipped="%d" time="%d">\n' \
			"$JUNIT_NAME" "$JUNIT_TOTAL" "$FAILCOUNT" "$SKIPCOUNT" \
			"$(( $JUNIT_END - $JUNIT_START ))"
		cat "$JUNIT_TMP"
		echo '</testsuite>'
	} > "$JUNIT_OUTPUT"
	rm -f "$JUNIT_TMP" "$JUNIT_LOG" "$JUNIT_RC"
}

junit_setup() {
	JUNIT_NAME="${1:-$BACKEND}"
	JUNIT_OUTPUT="${JUNIT_OUTPUT-$TESTWD/junit$TESTINST-$JUNIT_NAME.xml}"
	if [ -n "$JUNIT_OUTPUT" ]; then
		JUNIT_TMP="$TESTWD/junit_tmp$TESTINST"
		JUNIT_LOG="$TESTWD/junit_current$TESTINST.log"
		JUNIT_RC="$TESTWD/junit_current$TESTINST.rc"
		: > "$JUNIT_TMP"
		JUNIT_START=`date +%s`
		trap junit_finalize EXIT
	fi
}
