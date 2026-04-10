/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2026 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/ctype.h>
#include <ac/stdarg.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldap-int.h"

/*
 * ldap log 
 */

static int ldap_log_check( LDAP *ld, int loglvl )
{
	int errlvl;

	if(ld == NULL) {
		errlvl = ldap_debug;
	} else {
		errlvl = ld->ld_debug;
	}

	return errlvl & loglvl ? 1 : 0;
}

int ldap_log_printf( LDAP *ld, int loglvl, const char *fmt, ... )
{
	char buf[ 1024 ];
	va_list ap;
#ifdef HAVE_CLOCK_GETTIME
	struct timespec tv;
#define TS  "%08x"
#define Tfrac   tv.tv_nsec
#define gettime(tv) clock_gettime( CLOCK_REALTIME, tv )
#else
	struct timeval tv;
#define TS  "%05x"
#define Tfrac   tv.tv_usec
#define gettime(tv) gettimeofday( tv, NULL )
#endif

#ifdef NO_THREADS
#define TIDp ""
#define TIDs
#else
#define TIDp " %p"
#define TIDs , (void *)ldap_pvt_thread_self()
#endif

	char *ptr = buf;
	int len = sizeof(buf);

	if ( !ldap_log_check( ld, loglvl )) {
		return 0;
	}

	/* if using default printer, add timestamp and threadID.
	 * slapd uses its own printer and already includes this.
	 */
	if ( ber_pvt_log_print == ber_error_print ) {
		int prefixlen;
		gettime( &tv );
		prefixlen = sprintf( ptr, "%llx." TS TIDp " ",
			(long long)tv.tv_sec, (unsigned int)Tfrac TIDs );
		len -= prefixlen;
		ptr += prefixlen;
	}

	va_start( ap, fmt );

	buf[sizeof(buf) - 1] = '\0';
	vsnprintf( ptr, len-1, fmt, ap );

	va_end(ap);

	(*ber_pvt_log_print)( buf );
	return 1;
}
