/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2021 The OpenLDAP Foundation.
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

#include <ac/errno.h>
#include <ac/param.h>
#include <ac/string.h>
#include <ac/time.h>
#include <ac/unistd.h>

#include <sys/stat.h>
#include <sys/uio.h>
#include <fcntl.h>

#include "slap.h"


static char logfile_suffix[sizeof(".xx.gz")];
char logfile_path[MAXPATHLEN - sizeof(logfile_suffix) -1];
long logfile_fslimit;
int logfile_age, logfile_only, logfile_max;

ldap_pvt_thread_mutex_t logfile_mutex;

static off_t logfile_fsize;
static time_t logfile_fcreated;
static int logfile_fd;
static char logpaths[2][MAXPATHLEN];
static int logpathlen;

void
slap_debug_print( const char *data )
{
	char prefix[sizeof("ssssssssssssssss.ffffffff 0xtttttttttttttttt ")];
	struct iovec iov[2];
	int rotate = 0;
#ifdef HAVE_CLOCK_GETTIME
	struct timespec tv;
#define	TS	"%08x"
#define	Tfrac	tv.tv_nsec
#define gettime(tv)	clock_gettime( CLOCK_REALTIME, tv )
#else
	struct timeval tv;
#define	TS	"%05x"
#define	Tfrac	tv.tv_usec
#define	gettime(tv)	gettimeofday( tv, NULL )
#endif

	gettime( &tv );
	iov[0].iov_base = prefix;
	iov[0].iov_len = sprintf( prefix, "%lx." TS " %p ",
		(long)tv.tv_sec, (unsigned int)Tfrac, (void *)ldap_pvt_thread_self() );
	iov[1].iov_base = (void *)data;
	iov[1].iov_len = strlen( data );
	if ( !logfile_only )
		writev( 2, iov, 2 );
	if ( logfile_fd ) {
		int len = iov[0].iov_len + iov[1].iov_len;
		if ( logfile_fslimit || logfile_age ) {
			ldap_pvt_thread_mutex_lock( &logfile_mutex );
			if ( logfile_fslimit && logfile_fsize + len > logfile_fslimit )
				rotate = 1;
			if ( logfile_age && tv.tv_sec - logfile_fcreated >= logfile_age )
				rotate |= 2;
			if ( rotate ) {
				close( logfile_fd );
				strcpy( logpaths[0]+logpathlen, ".tmp" );
				rename( logfile_path, logpaths[0] );
				logfile_open( logfile_path );
			}
		}
		len = writev( logfile_fd, iov, 2 );
		if ( len > 0 )
			logfile_fsize += len;
		if ( logfile_fslimit || logfile_age )
			ldap_pvt_thread_mutex_unlock( &logfile_mutex );
	}
	if ( rotate ) {
		int i;
		for (i=logfile_max; i > 1; i--) {
			sprintf( logpaths[0]+logpathlen, ".%02d", i );
			sprintf( logpaths[1]+logpathlen, ".%02d", i-1 );
			rename( logpaths[1], logpaths[0] );
		}
		sprintf( logpaths[0]+logpathlen, ".tmp" );
		rename( logpaths[0], logpaths[1] );
	}
}

void
logfile_close()
{
	if ( logfile_fd ) {
		close( logfile_fd );
		logfile_fd = 0;
	}
	logfile_path[0] = '\0';
}

int
logfile_open( const char *path )
{
	struct stat st;
	int fd;

	fd = open( path, O_CREAT|O_WRONLY, 0640 );
	if ( fd < 0 )
		return errno;

	if ( fstat( fd, &st ) ) {
		close( fd );
		return errno;
	}

	if ( !logfile_path[0] ) {
		logpathlen = strlen( path );
		if ( logpathlen >= sizeof(logfile_path) )
			return ENAMETOOLONG;
		strcpy( logfile_path, path );
		strcpy( logpaths[0], path );
		strcpy( logpaths[1], path );
	}

	logfile_fsize = st.st_size;
	logfile_fcreated = st.st_ctime;	/* not strictly true but close enough */
	logfile_fd = fd;
	lseek( fd, 0, SEEK_END );

	return 0;
}

const char *
logfile_name()
{
	return logfile_path[0] ? logfile_path : NULL;
}
