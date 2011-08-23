/* dbcache.c - manage cache of open databases */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2000-2011 The OpenLDAP Foundation.
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
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>
#include <sys/stat.h>

#include "slap.h"
#include "back-mdb.h"

int
mdb_db_cache(
	Backend	*be,
	struct berval *name,
	MDB_dbi *dbout )
{
	int i, flags;
	int rc;
	struct mdb_info *mdb = (struct mdb_info *) be->be_private;
	struct mdb_db_info *db;
	char *file;

	*dbout = 0;

	for( i=MDB_NDB; i < mdb->mi_ndatabases; i++ ) {
		if( !ber_bvcmp( &mdb->mi_databases[i]->mdi_name, name) ) {
			*dbout = mdb->mi_databases[i]->mdi_dbi;
			return 0;
		}
	}

	ldap_pvt_thread_mutex_lock( &mdb->mi_database_mutex );

	/* check again! may have been added by another thread */
	for( i=MDB_NDB; i < mdb->mi_ndatabases; i++ ) {
		if( !ber_bvcmp( &mdb->mi_databases[i]->mdi_name, name) ) {
			*dbout = mdb->mi_databases[i]->mdi_dbi;
			ldap_pvt_thread_mutex_unlock( &mdb->mi_database_mutex );
			return 0;
		}
	}

	if( i >= MDB_INDICES ) {
		ldap_pvt_thread_mutex_unlock( &mdb->mi_database_mutex );
		return -1;
	}

	db = (struct mdb_db_info *) ch_calloc(1, sizeof(struct mdb_db_info));

	ber_dupbv( &db->mdi_name, name );

	rc = db_create( &db->mdi_dbi, mdb->mi_dbenv, 0 );
	if( rc != 0 ) {
		Debug( LDAP_DEBUG_ANY,
			"mdb_db_cache: db_create(%s) failed: %s (%d)\n",
			mdb->mi_dbenv_home, mdb_strerror(rc), rc );
		ldap_pvt_thread_mutex_unlock( &mdb->mi_database_mutex );
		ch_free( db );
		return rc;
	}

	file = ch_malloc( db->mdi_name.bv_len + sizeof(MDB_SUFFIX) );
	strcpy( file, db->mdi_name.bv_val );
	strcpy( file+db->mdi_name.bv_len, MDB_SUFFIX );

#ifdef HAVE_EBCDIC
	__atoe( file );
#endif
	flags = DB_CREATE | DB_THREAD;
#ifdef DB_AUTO_COMMIT
	if ( !( slapMode & SLAP_TOOL_QUICK ))
		flags |= DB_AUTO_COMMIT;
#endif
	/* Cannot Truncate when Transactions are in use */
	if ( (slapMode & (SLAP_TOOL_QUICK|SLAP_TRUNCATE_MODE)) ==
		(SLAP_TOOL_QUICK|SLAP_TRUNCATE_MODE))
			flags |= DB_TRUNCATE;

	rc = DB_OPEN( db->mdi_dbi,
		file, NULL /* name */,
		MDB_INDEXTYPE, mdb->mi_db_opflags | flags, mdb->mi_dbenv_mode );

	ch_free( file );

	if( rc != 0 ) {
		Debug( LDAP_DEBUG_ANY,
			"mdb_db_cache: db_open(%s) failed: %s (%d)\n",
			name->bv_val, mdb_strerror(rc), rc );
		ldap_pvt_thread_mutex_unlock( &mdb->mi_database_mutex );
		return rc;
	}

	mdb->mi_databases[i] = db;
	mdb->mi_ndatabases = i+1;

	*dbout = db->mdi_dbi;

	ldap_pvt_thread_mutex_unlock( &mdb->mi_database_mutex );
	return 0;
}
