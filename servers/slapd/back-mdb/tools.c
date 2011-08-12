/* tools.c - tools for slap tools */
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
#include <ac/string.h>
#include <ac/errno.h>

#define AVL_INTERNAL
#include "back-mdb.h"
#include "idl.h"

static DBC *cursor = NULL;
static DBT key, data;
static EntryHeader eh;
static ID nid, previd = NOID;
static char ehbuf[16];

typedef struct dn_id {
	ID id;
	struct berval dn;
} dn_id;

#define	HOLE_SIZE	4096
static dn_id hbuf[HOLE_SIZE], *holes = hbuf;
static unsigned nhmax = HOLE_SIZE;
static unsigned nholes;

static int index_nattrs;

static struct berval	*tool_base;
static int		tool_scope;
static Filter		*tool_filter;
static Entry		*tool_next_entry;

static ID mdb_tool_ix_id;
static Operation *mdb_tool_ix_op;
static int *mdb_tool_index_threads, mdb_tool_index_tcount;
static void *mdb_tool_index_rec;
static struct mdb_info *mdb_tool_info;
static ldap_pvt_thread_mutex_t mdb_tool_index_mutex;
static ldap_pvt_thread_cond_t mdb_tool_index_cond_main;
static ldap_pvt_thread_cond_t mdb_tool_index_cond_work;

#if DB_VERSION_FULL >= 0x04060000
#define	USE_TRICKLE	1
#else
/* Seems to slow things down too much in MDB 4.5 */
#undef USE_TRICKLE
#endif

#ifdef USE_TRICKLE
static ldap_pvt_thread_mutex_t mdb_tool_trickle_mutex;
static ldap_pvt_thread_cond_t mdb_tool_trickle_cond;
static ldap_pvt_thread_cond_t mdb_tool_trickle_cond_end;

static void * mdb_tool_trickle_task( void *ctx, void *ptr );
static int mdb_tool_trickle_active;
#endif

static void * mdb_tool_index_task( void *ctx, void *ptr );

static int
mdb_tool_entry_get_int( BackendDB *be, ID id, Entry **ep );

int mdb_tool_entry_open(
	BackendDB *be, int mode )
{
	struct mdb_info *mdb = (struct mdb_info *) be->be_private;

	/* initialize key and data thangs */
	DBTzero( &key );
	DBTzero( &data );
	key.flags = DB_DBT_USERMEM;
	key.data = &nid;
	key.size = key.ulen = sizeof( nid );
	data.flags = DB_DBT_USERMEM;

	if (cursor == NULL) {
		int rc = mdb->bi_id2entry->bdi_db->cursor(
			mdb->bi_id2entry->bdi_db, mdb->bi_cache.c_txn, &cursor,
			mdb->bi_db_opflags );
		if( rc != 0 ) {
			return -1;
		}
	}

	/* Set up for threaded slapindex */
	if (( slapMode & (SLAP_TOOL_QUICK|SLAP_TOOL_READONLY)) == SLAP_TOOL_QUICK ) {
		if ( !mdb_tool_info ) {
#ifdef USE_TRICKLE
			ldap_pvt_thread_mutex_init( &mdb_tool_trickle_mutex );
			ldap_pvt_thread_cond_init( &mdb_tool_trickle_cond );
			ldap_pvt_thread_cond_init( &mdb_tool_trickle_cond_end );
			ldap_pvt_thread_pool_submit( &connection_pool, mdb_tool_trickle_task, mdb->bi_dbenv );
#endif

			ldap_pvt_thread_mutex_init( &mdb_tool_index_mutex );
			ldap_pvt_thread_cond_init( &mdb_tool_index_cond_main );
			ldap_pvt_thread_cond_init( &mdb_tool_index_cond_work );
			if ( mdb->bi_nattrs ) {
				int i;
				mdb_tool_index_threads = ch_malloc( slap_tool_thread_max * sizeof( int ));
				mdb_tool_index_rec = ch_malloc( mdb->bi_nattrs * sizeof( IndexRec ));
				mdb_tool_index_tcount = slap_tool_thread_max - 1;
				for (i=1; i<slap_tool_thread_max; i++) {
					int *ptr = ch_malloc( sizeof( int ));
					*ptr = i;
					ldap_pvt_thread_pool_submit( &connection_pool,
						mdb_tool_index_task, ptr );
				}
			}
			mdb_tool_info = mdb;
		}
	}

	return 0;
}

int mdb_tool_entry_close(
	BackendDB *be )
{
	if ( mdb_tool_info ) {
		slapd_shutdown = 1;
#ifdef USE_TRICKLE
		ldap_pvt_thread_mutex_lock( &mdb_tool_trickle_mutex );

		/* trickle thread may not have started yet */
		while ( !mdb_tool_trickle_active )
			ldap_pvt_thread_cond_wait( &mdb_tool_trickle_cond_end,
					&mdb_tool_trickle_mutex );

		ldap_pvt_thread_cond_signal( &mdb_tool_trickle_cond );
		while ( mdb_tool_trickle_active )
			ldap_pvt_thread_cond_wait( &mdb_tool_trickle_cond_end,
					&mdb_tool_trickle_mutex );
		ldap_pvt_thread_mutex_unlock( &mdb_tool_trickle_mutex );
#endif
		ldap_pvt_thread_mutex_lock( &mdb_tool_index_mutex );

		/* There might still be some threads starting */
		while ( mdb_tool_index_tcount ) {
			ldap_pvt_thread_cond_wait( &mdb_tool_index_cond_main,
					&mdb_tool_index_mutex );
		}

		mdb_tool_index_tcount = slap_tool_thread_max - 1;
		ldap_pvt_thread_cond_broadcast( &mdb_tool_index_cond_work );

		/* Make sure all threads are stopped */
		while ( mdb_tool_index_tcount ) {
			ldap_pvt_thread_cond_wait( &mdb_tool_index_cond_main,
				&mdb_tool_index_mutex );
		}
		ldap_pvt_thread_mutex_unlock( &mdb_tool_index_mutex );

		mdb_tool_info = NULL;
		slapd_shutdown = 0;
		ch_free( mdb_tool_index_threads );
		ch_free( mdb_tool_index_rec );
		mdb_tool_index_tcount = slap_tool_thread_max - 1;
	}

	if( eh.bv.bv_val ) {
		ch_free( eh.bv.bv_val );
		eh.bv.bv_val = NULL;
	}

	if( cursor ) {
		cursor->c_close( cursor );
		cursor = NULL;
	}

	if( nholes ) {
		unsigned i;
		fprintf( stderr, "Error, entries missing!\n");
		for (i=0; i<nholes; i++) {
			fprintf(stderr, "  entry %ld: %s\n",
				holes[i].id, holes[i].dn.bv_val);
		}
		return -1;
	}
			
	return 0;
}

ID
mdb_tool_entry_first_x(
	BackendDB *be,
	struct berval *base,
	int scope,
	Filter *f )
{
	tool_base = base;
	tool_scope = scope;
	tool_filter = f;
	
	return mdb_tool_entry_next( be );
}

ID mdb_tool_entry_next(
	BackendDB *be )
{
	int rc;
	ID id;
	struct mdb_info *mdb;

	assert( be != NULL );
	assert( slapMode & SLAP_TOOL_MODE );

	mdb = (struct mdb_info *) be->be_private;
	assert( mdb != NULL );

next:;
	/* Get the header */
	data.ulen = data.dlen = sizeof( ehbuf );
	data.data = ehbuf;
	data.flags |= DB_DBT_PARTIAL;
	rc = cursor->c_get( cursor, &key, &data, DB_NEXT );

	if( rc ) {
		/* If we're doing linear indexing and there are more attrs to
		 * index, and we're at the end of the database, start over.
		 */
		if ( index_nattrs && rc == DB_NOTFOUND ) {
			/* optional - do a checkpoint here? */
			mdb_attr_info_free( mdb->bi_attrs[0] );
			mdb->bi_attrs[0] = mdb->bi_attrs[index_nattrs];
			index_nattrs--;
			rc = cursor->c_get( cursor, &key, &data, DB_FIRST );
			if ( rc ) {
				return NOID;
			}
		} else {
			return NOID;
		}
	}

	MDB_DISK2ID( key.data, &id );
	previd = id;

	if ( tool_filter || tool_base ) {
		static Operation op = {0};
		static Opheader ohdr = {0};

		op.o_hdr = &ohdr;
		op.o_bd = be;
		op.o_tmpmemctx = NULL;
		op.o_tmpmfuncs = &ch_mfuncs;

		if ( tool_next_entry ) {
			mdb_entry_release( &op, tool_next_entry, 0 );
			tool_next_entry = NULL;
		}

		rc = mdb_tool_entry_get_int( be, id, &tool_next_entry );
		if ( rc == LDAP_NO_SUCH_OBJECT ) {
			goto next;
		}

		assert( tool_next_entry != NULL );

#ifdef MDB_HIER
		/* TODO: needed until MDB_HIER is handled accordingly
		 * in mdb_tool_entry_get_int() */
		if ( tool_base && !dnIsSuffixScope( &tool_next_entry->e_nname, tool_base, tool_scope ) )
		{
			mdb_entry_release( &op, tool_next_entry, 0 );
			tool_next_entry = NULL;
			goto next;
		}
#endif

		if ( tool_filter && test_filter( NULL, tool_next_entry, tool_filter ) != LDAP_COMPARE_TRUE )
		{
			mdb_entry_release( &op, tool_next_entry, 0 );
			tool_next_entry = NULL;
			goto next;
		}
	}

	return id;
}

ID mdb_tool_dn2id_get(
	Backend *be,
	struct berval *dn
)
{
	Operation op = {0};
	Opheader ohdr = {0};
	EntryInfo *ei = NULL;
	int rc;

	if ( BER_BVISEMPTY(dn) )
		return 0;

	op.o_hdr = &ohdr;
	op.o_bd = be;
	op.o_tmpmemctx = NULL;
	op.o_tmpmfuncs = &ch_mfuncs;

	rc = mdb_cache_find_ndn( &op, 0, dn, &ei );
	if ( ei ) mdb_cache_entryinfo_unlock( ei );
	if ( rc == DB_NOTFOUND )
		return NOID;
	
	return ei->bei_id;
}

static int
mdb_tool_entry_get_int( BackendDB *be, ID id, Entry **ep )
{
	Entry *e = NULL;
	char *dptr;
	int rc, eoff;

	assert( be != NULL );
	assert( slapMode & SLAP_TOOL_MODE );

	if ( ( tool_filter || tool_base ) && id == previd && tool_next_entry != NULL ) {
		*ep = tool_next_entry;
		tool_next_entry = NULL;
		return LDAP_SUCCESS;
	}

	if ( id != previd ) {
		data.ulen = data.dlen = sizeof( ehbuf );
		data.data = ehbuf;
		data.flags |= DB_DBT_PARTIAL;

		MDB_ID2DISK( id, &nid );
		rc = cursor->c_get( cursor, &key, &data, DB_SET );
		if ( rc ) {
			rc = LDAP_OTHER;
			goto done;
		}
	}

	/* Get the header */
	dptr = eh.bv.bv_val;
	eh.bv.bv_val = ehbuf;
	eh.bv.bv_len = data.size;
	rc = entry_header( &eh );
	eoff = eh.data - eh.bv.bv_val;
	eh.bv.bv_val = dptr;
	if ( rc ) {
		rc = LDAP_OTHER;
		goto done;
	}

	/* Get the size */
	data.flags &= ~DB_DBT_PARTIAL;
	data.ulen = 0;
	rc = cursor->c_get( cursor, &key, &data, DB_CURRENT );
	if ( rc != DB_BUFFER_SMALL ) {
		rc = LDAP_OTHER;
		goto done;
	}

	/* Allocate a block and retrieve the data */
	eh.bv.bv_len = eh.nvals * sizeof( struct berval ) + data.size;
	eh.bv.bv_val = ch_realloc( eh.bv.bv_val, eh.bv.bv_len );
	eh.data = eh.bv.bv_val + eh.nvals * sizeof( struct berval );
	data.data = eh.data;
	data.ulen = data.size;

	/* Skip past already parsed nattr/nvals */
	eh.data += eoff;

	rc = cursor->c_get( cursor, &key, &data, DB_CURRENT );
	if ( rc ) {
		rc = LDAP_OTHER;
		goto done;
	}

#ifndef MDB_HIER
	/* TODO: handle MDB_HIER accordingly */
	if ( tool_base != NULL ) {
		struct berval ndn;
		entry_decode_dn( &eh, NULL, &ndn );

		if ( !dnIsSuffixScope( &ndn, tool_base, tool_scope ) ) {
			return LDAP_NO_SUCH_OBJECT;
		}
	}
#endif

#ifdef SLAP_ZONE_ALLOC
	/* FIXME: will add ctx later */
	rc = entry_decode( &eh, &e, NULL );
#else
	rc = entry_decode( &eh, &e );
#endif

	if( rc == LDAP_SUCCESS ) {
		e->e_id = id;
#ifdef MDB_HIER
		if ( slapMode & SLAP_TOOL_READONLY ) {
			struct mdb_info *mdb = (struct mdb_info *) be->be_private;
			EntryInfo *ei = NULL;
			Operation op = {0};
			Opheader ohdr = {0};

			op.o_hdr = &ohdr;
			op.o_bd = be;
			op.o_tmpmemctx = NULL;
			op.o_tmpmfuncs = &ch_mfuncs;

			rc = mdb_cache_find_parent( &op, mdb->bi_cache.c_txn, id, &ei );
			if ( rc == LDAP_SUCCESS ) {
				mdb_cache_entryinfo_unlock( ei );
				e->e_private = ei;
				ei->bei_e = e;
				mdb_fix_dn( e, 0 );
				ei->bei_e = NULL;
				e->e_private = NULL;
			}
		}
#endif
	}
done:
	if ( e != NULL ) {
		*ep = e;
	}

	return rc;
}

Entry*
mdb_tool_entry_get( BackendDB *be, ID id )
{
	Entry *e = NULL;

	(void)mdb_tool_entry_get_int( be, id, &e );
	return e;
}

static int mdb_tool_next_id(
	Operation *op,
	DB_TXN *tid,
	Entry *e,
	struct berval *text,
	int hole )
{
	struct berval dn = e->e_name;
	struct berval ndn = e->e_nname;
	struct berval pdn, npdn;
	EntryInfo *ei = NULL, eidummy;
	int rc;

	if (ndn.bv_len == 0) {
		e->e_id = 0;
		return 0;
	}

	rc = mdb_cache_find_ndn( op, tid, &ndn, &ei );
	if ( ei ) mdb_cache_entryinfo_unlock( ei );
	if ( rc == DB_NOTFOUND ) {
		if ( !be_issuffix( op->o_bd, &ndn ) ) {
			ID eid = e->e_id;
			dnParent( &dn, &pdn );
			dnParent( &ndn, &npdn );
			e->e_name = pdn;
			e->e_nname = npdn;
			rc = mdb_tool_next_id( op, tid, e, text, 1 );
			e->e_name = dn;
			e->e_nname = ndn;
			if ( rc ) {
				return rc;
			}
			/* If parent didn't exist, it was created just now
			 * and its ID is now in e->e_id. Make sure the current
			 * entry gets added under the new parent ID.
			 */
			if ( eid != e->e_id ) {
				eidummy.bei_id = e->e_id;
				ei = &eidummy;
			}
		}
		rc = mdb_next_id( op->o_bd, &e->e_id );
		if ( rc ) {
			snprintf( text->bv_val, text->bv_len,
				"next_id failed: %s (%d)",
				db_strerror(rc), rc );
		Debug( LDAP_DEBUG_ANY,
			"=> mdb_tool_next_id: %s\n", text->bv_val, 0, 0 );
			return rc;
		}
		rc = mdb_dn2id_add( op, tid, ei, e );
		if ( rc ) {
			snprintf( text->bv_val, text->bv_len, 
				"dn2id_add failed: %s (%d)",
				db_strerror(rc), rc );
		Debug( LDAP_DEBUG_ANY,
			"=> mdb_tool_next_id: %s\n", text->bv_val, 0, 0 );
		} else if ( hole ) {
			if ( nholes == nhmax - 1 ) {
				if ( holes == hbuf ) {
					holes = ch_malloc( nhmax * sizeof(dn_id) * 2 );
					AC_MEMCPY( holes, hbuf, sizeof(hbuf) );
				} else {
					holes = ch_realloc( holes, nhmax * sizeof(dn_id) * 2 );
				}
				nhmax *= 2;
			}
			ber_dupbv( &holes[nholes].dn, &ndn );
			holes[nholes++].id = e->e_id;
		}
	} else if ( !hole ) {
		unsigned i, j;

		e->e_id = ei->bei_id;

		for ( i=0; i<nholes; i++) {
			if ( holes[i].id == e->e_id ) {
				free(holes[i].dn.bv_val);
				for (j=i;j<nholes;j++) holes[j] = holes[j+1];
				holes[j].id = 0;
				nholes--;
				break;
			} else if ( holes[i].id > e->e_id ) {
				break;
			}
		}
	}
	return rc;
}

static int
mdb_tool_index_add(
	Operation *op,
	DB_TXN *txn,
	Entry *e )
{
	struct mdb_info *mdb = (struct mdb_info *) op->o_bd->be_private;

	if ( !mdb->bi_nattrs )
		return 0;

	if ( slapMode & SLAP_TOOL_QUICK ) {
		IndexRec *ir;
		int i, rc;
		Attribute *a;
		
		ir = mdb_tool_index_rec;
		memset(ir, 0, mdb->bi_nattrs * sizeof( IndexRec ));

		for ( a = e->e_attrs; a != NULL; a = a->a_next ) {
			rc = mdb_index_recset( mdb, a, a->a_desc->ad_type, 
				&a->a_desc->ad_tags, ir );
			if ( rc )
				return rc;
		}
		mdb_tool_ix_id = e->e_id;
		mdb_tool_ix_op = op;
		ldap_pvt_thread_mutex_lock( &mdb_tool_index_mutex );
		/* Wait for all threads to be ready */
		while ( mdb_tool_index_tcount ) {
			ldap_pvt_thread_cond_wait( &mdb_tool_index_cond_main, 
				&mdb_tool_index_mutex );
		}
		for ( i=1; i<slap_tool_thread_max; i++ )
			mdb_tool_index_threads[i] = LDAP_BUSY;
		mdb_tool_index_tcount = slap_tool_thread_max - 1;
		ldap_pvt_thread_cond_broadcast( &mdb_tool_index_cond_work );
		ldap_pvt_thread_mutex_unlock( &mdb_tool_index_mutex );
		rc = mdb_index_recrun( op, mdb, ir, e->e_id, 0 );
		if ( rc )
			return rc;
		ldap_pvt_thread_mutex_lock( &mdb_tool_index_mutex );
		for ( i=1; i<slap_tool_thread_max; i++ ) {
			if ( mdb_tool_index_threads[i] == LDAP_BUSY ) {
				ldap_pvt_thread_cond_wait( &mdb_tool_index_cond_main, 
					&mdb_tool_index_mutex );
				i--;
				continue;
			}
			if ( mdb_tool_index_threads[i] ) {
				rc = mdb_tool_index_threads[i];
				break;
			}
		}
		ldap_pvt_thread_mutex_unlock( &mdb_tool_index_mutex );
		return rc;
	} else {
		return mdb_index_entry_add( op, txn, e );
	}
}

ID mdb_tool_entry_put(
	BackendDB *be,
	Entry *e,
	struct berval *text )
{
	int rc;
	struct mdb_info *mdb;
	DB_TXN *tid = NULL;
	Operation op = {0};
	Opheader ohdr = {0};

	assert( be != NULL );
	assert( slapMode & SLAP_TOOL_MODE );

	assert( text != NULL );
	assert( text->bv_val != NULL );
	assert( text->bv_val[0] == '\0' );	/* overconservative? */

	Debug( LDAP_DEBUG_TRACE, "=> " LDAP_XSTRING(mdb_tool_entry_put)
		"( %ld, \"%s\" )\n", (long) e->e_id, e->e_dn, 0 );

	mdb = (struct mdb_info *) be->be_private;

	if (! (slapMode & SLAP_TOOL_QUICK)) {
	rc = TXN_BEGIN( mdb->bi_dbenv, NULL, &tid, 
		mdb->bi_db_opflags );
	if( rc != 0 ) {
		snprintf( text->bv_val, text->bv_len,
			"txn_begin failed: %s (%d)",
			db_strerror(rc), rc );
		Debug( LDAP_DEBUG_ANY,
			"=> " LDAP_XSTRING(mdb_tool_entry_put) ": %s\n",
			 text->bv_val, 0, 0 );
		return NOID;
	}
	}

	op.o_hdr = &ohdr;
	op.o_bd = be;
	op.o_tmpmemctx = NULL;
	op.o_tmpmfuncs = &ch_mfuncs;

	/* add dn2id indices */
	rc = mdb_tool_next_id( &op, tid, e, text, 0 );
	if( rc != 0 ) {
		goto done;
	}

#ifdef USE_TRICKLE
	if (( slapMode & SLAP_TOOL_QUICK ) && (( e->e_id & 0xfff ) == 0xfff )) {
		ldap_pvt_thread_cond_signal( &mdb_tool_trickle_cond );
	}
#endif

	if ( !mdb->bi_linear_index )
		rc = mdb_tool_index_add( &op, tid, e );
	if( rc != 0 ) {
		snprintf( text->bv_val, text->bv_len,
				"index_entry_add failed: %s (%d)",
				rc == LDAP_OTHER ? "Internal error" :
				db_strerror(rc), rc );
		Debug( LDAP_DEBUG_ANY,
			"=> " LDAP_XSTRING(mdb_tool_entry_put) ": %s\n",
			text->bv_val, 0, 0 );
		goto done;
	}

	/* id2entry index */
	rc = mdb_id2entry_add( be, tid, e );
	if( rc != 0 ) {
		snprintf( text->bv_val, text->bv_len,
				"id2entry_add failed: %s (%d)",
				db_strerror(rc), rc );
		Debug( LDAP_DEBUG_ANY,
			"=> " LDAP_XSTRING(mdb_tool_entry_put) ": %s\n",
			text->bv_val, 0, 0 );
		goto done;
	}

done:
	if( rc == 0 ) {
		if ( !( slapMode & SLAP_TOOL_QUICK )) {
		rc = TXN_COMMIT( tid, 0 );
		if( rc != 0 ) {
			snprintf( text->bv_val, text->bv_len,
					"txn_commit failed: %s (%d)",
					db_strerror(rc), rc );
			Debug( LDAP_DEBUG_ANY,
				"=> " LDAP_XSTRING(mdb_tool_entry_put) ": %s\n",
				text->bv_val, 0, 0 );
			e->e_id = NOID;
		}
		}

	} else {
		if ( !( slapMode & SLAP_TOOL_QUICK )) {
		TXN_ABORT( tid );
		snprintf( text->bv_val, text->bv_len,
			"txn_aborted! %s (%d)",
			rc == LDAP_OTHER ? "Internal error" :
			db_strerror(rc), rc );
		Debug( LDAP_DEBUG_ANY,
			"=> " LDAP_XSTRING(mdb_tool_entry_put) ": %s\n",
			text->bv_val, 0, 0 );
		}
		e->e_id = NOID;
	}

	return e->e_id;
}

int mdb_tool_entry_reindex(
	BackendDB *be,
	ID id,
	AttributeDescription **adv )
{
	struct mdb_info *bi = (struct mdb_info *) be->be_private;
	int rc;
	Entry *e;
	DB_TXN *tid = NULL;
	Operation op = {0};
	Opheader ohdr = {0};

	Debug( LDAP_DEBUG_ARGS,
		"=> " LDAP_XSTRING(mdb_tool_entry_reindex) "( %ld )\n",
		(long) id, 0, 0 );
	assert( tool_base == NULL );
	assert( tool_filter == NULL );

	/* No indexes configured, nothing to do. Could return an
	 * error here to shortcut things.
	 */
	if (!bi->bi_attrs) {
		return 0;
	}

	/* Check for explicit list of attrs to index */
	if ( adv ) {
		int i, j, n;

		if ( bi->bi_attrs[0]->ai_desc != adv[0] ) {
			/* count */
			for ( n = 0; adv[n]; n++ ) ;

			/* insertion sort */
			for ( i = 0; i < n; i++ ) {
				AttributeDescription *ad = adv[i];
				for ( j = i-1; j>=0; j--) {
					if ( SLAP_PTRCMP( adv[j], ad ) <= 0 ) break;
					adv[j+1] = adv[j];
				}
				adv[j+1] = ad;
			}
		}

		for ( i = 0; adv[i]; i++ ) {
			if ( bi->bi_attrs[i]->ai_desc != adv[i] ) {
				for ( j = i+1; j < bi->bi_nattrs; j++ ) {
					if ( bi->bi_attrs[j]->ai_desc == adv[i] ) {
						AttrInfo *ai = bi->bi_attrs[i];
						bi->bi_attrs[i] = bi->bi_attrs[j];
						bi->bi_attrs[j] = ai;
						break;
					}
				}
				if ( j == bi->bi_nattrs ) {
					Debug( LDAP_DEBUG_ANY,
						LDAP_XSTRING(mdb_tool_entry_reindex)
						": no index configured for %s\n",
						adv[i]->ad_cname.bv_val, 0, 0 );
					return -1;
				}
			}
		}
		bi->bi_nattrs = i;
	}

	/* Get the first attribute to index */
	if (bi->bi_linear_index && !index_nattrs) {
		index_nattrs = bi->bi_nattrs - 1;
		bi->bi_nattrs = 1;
	}

	e = mdb_tool_entry_get( be, id );

	if( e == NULL ) {
		Debug( LDAP_DEBUG_ANY,
			LDAP_XSTRING(mdb_tool_entry_reindex)
			": could not locate id=%ld\n",
			(long) id, 0, 0 );
		return -1;
	}

	if (! (slapMode & SLAP_TOOL_QUICK)) {
	rc = TXN_BEGIN( bi->bi_dbenv, NULL, &tid, bi->bi_db_opflags );
	if( rc != 0 ) {
		Debug( LDAP_DEBUG_ANY,
			"=> " LDAP_XSTRING(mdb_tool_entry_reindex) ": "
			"txn_begin failed: %s (%d)\n",
			db_strerror(rc), rc, 0 );
		goto done;
	}
	}
 	
	/*
	 * just (re)add them for now
	 * assume that some other routine (not yet implemented)
	 * will zap index databases
	 *
	 */

	Debug( LDAP_DEBUG_TRACE,
		"=> " LDAP_XSTRING(mdb_tool_entry_reindex) "( %ld, \"%s\" )\n",
		(long) id, e->e_dn, 0 );

	op.o_hdr = &ohdr;
	op.o_bd = be;
	op.o_tmpmemctx = NULL;
	op.o_tmpmfuncs = &ch_mfuncs;

	rc = mdb_tool_index_add( &op, tid, e );

done:
	if( rc == 0 ) {
		if (! (slapMode & SLAP_TOOL_QUICK)) {
		rc = TXN_COMMIT( tid, 0 );
		if( rc != 0 ) {
			Debug( LDAP_DEBUG_ANY,
				"=> " LDAP_XSTRING(mdb_tool_entry_reindex)
				": txn_commit failed: %s (%d)\n",
				db_strerror(rc), rc, 0 );
			e->e_id = NOID;
		}
		}

	} else {
		if (! (slapMode & SLAP_TOOL_QUICK)) {
		TXN_ABORT( tid );
		Debug( LDAP_DEBUG_ANY,
			"=> " LDAP_XSTRING(mdb_tool_entry_reindex)
			": txn_aborted! %s (%d)\n",
			db_strerror(rc), rc, 0 );
		}
		e->e_id = NOID;
	}
	mdb_entry_release( &op, e, 0 );

	return rc;
}

ID mdb_tool_entry_modify(
	BackendDB *be,
	Entry *e,
	struct berval *text )
{
	int rc;
	struct mdb_info *mdb;
	DB_TXN *tid = NULL;
	Operation op = {0};
	Opheader ohdr = {0};

	assert( be != NULL );
	assert( slapMode & SLAP_TOOL_MODE );

	assert( text != NULL );
	assert( text->bv_val != NULL );
	assert( text->bv_val[0] == '\0' );	/* overconservative? */

	assert ( e->e_id != NOID );

	Debug( LDAP_DEBUG_TRACE,
		"=> " LDAP_XSTRING(mdb_tool_entry_modify) "( %ld, \"%s\" )\n",
		(long) e->e_id, e->e_dn, 0 );

	mdb = (struct mdb_info *) be->be_private;

	if (! (slapMode & SLAP_TOOL_QUICK)) {
		if( cursor ) {
			cursor->c_close( cursor );
			cursor = NULL;
		}
		rc = TXN_BEGIN( mdb->bi_dbenv, NULL, &tid, 
			mdb->bi_db_opflags );
		if( rc != 0 ) {
			snprintf( text->bv_val, text->bv_len,
				"txn_begin failed: %s (%d)",
				db_strerror(rc), rc );
			Debug( LDAP_DEBUG_ANY,
				"=> " LDAP_XSTRING(mdb_tool_entry_modify) ": %s\n",
				 text->bv_val, 0, 0 );
			return NOID;
		}
	}

	op.o_hdr = &ohdr;
	op.o_bd = be;
	op.o_tmpmemctx = NULL;
	op.o_tmpmfuncs = &ch_mfuncs;

	/* id2entry index */
	rc = mdb_id2entry_update( be, tid, e );
	if( rc != 0 ) {
		snprintf( text->bv_val, text->bv_len,
				"id2entry_add failed: %s (%d)",
				db_strerror(rc), rc );
		Debug( LDAP_DEBUG_ANY,
			"=> " LDAP_XSTRING(mdb_tool_entry_modify) ": %s\n",
			text->bv_val, 0, 0 );
		goto done;
	}

done:
	if( rc == 0 ) {
		if (! (slapMode & SLAP_TOOL_QUICK)) {
		rc = TXN_COMMIT( tid, 0 );
		if( rc != 0 ) {
			snprintf( text->bv_val, text->bv_len,
					"txn_commit failed: %s (%d)",
					db_strerror(rc), rc );
			Debug( LDAP_DEBUG_ANY,
				"=> " LDAP_XSTRING(mdb_tool_entry_modify) ": "
				"%s\n", text->bv_val, 0, 0 );
			e->e_id = NOID;
		}
		}

	} else {
		if (! (slapMode & SLAP_TOOL_QUICK)) {
		TXN_ABORT( tid );
		snprintf( text->bv_val, text->bv_len,
			"txn_aborted! %s (%d)",
			db_strerror(rc), rc );
		Debug( LDAP_DEBUG_ANY,
			"=> " LDAP_XSTRING(mdb_tool_entry_modify) ": %s\n",
			text->bv_val, 0, 0 );
		}
		e->e_id = NOID;
	}

	return e->e_id;
}

#ifdef USE_TRICKLE
static void *
mdb_tool_trickle_task( void *ctx, void *ptr )
{
	DB_ENV *env = ptr;
	int wrote;

	ldap_pvt_thread_mutex_lock( &mdb_tool_trickle_mutex );
	mdb_tool_trickle_active = 1;
	ldap_pvt_thread_cond_signal( &mdb_tool_trickle_cond_end );
	while ( 1 ) {
		ldap_pvt_thread_cond_wait( &mdb_tool_trickle_cond,
			&mdb_tool_trickle_mutex );
		if ( slapd_shutdown )
			break;
		env->memp_trickle( env, 30, &wrote );
	}
	mdb_tool_trickle_active = 0;
	ldap_pvt_thread_cond_signal( &mdb_tool_trickle_cond_end );
	ldap_pvt_thread_mutex_unlock( &mdb_tool_trickle_mutex );

	return NULL;
}
#endif

static void *
mdb_tool_index_task( void *ctx, void *ptr )
{
	int base = *(int *)ptr;

	free( ptr );
	while ( 1 ) {
		ldap_pvt_thread_mutex_lock( &mdb_tool_index_mutex );
		mdb_tool_index_tcount--;
		if ( !mdb_tool_index_tcount )
			ldap_pvt_thread_cond_signal( &mdb_tool_index_cond_main );
		ldap_pvt_thread_cond_wait( &mdb_tool_index_cond_work,
			&mdb_tool_index_mutex );
		if ( slapd_shutdown ) {
			mdb_tool_index_tcount--;
			if ( !mdb_tool_index_tcount )
				ldap_pvt_thread_cond_signal( &mdb_tool_index_cond_main );
			ldap_pvt_thread_mutex_unlock( &mdb_tool_index_mutex );
			break;
		}
		ldap_pvt_thread_mutex_unlock( &mdb_tool_index_mutex );

		mdb_tool_index_threads[base] = mdb_index_recrun( mdb_tool_ix_op,
			mdb_tool_info, mdb_tool_index_rec, mdb_tool_ix_id, base );
	}

	return NULL;
}
