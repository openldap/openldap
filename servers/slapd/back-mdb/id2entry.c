/* id2entry.c - routines to deal with the id2entry database */
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

#include "back-mdb.h"

static int mdb_id2entry_put(
	Operation *op,
	MDB_txn *tid,
	Entry *e,
	int flag )
{
	struct mdb_info *mdb = (struct mdb_info *) op->o_bd->be_private;
	MDB_dbi dbi = mdb->mi_id2entry->mdi_dbi;
	MDB_val key, data;
	struct berval bv;
	int rc;
	struct berval odn, ondn;

	/* We only store rdns, and they go in the dn2id database. */

	odn = e->e_name; ondn = e->e_nname;

	e->e_name = slap_empty_bv;
	e->e_nname = slap_empty_bv;

	key.mv_data = &e->e_id;
	key.mv_size = sizeof(ID);

	rc = entry_encode( e, &bv );
	e->e_name = odn; e->e_nname = ondn;
	if( rc != LDAP_SUCCESS ) {
		return -1;
	}

	data.mv_size = bv.bv_len;
	data.mv_data = bv.bv_val;

	rc = mdb_put( tid, dbi, &key, &data, flag );

	op->o_tmpfree( op->o_tmpmemctx, bv.bv_val );
	return rc;
}

/*
 * This routine adds (or updates) an entry on disk.
 * The cache should be already be updated.
 */


int mdb_id2entry_add(
	Operation *op,
	MDB_txn *tid,
	Entry *e )
{
	return mdb_id2entry_put(op, tid, e, MDB_NOOVERWRITE);
}

int mdb_id2entry_update(
	Operation *op,
	MDB_txn *tid,
	Entry *e )
{
	return mdb_id2entry_put(op, tid, e, 0);
}

int mdb_id2entry(
	Operation *op,
	MDB_txn *tid,
	ID id,
	Entry **e )
{
	struct mdb_info *mdb = (struct mdb_info *) op->o_bd->be_private;
	MDB_dbi dbi = mdb->mi_id2entry->mdi_dbi;
	MDB_val key, data;
	EntryHeader eh;
	char buf[16];
	int rc = 0, off;

	*e = NULL;

	key.mv_data = &id;
	key.mv_size = sizeof(ID);

	/* fetch it */
	rc = mdb_get( tid, dbi, &key, &data );
	if ( rc ) return rc;

	eh.bv.bv_val = data.mv_data;
	eh.bv.bv_len = data.mv_size;
	rc = entry_header( &eh );
	if ( rc ) return rc;

	eh.bv.bv_len = eh.nvals * sizeof( struct berval );
	eh.bv.bv_val = ch_malloc( eh.bv.bv_len );
	rc = entry_decode(&eh, e);

	if( rc == 0 ) {
		(*e)->e_id = id;
		(*e)->e_bv = eh.bv;
	} else {
		ch_free( eh.bv.bv_val );
	}

	return rc;
}

int mdb_id2entry_delete(
	BackendDB *be,
	MDB_txn *tid,
	Entry *e )
{
	struct mdb_info *mdb = (struct mdb_info *) be->be_private;
	MDB_dbi dbi = mdb->mi_id2entry->mdi_dbi;
	MDB_val key;
	int rc;

	key.mv_data = &e->e_id;
	key.mv_size = sizeof(ID);

	/* delete from database */
	rc = mdb_del( tid, dbi, &key, NULL, 0 );

	return rc;
}

int mdb_entry_return(
	Entry *e
)
{
	/* Our entries are allocated in two blocks; the data comes from
	 * the db itself and the Entry structure and associated pointers
	 * are allocated in entry_decode. The db data pointer is saved
	 * in e_bv.
	 */
	if ( e->e_bv.bv_val ) {
		/* See if the DNs were changed by modrdn */
		if( e->e_nname.bv_val < e->e_bv.bv_val || e->e_nname.bv_val >
			e->e_bv.bv_val + e->e_bv.bv_len ) {
			ch_free(e->e_name.bv_val);
			ch_free(e->e_nname.bv_val);
		}
		e->e_name.bv_val = NULL;
		e->e_nname.bv_val = NULL;
		/* In tool mode the e_bv buffer is realloc'd, leave it alone */
		if( !(slapMode & SLAP_TOOL_MODE) ) {
			free( e->e_bv.bv_val );
		}
		BER_BVZERO( &e->e_bv );
	}
	entry_free( e );
	return 0;
}

int mdb_entry_release(
	Operation *op,
	Entry *e,
	int rw )
{
#if 0
	struct mdb_info *mdb = (struct mdb_info *) op->o_bd->be_private;
	struct mdb_op_info *moi;
	OpExtra *oex;
 
	/* slapMode : SLAP_SERVER_MODE, SLAP_TOOL_MODE,
			SLAP_TRUNCATE_MODE, SLAP_UNDEFINED_MODE */
 
	if ( slapMode == SLAP_SERVER_MODE ) {
		/* If not in our cache, just free it */
		if ( !e->e_private ) {
			return mdb_entry_return( e );
		}
		/* free entry and reader or writer lock */
		LDAP_SLIST_FOREACH( oex, &op->o_extra, oe_next ) {
			if ( oex->oe_key == mdb ) break;
		}
		moi = (struct mdb_op_info *)oex;

		/* lock is freed with txn */
		if ( !moi || moi->moi_txn ) {
			mdb_unlocked_cache_return_entry_rw( mdb, e, rw );
		} else {
			struct mdb_lock_info *bli, *prev;
			for ( prev=(struct mdb_lock_info *)&moi->boi_locks,
				bli = boi->boi_locks; bli; prev=bli, bli=bli->bli_next ) {
				if ( bli->bli_id == e->e_id ) {
					mdb_cache_return_entry_rw( mdb, e, rw, &bli->bli_lock );
					prev->bli_next = bli->bli_next;
					/* Cleanup, or let caller know we unlocked */
					if ( bli->bli_flag & BLI_DONTFREE )
						bli->bli_flag = 0;
					else
						op->o_tmpfree( bli, op->o_tmpmemctx );
					break;
				}
			}
			if ( !boi->boi_locks ) {
				LDAP_SLIST_REMOVE( &op->o_extra, &boi->boi_oe, OpExtra, oe_next );
				if ( !(boi->boi_flag & BOI_DONTFREE))
					op->o_tmpfree( boi, op->o_tmpmemctx );
			}
		}
	} else {
		if (e->e_private != NULL)
			BEI(e)->bei_e = NULL;
		e->e_private = NULL;
		mdb_entry_return ( e );
	}
 
	return 0;
#else
	return mdb_entry_return( e );
#endif
}

/* return LDAP_SUCCESS IFF we can retrieve the specified entry.
 */
int mdb_entry_get(
	Operation *op,
	struct berval *ndn,
	ObjectClass *oc,
	AttributeDescription *at,
	int rw,
	Entry **ent )
{
#if 0
	struct mdb_info *mdb = (struct mdb_info *) op->o_bd->be_private;
	struct mdb_op_info *boi = NULL;
	MDB_txn *txn = NULL;
	Entry *e = NULL;
	EntryInfo *ei;
	int	rc;
	const char *at_name = at ? at->ad_cname.bv_val : "(null)";

	Debug( LDAP_DEBUG_ARGS,
		"=> mdb_entry_get: ndn: \"%s\"\n", ndn->bv_val, 0, 0 ); 
	Debug( LDAP_DEBUG_ARGS,
		"=> mdb_entry_get: oc: \"%s\", at: \"%s\"\n",
		oc ? oc->soc_cname.bv_val : "(null)", at_name, 0);

	if( op ) {
		OpExtra *oex;
		LDAP_SLIST_FOREACH( oex, &op->o_extra, oe_next ) {
			if ( oex->oe_key == mdb ) break;
		}
		boi = (struct mdb_op_info *)oex;
		if ( boi )
			txn = boi->boi_txn;
	}

	if ( !txn ) {
		rc = mdb_reader_get( op, mdb->bi_dbenv, &txn );
		switch(rc) {
		case 0:
			break;
		default:
			return LDAP_OTHER;
		}
	}

dn2entry_retry:
	/* can we find entry */
	rc = mdb_dn2entry( op, txn, ndn, &ei, 0, &lock );
	switch( rc ) {
	case MDB_NOTFOUND:
	case 0:
		break;
	default:
		if ( boi ) boi->boi_err = rc;
		return (rc != LDAP_BUSY) ? LDAP_OTHER : LDAP_BUSY;
	}
	if (ei) e = ei->bei_e;
	if (e == NULL) {
		Debug( LDAP_DEBUG_ACL,
			"=> mdb_entry_get: cannot find entry: \"%s\"\n",
				ndn->bv_val, 0, 0 ); 
		return LDAP_NO_SUCH_OBJECT; 
	}
	
	Debug( LDAP_DEBUG_ACL,
		"=> mdb_entry_get: found entry: \"%s\"\n",
		ndn->bv_val, 0, 0 ); 

	if ( oc && !is_entry_objectclass( e, oc, 0 )) {
		Debug( LDAP_DEBUG_ACL,
			"<= mdb_entry_get: failed to find objectClass %s\n",
			oc->soc_cname.bv_val, 0, 0 ); 
		rc = LDAP_NO_SUCH_ATTRIBUTE;
		goto return_results;
	}

	/* NOTE: attr_find() or attrs_find()? */
	if ( at && attr_find( e->e_attrs, at ) == NULL ) {
		Debug( LDAP_DEBUG_ACL,
			"<= mdb_entry_get: failed to find attribute %s\n",
			at->ad_cname.bv_val, 0, 0 ); 
		rc = LDAP_NO_SUCH_ATTRIBUTE;
		goto return_results;
	}

return_results:
	if( rc != LDAP_SUCCESS ) {
		/* free entry */
		mdb_cache_return_entry_rw(mdb, e, rw, &lock);

	} else {
		if ( slapMode == SLAP_SERVER_MODE ) {
			*ent = e;
			/* big drag. we need a place to store a read lock so we can
			 * release it later?? If we're in a txn, nothing is needed
			 * here because the locks will go away with the txn.
			 */
			if ( op ) {
				if ( !boi ) {
					boi = op->o_tmpcalloc(1,sizeof(struct mdb_op_info),op->o_tmpmemctx);
					boi->boi_oe.oe_key = mdb;
					LDAP_SLIST_INSERT_HEAD( &op->o_extra, &boi->boi_oe, oe_next );
				}
				if ( !boi->boi_txn ) {
					struct mdb_lock_info *bli;
					bli = op->o_tmpalloc( sizeof(struct mdb_lock_info),
						op->o_tmpmemctx );
					bli->bli_next = boi->boi_locks;
					bli->bli_id = e->e_id;
					bli->bli_flag = 0;
					bli->bli_lock = lock;
					boi->boi_locks = bli;
				}
			}
		} else {
			*ent = entry_dup( e );
			mdb_cache_return_entry_rw(mdb, e, rw, &lock);
		}
	}

	Debug( LDAP_DEBUG_TRACE,
		"mdb_entry_get: rc=%d\n",
		rc, 0, 0 ); 
	return(rc);
#endif
}
