/* attr.c - backend routines for dealing with attributes */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2000-2024 The OpenLDAP Foundation.
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

#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "back-mdb.h"
#include "slap-config.h"
#include "lutil.h"

/* Find the ad, return -1 if not found,
 * set point for insertion if ins is non-NULL
 */
int
mdb_attr_slot( struct mdb_info *mdb, AttributeDescription *ad, int *ins )
{
	unsigned base = 0, cursor = 0;
	unsigned n = mdb->mi_nattrs;
	int val = 0;
	
	while ( 0 < n ) {
		unsigned pivot = n >> 1;
		cursor = base + pivot;

		val = SLAP_PTRCMP( ad, mdb->mi_attrs[cursor]->ai_desc );
		if ( val < 0 ) {
			n = pivot;
		} else if ( val > 0 ) {
			base = cursor + 1;
			n -= pivot + 1;
		} else {
			return cursor;
		}
	}
	if ( ins ) {
		if ( val > 0 )
			++cursor;
		*ins = cursor;
	}
	return -1;
}

static int
ainfo_insert( struct mdb_info *mdb, AttrInfo *a )
{
	int x;
	int i = mdb_attr_slot( mdb, a->ai_desc, &x );

	/* Is it a dup? */
	if ( i >= 0 )
		return -1;

	mdb->mi_attrs = ch_realloc( mdb->mi_attrs, ( mdb->mi_nattrs+1 ) * 
		sizeof( AttrInfo * ));
	if ( x < mdb->mi_nattrs )
		AC_MEMCPY( &mdb->mi_attrs[x+1], &mdb->mi_attrs[x],
			( mdb->mi_nattrs - x ) * sizeof( AttrInfo *));
	mdb->mi_attrs[x] = a;
	mdb->mi_nattrs++;
	return 0;
}

AttrInfo *
mdb_attr_mask(
	struct mdb_info	*mdb,
	AttributeDescription *desc )
{
	int i = mdb_attr_slot( mdb, desc, NULL );
	return i < 0 ? NULL : mdb->mi_attrs[i];
}

/* Open all un-opened index DB handles */
int
mdb_attr_dbs_open(
	BackendDB *be, MDB_txn *tx0, ConfigReply *cr )
{
	struct mdb_info *mdb = (struct mdb_info *) be->be_private;
	MDB_txn *txn;
	MDB_dbi *dbis = NULL;
	int i, flags;
	int rc;

	if ( !mdb->mi_nattrs )
		return 0;

	txn = tx0;
	if ( txn == NULL ) {
		rc = mdb_txn_begin( mdb->mi_dbenv, NULL, 0, &txn );
		if ( rc ) {
			snprintf( cr->msg, sizeof(cr->msg), "database \"%s\": "
				"txn_begin failed: %s (%d).",
				be->be_suffix[0].bv_val, mdb_strerror(rc), rc );
			Debug( LDAP_DEBUG_ANY,
				LDAP_XSTRING(mdb_attr_dbs) ": %s\n",
				cr->msg );
			return rc;
		}
		dbis = ch_calloc( 1, mdb->mi_nattrs * sizeof(MDB_dbi) );
	} else {
		rc = 0;
	}

	flags = MDB_DUPSORT|MDB_DUPFIXED|MDB_INTEGERDUP;
	if ( !(slapMode & SLAP_TOOL_READONLY) )
		flags |= MDB_CREATE;

	for ( i=0; i<mdb->mi_nattrs; i++ ) {
		if ( mdb->mi_attrs[i]->ai_dbi )	/* already open */
			continue;
		if ( !( mdb->mi_attrs[i]->ai_indexmask || mdb->mi_attrs[i]->ai_newmask ))	/* not an index record */
			continue;
		rc = mdb_dbi_open( txn, mdb->mi_attrs[i]->ai_desc->ad_type->sat_cname.bv_val,
			flags, &mdb->mi_attrs[i]->ai_dbi );
		if ( rc ) {
			snprintf( cr->msg, sizeof(cr->msg), "database \"%s\": "
				"mdb_dbi_open(%s) failed: %s (%d).",
				be->be_suffix[0].bv_val,
				mdb->mi_attrs[i]->ai_desc->ad_type->sat_cname.bv_val,
				mdb_strerror(rc), rc );
			Debug( LDAP_DEBUG_ANY,
				LDAP_XSTRING(mdb_attr_dbs) ": %s\n",
				cr->msg );
			break;
		}
		/* Remember newly opened DBI handles */
		if ( dbis )
			dbis[i] = mdb->mi_attrs[i]->ai_dbi;
	}

	/* Only commit if this is our txn */
	if ( tx0 == NULL ) {
		if ( !rc ) {
			rc = mdb_txn_commit( txn );
			if ( rc ) {
				snprintf( cr->msg, sizeof(cr->msg), "database \"%s\": "
					"txn_commit failed: %s (%d).",
					be->be_suffix[0].bv_val, mdb_strerror(rc), rc );
				Debug( LDAP_DEBUG_ANY,
					LDAP_XSTRING(mdb_attr_dbs) ": %s\n",
					cr->msg );
			}
		} else {
			mdb_txn_abort( txn );
		}
		/* Something failed, forget anything we just opened */
		if ( rc ) {
			for ( i=0; i<mdb->mi_nattrs; i++ ) {
				if ( dbis[i] ) {
					mdb->mi_attrs[i]->ai_dbi = 0;
					mdb->mi_attrs[i]->ai_indexmask |= MDB_INDEX_DELETING;
				}
			}
			mdb_attr_flush( mdb );
		}
		ch_free( dbis );
	}

	return rc;
}

void
mdb_attr_dbs_close(
	struct mdb_info *mdb
)
{
	int i;
	for ( i=0; i<mdb->mi_nattrs; i++ )
		if ( mdb->mi_attrs[i]->ai_dbi ) {
			mdb_dbi_close( mdb->mi_dbenv, mdb->mi_attrs[i]->ai_dbi );
			mdb->mi_attrs[i]->ai_dbi = 0;
		}
}

int
mdb_attr_index_config(
	struct mdb_info	*mdb,
	const char		*fname,
	int			lineno,
	int			argc,
	char		**argv,
	struct		config_reply_s *c_reply)
{
	int rc = 0;
	int	i;
	slap_mask_t mask;
	char **attrs;
	char **indexes = NULL;

	attrs = ldap_str2charray( argv[0], "," );

	if( attrs == NULL ) {
		fprintf( stderr, "%s: line %d: "
			"no attributes specified: %s\n",
			fname, lineno, argv[0] );
		return LDAP_PARAM_ERROR;
	}

	if ( argc > 1 ) {
		indexes = ldap_str2charray( argv[1], "," );

		if( indexes == NULL ) {
			fprintf( stderr, "%s: line %d: "
				"no indexes specified: %s\n",
				fname, lineno, argv[1] );
			rc = LDAP_PARAM_ERROR;
			goto done;
		}
	}

	if( indexes == NULL ) {
		mask = mdb->mi_defaultmask;

	} else {
		mask = 0;

		for ( i = 0; indexes[i] != NULL; i++ ) {
			slap_mask_t index;
			rc = slap_str2index( indexes[i], &index );

			if( rc != LDAP_SUCCESS ) {
				if ( c_reply )
				{
					snprintf(c_reply->msg, sizeof(c_reply->msg),
						"index type \"%s\" undefined", indexes[i] );

					fprintf( stderr, "%s: line %d: %s\n",
						fname, lineno, c_reply->msg );
				}
				rc = LDAP_PARAM_ERROR;
				goto done;
			}

			mask |= index;
		}
	}

	if( !mask ) {
		if ( c_reply )
		{
			snprintf(c_reply->msg, sizeof(c_reply->msg),
				"no indexes selected" );
			fprintf( stderr, "%s: line %d: %s\n",
				fname, lineno, c_reply->msg );
		}
		rc = LDAP_PARAM_ERROR;
		goto done;
	}

	for ( i = 0; attrs[i] != NULL; i++ ) {
		AttrInfo	*a;
		AttributeDescription *ad;
		const char *text;
#ifdef LDAP_COMP_MATCH
		ComponentReference* cr = NULL;
		AttrInfo *a_cr = NULL;
#endif

		if( strcasecmp( attrs[i], "default" ) == 0 ) {
			mdb->mi_defaultmask |= mask;
			continue;
		}

#ifdef LDAP_COMP_MATCH
		if ( is_component_reference( attrs[i] ) ) {
			rc = extract_component_reference( attrs[i], &cr );
			if ( rc != LDAP_SUCCESS ) {
				if ( c_reply )
				{
					snprintf(c_reply->msg, sizeof(c_reply->msg),
						"index component reference\"%s\" undefined",
						attrs[i] );
					fprintf( stderr, "%s: line %d: %s\n",
						fname, lineno, c_reply->msg );
				}
				goto done;
			}
			cr->cr_indexmask = mask;
			/*
			 * After extracting a component reference
			 * only the name of a attribute will be remaining
			 */
		} else {
			cr = NULL;
		}
#endif
		ad = NULL;
		rc = slap_str2ad( attrs[i], &ad, &text );

		if( rc != LDAP_SUCCESS ) {
			if ( c_reply )
			{
				snprintf(c_reply->msg, sizeof(c_reply->msg),
					"index attribute \"%s\" undefined",
					attrs[i] );

				fprintf( stderr, "%s: line %d: %s\n",
					fname, lineno, c_reply->msg );
			}
fail:
#ifdef LDAP_COMP_MATCH
			ch_free( cr );
#endif
			goto done;
		}

		if( ad == slap_schema.si_ad_entryDN || slap_ad_is_binary( ad ) ) {
			if (c_reply) {
				snprintf(c_reply->msg, sizeof(c_reply->msg),
					"index of attribute \"%s\" disallowed", attrs[i] );
				fprintf( stderr, "%s: line %d: %s\n",
					fname, lineno, c_reply->msg );
			}
			rc = LDAP_UNWILLING_TO_PERFORM;
			goto fail;
		}

		if( IS_SLAP_INDEX( mask, SLAP_INDEX_APPROX ) && !(
			ad->ad_type->sat_approx
				&& ad->ad_type->sat_approx->smr_indexer
				&& ad->ad_type->sat_approx->smr_filter ) )
		{
			if (c_reply) {
				snprintf(c_reply->msg, sizeof(c_reply->msg),
					"approx index of attribute \"%s\" disallowed", attrs[i] );
				fprintf( stderr, "%s: line %d: %s\n",
					fname, lineno, c_reply->msg );
			}
			rc = LDAP_INAPPROPRIATE_MATCHING;
			goto fail;
		}

		if( IS_SLAP_INDEX( mask, SLAP_INDEX_EQUALITY ) && !(
			ad->ad_type->sat_equality
				&& ad->ad_type->sat_equality->smr_indexer
				&& ad->ad_type->sat_equality->smr_filter ) )
		{
			if (c_reply) {
				snprintf(c_reply->msg, sizeof(c_reply->msg),
					"equality index of attribute \"%s\" disallowed", attrs[i] );
				fprintf( stderr, "%s: line %d: %s\n",
					fname, lineno, c_reply->msg );
			}
			rc = LDAP_INAPPROPRIATE_MATCHING;
			goto fail;
		}

		if( IS_SLAP_INDEX( mask, SLAP_INDEX_SUBSTR ) && !(
			ad->ad_type->sat_substr
				&& ad->ad_type->sat_substr->smr_indexer
				&& ad->ad_type->sat_substr->smr_filter ) )
		{
			if (c_reply) {
				snprintf(c_reply->msg, sizeof(c_reply->msg),
					"substr index of attribute \"%s\" disallowed", attrs[i] );
				fprintf( stderr, "%s: line %d: %s\n",
					fname, lineno, c_reply->msg );
			}
			rc = LDAP_INAPPROPRIATE_MATCHING;
			goto fail;
		}

		Debug( LDAP_DEBUG_CONFIG, "index %s 0x%04lx\n",
			ad->ad_cname.bv_val, mask );

		a = (AttrInfo *) ch_malloc( sizeof(AttrInfo) );

#ifdef LDAP_COMP_MATCH
		a->ai_cr = NULL;
#endif
		a->ai_cursor = NULL;
		a->ai_root = NULL;
		a->ai_desc = ad;
		a->ai_dbi = 0;
		a->ai_multi_hi = UINT_MAX;
		a->ai_multi_lo = UINT_MAX;

		if ( mdb->mi_flags & MDB_IS_OPEN ) {
			a->ai_indexmask = 0;
			a->ai_newmask = mask;
		} else {
			a->ai_indexmask = mask;
			a->ai_newmask = 0;
		}

#ifdef LDAP_COMP_MATCH
		if ( cr ) {
			a_cr = mdb_attr_mask( mdb, ad );
			if ( a_cr ) {
				/*
				 * AttrInfo is already in AVL
				 * just add the extracted component reference
				 * in the AttrInfo
				 */
				ch_free( a );
				rc = insert_component_reference( cr, &a_cr->ai_cr );
				if ( rc != LDAP_SUCCESS) {
					fprintf( stderr, " error during inserting component reference in %s ", attrs[i]);
					rc = LDAP_PARAM_ERROR;
					goto fail;
				}
				continue;
			} else {
				rc = insert_component_reference( cr, &a->ai_cr );
				if ( rc != LDAP_SUCCESS) {
					fprintf( stderr, " error during inserting component reference in %s ", attrs[i]);
					rc = LDAP_PARAM_ERROR;
					ch_free( a );
					goto fail;
				}
			}
		}
#endif
		rc = ainfo_insert( mdb, a );
		if( rc ) {
			AttrInfo *b = mdb_attr_mask( mdb, ad );
			/* If this is just a multival record, reuse it for index info */
			if ( !( b->ai_indexmask || b->ai_newmask ) && b->ai_multi_lo < UINT_MAX ) {
				b->ai_indexmask = a->ai_indexmask;
				b->ai_newmask = a->ai_newmask;
				ch_free( a );
				rc = 0;
				continue;
			}
			if ( mdb->mi_flags & MDB_IS_OPEN ) {
				/* If there is already an index defined for this attribute
				 * it must be replaced. Otherwise we end up with multiple 
				 * olcIndex values for the same attribute */
				if ( b->ai_indexmask & MDB_INDEX_DELETING ) {
					/* If we were editing this attr, reset it */
					b->ai_indexmask &= ~MDB_INDEX_DELETING;
					/* If this is leftover from a previous add, commit it */
					if ( b->ai_newmask )
						b->ai_indexmask = b->ai_newmask;
					/* If the mask changed, remember it */
					if ( b->ai_indexmask != a->ai_newmask )
						b->ai_newmask = a->ai_newmask;
					else	/* else ignore it */
						b->ai_newmask = 0;
					ch_free( a );
					rc = 0;
					continue;
				}
			}
			if (c_reply) {
				snprintf(c_reply->msg, sizeof(c_reply->msg),
					"duplicate index definition for attr \"%s\"",
					attrs[i] );
				fprintf( stderr, "%s: line %d: %s\n",
					fname, lineno, c_reply->msg );
			}

			rc = LDAP_PARAM_ERROR;
			goto done;
		}
	}

done:
	ldap_charray_free( attrs );
	if ( indexes != NULL ) ldap_charray_free( indexes );

	return rc;
}

static int
mdb_attr_index_unparser( void *v1, void *v2 )
{
	AttrInfo *ai = v1;
	BerVarray *bva = v2;
	struct berval bv;
	char *ptr;

	slap_index2bvlen( ai->ai_indexmask, &bv );
	if ( bv.bv_len ) {
		bv.bv_len += ai->ai_desc->ad_cname.bv_len + 1;
		ptr = ch_malloc( bv.bv_len+1 );
		bv.bv_val = lutil_strcopy( ptr, ai->ai_desc->ad_cname.bv_val );
		*bv.bv_val++ = ' ';
		slap_index2bv( ai->ai_indexmask, &bv );
		bv.bv_val = ptr;
		ber_bvarray_add( bva, &bv );
	}
	return 0;
}

static AttributeDescription addef = { NULL, NULL, BER_BVC("default") };
static AttrInfo aidef = { &addef };

void
mdb_attr_index_unparse( struct mdb_info *mdb, BerVarray *bva )
{
	int i;

	if ( mdb->mi_defaultmask ) {
		aidef.ai_indexmask = mdb->mi_defaultmask;
		mdb_attr_index_unparser( &aidef, bva );
	}
	for ( i=0; i<mdb->mi_nattrs; i++ )
		if ( mdb->mi_attrs[i]->ai_indexmask )
			mdb_attr_index_unparser( mdb->mi_attrs[i], bva );
}

int
mdb_attr_multi_config(
	struct mdb_info	*mdb,
	const char		*fname,
	int			lineno,
	int			argc,
	char		**argv,
	struct		config_reply_s *c_reply)
{
	int rc = 0;
	int	i;
	unsigned hi,lo;
	char **attrs, *next, *s;

	attrs = ldap_str2charray( argv[0], "," );

	if( attrs == NULL ) {
		fprintf( stderr, "%s: line %d: "
			"no attributes specified: %s\n",
			fname, lineno, argv[0] );
		return LDAP_PARAM_ERROR;
	}

	hi = strtoul( argv[1], &next, 10 );
	if ( next == argv[1] || next[0] != ',' )
		goto badval;
	s = next+1;
	lo = strtoul( s, &next, 10 );
	if ( next == s || next[0] != '\0' )
		goto badval;

	if ( lo > hi ) {
badval:
		snprintf(c_reply->msg, sizeof(c_reply->msg),
			"invalid hi/lo thresholds" );
		fprintf( stderr, "%s: line %d: %s\n",
			fname, lineno, c_reply->msg );
		return LDAP_PARAM_ERROR;
	}

	for ( i = 0; attrs[i] != NULL; i++ ) {
		AttrInfo	*a;
		AttributeDescription *ad;
		const char *text;

		if( strcasecmp( attrs[i], "default" ) == 0 ) {
			mdb->mi_multi_hi = hi;
			mdb->mi_multi_lo = lo;
			continue;
		}

		ad = NULL;
		rc = slap_str2ad( attrs[i], &ad, &text );

		if( rc != LDAP_SUCCESS ) {
			if ( c_reply )
			{
				snprintf(c_reply->msg, sizeof(c_reply->msg),
					"multival attribute \"%s\" undefined",
					attrs[i] );

				fprintf( stderr, "%s: line %d: %s\n",
					fname, lineno, c_reply->msg );
			}
fail:
			goto done;
		}

		a = (AttrInfo *) ch_calloc( 1, sizeof(AttrInfo) );

		a->ai_desc = ad;
		a->ai_multi_hi = hi;
		a->ai_multi_lo = lo;

		rc = ainfo_insert( mdb, a );
		if( rc ) {
			AttrInfo *b = mdb_attr_mask( mdb, ad );
			/* If this is just an index record, reuse it for multival info */
			if ( b->ai_multi_lo == UINT_MAX ) {
				b->ai_multi_hi = a->ai_multi_hi;
				b->ai_multi_lo = a->ai_multi_lo;
				ch_free( a );
				rc = 0;
				continue;
			}
			if (c_reply) {
				snprintf(c_reply->msg, sizeof(c_reply->msg),
					"duplicate multival definition for attr \"%s\"",
					attrs[i] );
				fprintf( stderr, "%s: line %d: %s\n",
					fname, lineno, c_reply->msg );
			}

			rc = LDAP_PARAM_ERROR;
			goto done;
		}
	}

done:
	ldap_charray_free( attrs );

	return rc;
}

static int
mdb_attr_multi_unparser( void *v1, void *v2 )
{
	AttrInfo *ai = v1;
	BerVarray *bva = v2;
	struct berval bv;
	char digbuf[sizeof("4294967296,4294967296")];
	char *ptr;

	bv.bv_len = snprintf( digbuf, sizeof(digbuf), "%u,%u",
		ai->ai_multi_hi, ai->ai_multi_lo );
	if ( bv.bv_len ) {
		bv.bv_len += ai->ai_desc->ad_cname.bv_len + 1;
		ptr = ch_malloc( bv.bv_len+1 );
		bv.bv_val = lutil_strcopy( ptr, ai->ai_desc->ad_cname.bv_val );
		*bv.bv_val++ = ' ';
		strcpy(bv.bv_val, digbuf);
		bv.bv_val = ptr;
		ber_bvarray_add( bva, &bv );
	}
	return 0;
}

void
mdb_attr_multi_unparse( struct mdb_info *mdb, BerVarray *bva )
{
	int i;

	if ( mdb->mi_multi_hi < UINT_MAX ) {
		aidef.ai_multi_hi = mdb->mi_multi_hi;
		aidef.ai_multi_lo = mdb->mi_multi_lo;
		mdb_attr_multi_unparser( &aidef, bva );
	}
	for ( i=0; i<mdb->mi_nattrs; i++ )
		if ( mdb->mi_attrs[i]->ai_multi_hi < UINT_MAX )
			mdb_attr_multi_unparser( mdb->mi_attrs[i], bva );
}

void
mdb_attr_multi_thresh( struct mdb_info *mdb, AttributeDescription *ad, unsigned *hi, unsigned *lo )
{
	AttrInfo *ai = mdb_attr_mask( mdb, ad );
	if ( ai && ai->ai_multi_hi < UINT_MAX )
	{
		if ( hi )
			*hi = ai->ai_multi_hi;
		if ( lo )
			*lo = ai->ai_multi_lo;
	} else
	{
		if ( hi )
			*hi = mdb->mi_multi_hi;
		if ( lo )
			*lo = mdb->mi_multi_lo;
	}
}

void
mdb_attr_info_free( AttrInfo *ai )
{
#ifdef LDAP_COMP_MATCH
	free( ai->ai_cr );
#endif
	free( ai );
}

void
mdb_attr_index_destroy( struct mdb_info *mdb )
{
	int i;

	for ( i=0; i<mdb->mi_nattrs; i++ ) 
		mdb_attr_info_free( mdb->mi_attrs[i] );

	free( mdb->mi_attrs );
}

void mdb_attr_index_free( struct mdb_info *mdb, AttributeDescription *ad )
{
	int i;

	i = mdb_attr_slot( mdb, ad, NULL );
	if ( i >= 0 ) {
		mdb_attr_info_free( mdb->mi_attrs[i] );
		mdb->mi_nattrs--;
		for (; i<mdb->mi_nattrs; i++)
			mdb->mi_attrs[i] = mdb->mi_attrs[i+1];
	}
}

void mdb_attr_flush( struct mdb_info *mdb )
{
	int i;

	for ( i=0; i<mdb->mi_nattrs; i++ ) {
		if ( mdb->mi_attrs[i]->ai_indexmask & MDB_INDEX_DELETING ) {
			/* if this is also a multival rec, just clear index */
			if ( mdb->mi_attrs[i]->ai_multi_lo < UINT_MAX ) {
				mdb->mi_attrs[i]->ai_indexmask = 0;
				mdb->mi_attrs[i]->ai_newmask = 0;
			} else {
				int j;
				mdb_attr_info_free( mdb->mi_attrs[i] );
				mdb->mi_nattrs--;
				for (j=i; j<mdb->mi_nattrs; j++)
					mdb->mi_attrs[j] = mdb->mi_attrs[j+1];
				i--;
			}
		}
	}
}

int mdb_ad_read( struct mdb_info *mdb, MDB_txn *txn )
{
	int i, rc;
	MDB_cursor *mc;
	MDB_val key, data;
	struct berval bdata;
	const char *text;
	AttributeDescription *ad;

	rc = mdb_cursor_open( txn, mdb->mi_ad2id, &mc );
	if ( rc ) {
		Debug( LDAP_DEBUG_ANY,
			"mdb_ad_read: cursor_open failed %s(%d)\n",
			mdb_strerror(rc), rc );
		return rc;
	}

	/* our array is 1-based, an index of 0 means no data */
	i = mdb->mi_numads+1;
	key.mv_size = sizeof(int);
	key.mv_data = &i;

	rc = mdb_cursor_get( mc, &key, &data, MDB_SET );

	while ( rc == MDB_SUCCESS ) {
		bdata.bv_len = data.mv_size;
		bdata.bv_val = data.mv_data;
		ad = NULL;
		rc = slap_bv2ad( &bdata, &ad, &text );
		if ( rc ) {
			rc = slap_bv2undef_ad( &bdata, &mdb->mi_ads[i], &text, 0 );
		} else {
			if ( ad->ad_index >= MDB_MAXADS ) {
				Debug( LDAP_DEBUG_ANY,
					"mdb_adb_read: too many AttributeDescriptions in use\n" );
				return LDAP_OTHER;
			}
			mdb->mi_adxs[ad->ad_index] = i;
			mdb->mi_ads[i] = ad;
		}
		i++;
		rc = mdb_cursor_get( mc, &key, &data, MDB_NEXT );
	}
	mdb->mi_numads = i-1;

done:
	if ( rc == MDB_NOTFOUND )
		rc = 0;

	mdb_cursor_close( mc );

	return rc;
}

int mdb_ad_get( struct mdb_info *mdb, MDB_txn *txn, AttributeDescription *ad )
{
	int i, rc;
	MDB_val key, val;

	rc = mdb_ad_read( mdb, txn );
	if (rc)
		return rc;

	if ( mdb->mi_adxs[ad->ad_index] )
		return 0;

	i = mdb->mi_numads+1;
	key.mv_size = sizeof(int);
	key.mv_data = &i;
	val.mv_size = ad->ad_cname.bv_len;
	val.mv_data = ad->ad_cname.bv_val;

	rc = mdb_put( txn, mdb->mi_ad2id, &key, &val, 0 );
	if ( rc == MDB_SUCCESS ) {
		mdb->mi_adxs[ad->ad_index] = i;
		mdb->mi_ads[i] = ad;
		mdb->mi_numads = i;
	} else {
		Debug( LDAP_DEBUG_ANY,
			"mdb_ad_get: mdb_put failed %s(%d)\n",
			mdb_strerror(rc), rc );
	}

	return rc;
}

void mdb_ad_unwind( struct mdb_info *mdb, int prev_ads )
{
	int i;

	for (i=mdb->mi_numads; i>prev_ads; i--) {
		mdb->mi_adxs[mdb->mi_ads[i]->ad_index] = 0;
		mdb->mi_ads[i] = NULL;
	}
	mdb->mi_numads = i;
}
