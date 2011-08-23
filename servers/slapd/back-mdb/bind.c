/* bind.c - mdb backend bind routine */
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
#include <ac/unistd.h>

#include "back-mdb.h"

int
mdb_bind( Operation *op, SlapReply *rs )
{
	struct mdb_info *mdb = (struct mdb_info *) op->o_bd->be_private;
	Entry		*e;
	Attribute	*a;

	AttributeDescription *password = slap_schema.si_ad_userPassword;

	MDB_txn		*rtxn;

	Debug( LDAP_DEBUG_ARGS,
		"==> " LDAP_XSTRING(mdb_bind) ": dn: %s\n",
		op->o_req_dn.bv_val, 0, 0);

	/* allow noauth binds */
	switch ( be_rootdn_bind( op, NULL ) ) {
	case LDAP_SUCCESS:
		/* frontend will send result */
		return rs->sr_err = LDAP_SUCCESS;

	default:
		/* give the database a chance */
		/* NOTE: this behavior departs from that of other backends,
		 * since the others, in case of password checking failure
		 * do not give the database a chance.  If an entry with
		 * rootdn's name does not exist in the database the result
		 * will be the same.  See ITS#4962 for discussion. */
		break;
	}

	rs->sr_err = mdb_reader_get(op, mdb->mi_dbenv, &rtxn);
	switch(rs->sr_err) {
	case 0:
		break;
	default:
		rs->sr_text = "internal error";
		send_ldap_result( op, rs );
		return rs->sr_err;
	}

	/* get entry with reader lock */
	rs->sr_err = mdb_dn2entry( op, rtxn, &op->o_req_ndn, &e, 0 );

	switch(rs->sr_err) {
	case MDB_NOTFOUND:
		rs->sr_err = LDAP_INVALID_CREDENTIALS;
		send_ldap_result( op, rs );
		return rs->sr_err;
	case 0:
		break;
	case LDAP_BUSY:
		send_ldap_error( op, rs, LDAP_BUSY, "ldap_server_busy" );
		return LDAP_BUSY;
	default:
		send_ldap_error( op, rs, LDAP_OTHER, "internal error" );
		return rs->sr_err;
	}

	ber_dupbv( &op->oq_bind.rb_edn, &e->e_name );

	/* check for deleted */
	if ( is_entry_subentry( e ) ) {
		/* entry is an subentry, don't allow bind */
		Debug( LDAP_DEBUG_TRACE, "entry is subentry\n", 0,
			0, 0 );
		rs->sr_err = LDAP_INVALID_CREDENTIALS;
		goto done;
	}

	if ( is_entry_alias( e ) ) {
		/* entry is an alias, don't allow bind */
		Debug( LDAP_DEBUG_TRACE, "entry is alias\n", 0, 0, 0 );
		rs->sr_err = LDAP_INVALID_CREDENTIALS;
		goto done;
	}

	if ( is_entry_referral( e ) ) {
		Debug( LDAP_DEBUG_TRACE, "entry is referral\n", 0,
			0, 0 );
		rs->sr_err = LDAP_INVALID_CREDENTIALS;
		goto done;
	}

	switch ( op->oq_bind.rb_method ) {
	case LDAP_AUTH_SIMPLE:
		a = attr_find( e->e_attrs, password );
		if ( a == NULL ) {
			rs->sr_err = LDAP_INVALID_CREDENTIALS;
			goto done;
		}

		if ( slap_passwd_check( op, e, a, &op->oq_bind.rb_cred,
					&rs->sr_text ) != 0 )
		{
			/* failure; stop front end from sending result */
			rs->sr_err = LDAP_INVALID_CREDENTIALS;
			goto done;
		}
			
		rs->sr_err = 0;
		break;

	default:
		assert( 0 ); /* should not be reachable */
		rs->sr_err = LDAP_STRONG_AUTH_NOT_SUPPORTED;
		rs->sr_text = "authentication method not supported";
	}

done:
	/* free entry and reader lock */
	if( e != NULL ) {
		mdb_entry_return( e );
	}

	if ( rs->sr_err ) {
		send_ldap_result( op, rs );
		if ( rs->sr_ref ) {
			ber_bvarray_free( rs->sr_ref );
			rs->sr_ref = NULL;
		}
	}
	/* front end will send result on success (rs->sr_err==0) */
	return rs->sr_err;
}
