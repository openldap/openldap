/* dn2entry.c - routines to deal with the dn2id / id2entry glue */
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

#include "back-mdb.h"

/*
 * dn2entry - look up dn in the cache/indexes and return the corresponding
 * entry. If the requested DN is not found and matched is TRUE, return info
 * for the closest ancestor of the DN. Otherwise e is NULL.
 */

int
mdb_dn2entry(
	Operation *op,
	MDB_txn *tid,
	struct berval *dn,
	Entry **e,
	struct berval *matched )
{
	int rc, rc2;
	ID id;

	Debug(LDAP_DEBUG_TRACE, "mdb_dn2entry(\"%s\")\n",
		dn->bv_val, 0, 0 );

	*e = NULL;

	rc = mdb_dn2id( op, tid, dn, &id );
	if ( rc ) {
		*e = NULL;
		if ( matched && rc == MDB_NOTFOUND ) {
			/* Get the parent's DN */
			mdb_id2name( op, tid, id, matched, NULL );
		}
	} else {
		rc = mdb_id2entry( op, tid, id, e );
	}

	return rc;
}
