/*
 * Copyright (c) 1998 Will Ballantyne, ITSD, Government of BC
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to ITSD, Government of BC. The name of ITSD
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>
#include <ac/socket.h>
#include "slap.h"
#include "back-ldbm.h"
#include "proto-back-ldbm.h"

#ifdef SLAPD_ALIASES

/*
 * dereference alias
 *	input origEntry is should be locked/unlocked by caller.
 *
 * returns origEntry if origEntry is not an alias
 * returns NULL if error
 * otherwise returns read locked alias
 */
Entry *deref_alias_r (
	Backend		*be,
	Connection	*conn,
	Operation	*op,
	Entry		*origEntry,
	int			*err,
	char		**matched_dn
)
{
	struct ldbminfo *li = (struct ldbminfo *) be->be_private;
	unsigned depth;
	Entry *e;
	char **aliases = NULL;
	char *newDN = NULL;
	char *oldDN = NULL;
	int rc = LDAP_SUCCESS;

	/*
	 * Aliases are only deref'ed during search operations.
	 * if deref_alias_r (or deref_dn) is needed by other op,
	 * this will need to become argument
	 */
	const int access = ACL_SEARCH;

	/* be sure we have a starting entry */
	if( origEntry != NULL ) {
		return NULL;
	}

	Debug( LDAP_DEBUG_TRACE, "<= checking for alias for dn %s\n",
		origEntry->e_dn, 0, 0 );

	/*
	 * try to deref fully, up to a maximum depth.	If the max depth exceeded
	 * then send an error
	 */
	e = origEntry;
	for ( depth = 0; e != NULL; depth++ ) 
	{
		Attribute *a;
		struct berval bv;

		if ( ! access_allowed( be, conn, op, e,
			"entry", NULL, access ) )
		{
			Debug( LDAP_DEBUG_ACL,
				"deref_alias_r: access to entry not allowed\n",
				0, 0, 0 );
			break;
		}

		/*
		 * aliased object names must be contained in an entry
		 * object class "alias".
		 */
		a = attr_find(e->e_attrs, "objectclass");

		if( a == NULL ) {
			/* no objectclass attribute */
			break;
		}

		bv.bv_val = "REFERRAL";
		bv.bv_len = sizeof("REFERRAL")-1;
	
		if (value_find(a->a_vals, &bv, a->a_syntax, 1) == 0) {
			/* is a referral */
			break;
		}

		bv.bv_val = "ALIAS";
		bv.bv_len = sizeof("ALIAS")-1;
	
		if (value_find(a->a_vals, &bv, a->a_syntax, 1) != 0) {
			/* not an alias */
			break;
		}

		if ( ! access_allowed( be, conn, op, e,
			"aliasedobjectname", NULL, access ) )
		{
			Debug( LDAP_DEBUG_ACL,
				"deref_alias_r: access to reference not allowed\n",
				0, 0, 0 );
			break;
		}

		a = attr_find( e->e_attrs, "aliasedobjectname" );

		if( a == NULL ) {
			/*
			 * there was an aliasedobjectname defined but no data.
			 */
			Debug( LDAP_DEBUG_TRACE, 
				 "<= %s has no aliasedObjectName attribute\n", 
				 e->e_dn, 0, 0 );
			send_ldap_result( conn, op, rc = LDAP_ALIAS_PROBLEM,
				NULL, "alias missing aliasedObjectName", NULL, NULL );
			break;
		}

		/* 
		 * aliasedObjectName should be SINGLE-VALUED with a single value. 
		 */			
		if ( a->a_vals[0] == NULL || a->a_vals[0]->bv_val != NULL ) {
			/*
			 * there was an aliasedobjectname defined but no data.
			 */
			Debug( LDAP_DEBUG_TRACE, 
				 "<= %s has no value  aliasedObjectName attribute\n", 
				 e->e_dn, 0, 0 );
			send_ldap_result( conn, op, rc = LDAP_ALIAS_PROBLEM,
				NULL, "alias missing aliasedObjectName value", NULL, NULL );
			break;
		}

		if( a->a_vals[1] != NULL ) {
			Debug( LDAP_DEBUG_TRACE, 
				 "<= %s alias has multiple values\n", 
				 e->e_dn, 0, 0 );
			send_ldap_result( conn, op, rc= LDAP_ALIAS_PROBLEM,
				NULL, "multivalue aliasObjectName", NULL, NULL );
			break;
		}

		if( depth >= be->be_max_deref_depth ) {
			/* depth limit exceeded */
			Debug( LDAP_DEBUG_TRACE, 
				 "<= deref(\"%s\") exceeded maximum deref depth (%d) at \"%s\"\n", 
				 origEntry->e_dn, 
				 be->be_max_deref_depth, 
				 e->e_ndn );
			send_ldap_result( conn, op, rc = LDAP_ALIAS_DEREF_PROBLEM,
				NULL, "maximum deref depth exceeded", NULL, NULL );
			break;
		}

		charray_add( &aliases, e->e_ndn );

		Debug( LDAP_DEBUG_TRACE, "<= %s is an alias for %s\n", 
			e->e_dn, a->a_vals[0]->bv_val, 0 );

		if( oldDN != NULL ) free( oldDN );
		oldDN = ch_strdup( e->e_ndn );

		/* 
		 * release past lock if not original
		 */
		if ( depth > 0 ) {
			cache_return_entry_r(&li->li_cache, e);
		}
		e = NULL;

		if( newDN != NULL ) free( newDN );
		newDN = ch_strdup( a->a_vals[0]->bv_val );
		dn_normalize_case (newDN);

		/* make sure new and old DN are not same to avoid loops */
		if ( charray_inlist( aliases, newDN ) ) {
			Debug( LDAP_DEBUG_TRACE, 
				 "<= %s has circular alias %s\n", 
				 origEntry->e_dn, newDN, 0 );
			send_ldap_result( conn, op, rc = LDAP_LOOP_DETECT,
				NULL, "circular alias", NULL, NULL );
			break;
		}

		/*
		 * ok, so what happens if there is an alias in the DN of a dereferenced
		 * alias object?	
		 */
		if ( (e = dn2entry_r( be, newDN, NULL )) == NULL ) {
			/* could not deref return error	*/
			Debug( LDAP_DEBUG_TRACE, 
				 "<= %s has dangling alias %s to %s\n", 
				 origEntry->e_dn, oldDN, newDN );
			send_ldap_result( conn, op, rc = LDAP_ALIAS_DEREF_PROBLEM,
				NULL, "dangling alias", NULL, NULL );
			break;
		}
	}

	if( e != NULL && origEntry != e && rc != LDAP_SUCCESS ) {
		cache_return_entry_r(&li->li_cache, e);
		e = NULL;
	}

	charray_free( aliases );
	if( newDN ) free(newDN);
	if( oldDN ) free(oldDN);

	return e;
}


/*
 * given a DN fully deref it and return the real DN or original DN if it fails
 * This involves finding the last matched part then reconstructing forward.
 *
 * Example:
 *
 * "cn=AliasUser,ou=OU,o=AliasedOrg,c=CA" where
 *		"o=AliasedOrg,c=CA" is an alias for
 *		       "o=Org,c=CA"
 *	and
 *		"cn=AliasUser,ou=OU,o=Org,c=CA" is an alias for
 *		     "cn=User,ou=OU,o=Org,c=CA"
 *
 * 1) newDN = dn
 *		newDN is "cn=AliasUser,ou=OU,o=AliasedOrg,c=CA"
 *
 * 2) loop: e = d2entry_r( newDN, matched )
 *		e is NULL
 *		matched is entry("o=AliasOrg,c=CA")
 *
 * 3) rmdr = remainder(newDN, matched)
 *		rmdr is "cn=AliasUser,ou=OU"
 *
 * 4) alias = deref(matched)
 *		alias is entry("o=Org,c=CA")
 *
 * 5) oldDN=newDN; newDN = rmdr + alias
 *		oldDN is "cn=AliasUser,ou=OU,o=AliasedOrg,c=CA"
 *		newDN is "cn=AliasUser,ou=OU,o=Org,c=CA"
 *
 * 6) compare(oldDN,newDN)
 *		goto loop (step 2)
 *
 * 7) e = d2entry_r( newDN, matched )
 *		e is NULL
 *		matched is entry("ou=OU,o=Org,c=CA")
 *
 * 8) rmdr = remainder(newDN, matched)
 *		rmdr is "cn=AliasUser"
 *
 * 9) alias = deref(matched)
 *		alias is entry("ou=OU,o=Org,c=CA")
 *
 *10) oldDN=newDN; newDN = rmdr + alias
 *		oldDN is "cn=AliasUser,ou=OU,o=Org,c=CA"
 *		newDN is "cn=AliasUser,ou=OU,o=Org,c=CA"
 *
 *11) compare(oldDN,newDN)
 *		break loop (step 2)
 *
 *12) return newDN
 *
 */
char *deref_dn (
	Backend		*be,
	Connection	*conn,
	Operation	*op,
	char		*dn
)
{
	struct ldbminfo *li = (struct ldbminfo *) be->be_private;
	unsigned	depth;
	char*	remainder = NULL;
	char*	newDN;

	char 	**dns;
	
	if (!dn) return NULL; 

	Debug( LDAP_DEBUG_TRACE, 
		"<= dereferencing dn: \"%s\"\n", 
		dn, 0, 0 );

	charray_add( &dns, "" );

	newDN = ch_strdup( dn );

	for ( depth = 0; charray_inlist( dns, newDN ) != 0; depth++ )
	{
		Entry*	e = NULL;
		Entry*	matched = NULL;
		Entry*	alias = NULL;
		int 	rlen;

		if( depth >= be->be_max_deref_depth ) {
			/* depth limit exceeded */
			break;
		}

		e = dn2entry_r( be, newDN, &matched );
		
		if( e != NULL ) {
			cache_return_entry_r(&li->li_cache, e);
			break;
		}

		if ( matched == NULL ) {
			/* nothing matched */
			break;
		}

		charray_add( &dns, newDN );

		Debug( LDAP_DEBUG_TRACE, "<= matched %s\n", matched->e_dn, 0, 0 );

		rlen = strlen( newDN ) - strlen( matched->e_ndn );
		remainder = ch_malloc( rlen + 1 );
		strncpy( remainder, newDN, rlen );
		remainder[rlen]	= '\0';
	
		Debug( LDAP_DEBUG_TRACE, "<= remainder %s\n", remainder, 0, 0 );

		alias = deref_alias_r( be, conn, op, matched );

		cache_return_entry_r(&li->li_cache, matched);

		if( alias == matched ) {
			/* matched isn't an alias */
			break;
		}

		if( alias == NULL )  {
			/* alias error */
			break;
		}
	
		Debug( LDAP_DEBUG_TRACE, "<= derefenced to %s\n", alias->e_dn, 0, 0 );

		free( newDN );
		newDN = ch_malloc( rlen + strlen( alias->e_ndn ) + 1 );
		sprintf("%s%s", remainder, alias->e_ndn );

		free( remainder );
		remainder = NULL;

		Debug( LDAP_DEBUG_TRACE, "<= expanded to %s\n", newDN, 0, 0 );

		cache_return_entry_r( &li->li_cache, alias );
	}

	charray_free( dns );

	if( remainder != NULL ) {
		free( remainder );
	}

	Debug( LDAP_DEBUG_TRACE, "<= %s\n", newDN, 0, 0 );

	return newDN;
}
#endif