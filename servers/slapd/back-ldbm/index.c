/* index.c - routines for dealing with attribute indexes */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "back-ldbm.h"

static int	change_value(Backend *be,
			  struct dbcache *db,
			  AttributeType *at,
			  MatchingRule *mr,
			  char *val,
			  ID id,
			  int
			  (*idl_func)(Backend *, struct dbcache *, Datum, ID));
static int	index2prefix(AttributeType *at, MatchingRule *mr);

int
index_add_entry(
    Backend	*be,
    Entry	*e
)
{
	Attribute	*ap;
	struct berval	bv;
	struct berval	*bvals[2];

	Debug( LDAP_DEBUG_TRACE, "=> index_add( %ld, \"%s\" )\n", e->e_id,
	    e->e_dn, 0 );

	/*
	 * dn index entry - make it look like an attribute so it works
	 * with index_change_values() call
	 */

	bv.bv_val = ch_strdup( e->e_ndn );
	bv.bv_len = strlen( bv.bv_val );
	bvals[0] = &bv;
	bvals[1] = NULL;

	/* add the dn to the indexes */
	{
		AttributeType *dn = at_find( "*dn" );
		index_change_values( be, dn, bvals, e->e_id, __INDEX_ADD_OP );
	}

	free( bv.bv_val );

	/* add each attribute to the indexes */
	for ( ap = e->e_attrs; ap != NULL; ap = ap->a_next ) {

		AttributeType *at;
		at = at_find( ap->a_type );
		if ( !at )
			continue;
		index_change_values( be, at, ap->a_vals, e->e_id,
				     __INDEX_ADD_OP );
	}

	Debug( LDAP_DEBUG_TRACE, "<= index_add( %ld, \"%s\" ) 0\n", e->e_id,
	    e->e_ndn, 0 );
	return( 0 );
}

int
index_add_mods(
    Backend	*be,
    LDAPModList	*ml,
    ID		id
)
{
	int	rc;

	for ( ; ml != NULL; ml = ml->ml_next ) {
		LDAPMod *mod = &ml->ml_mod;
		AttributeType *at;
		at = at_find( mod->mod_type );
		if ( !at )
			continue;
		switch ( mod->mod_op & ~LDAP_MOD_BVALUES ) {
		case LDAP_MOD_REPLACE:
			/* XXX: Delete old index data==>problem when this 
			 * gets called we lost values already!
			 */
		case LDAP_MOD_ADD:
			rc = index_change_values( be,
					       at,
					       mod->mod_bvalues,
					       id,
					       __INDEX_ADD_OP);
			break;
		case LDAP_MOD_DELETE:
			rc =  index_change_values( be,
						   at,
						   mod->mod_bvalues,
						   id,
						   __INDEX_DELETE_OP );
			break;
 		case LDAP_MOD_SOFTADD:	/* SOFTADD means index was there */
			rc = 0;
			break;
		}

		if ( rc != 0 ) {
			return( rc );
		}
	}

	return( 0 );
}

ID_BLOCK *
index_read(
    Backend		*be,
    AttributeType	*at,
    MatchingRule	*mr,
    char		*val
)
{
	struct dbcache	*db;
	Datum   	key;
	ID_BLOCK		*idl;
	char		prefix;
	char		*realval, *tmpval;
	char		buf[BUFSIZ];
	char		*at_cn;
	int		i;

	ldbm_datum_init( key );

	at_cn = at_canonical_name( at );

	prefix = index2prefix( at, mr );
	Debug( LDAP_DEBUG_TRACE, "=> index_read( \"%s\" \"%c\" \"%s\" )\n",
	    at_cn, prefix, val );

	if ( prefix == UNKNOWN_PREFIX ) {
		idl =  idl_allids( be );
		Debug( LDAP_DEBUG_TRACE,
		    "<= index_read %ld candidates (allids - not indexed)\n",
		    idl ? ID_BLOCK_NIDS(idl) : 0, 0, 0 );
		return( idl );
	}

	if ( (db = ldbm_cache_open( be, at_cn, LDBM_SUFFIX, LDBM_WRCREAT ))
	    == NULL ) {
		Debug( LDAP_DEBUG_ANY,
		    "<= index_read NULL (could not open %s%s)\n", at_cn,
		    LDBM_SUFFIX, 0 );
		return( NULL );
	}

	realval = val;
	tmpval = NULL;
	if ( prefix != UNKNOWN_PREFIX ) {
              unsigned int	len = strlen( val );

              if ( (len + 2) < sizeof(buf) ) {
			realval = buf;
		} else {
			/* value + prefix + null */
			tmpval = (char *) ch_malloc( len + 2 );
			realval = tmpval;
		}
              realval[0] = prefix;
              strcpy( &realval[1], val );
	}

	key.dptr = realval;
	key.dsize = strlen( realval ) + 1;

	idl = idl_fetch( be, db, key );
	if ( tmpval != NULL ) {
              free( tmpval );
	}

	ldbm_cache_close( be, db );

	Debug( LDAP_DEBUG_TRACE, "<= index_read %ld candidates\n",
	       idl ? ID_BLOCK_NIDS(idl) : 0, 0, 0 );
	return( idl );
}

/* Add or remove stuff from index files */

static int
change_value(
    Backend		*be,
    struct dbcache	*db,
    AttributeType	*at,
    MatchingRule	*mr,
    char		*val,
    ID			id,
    int			(*idl_func)(Backend *, struct dbcache *, Datum, ID)
)
{
	int	rc;
	Datum   key;
	char	*tmpval = NULL;
	char	*realval = val;
	char	buf[BUFSIZ];

	char	prefix = index2prefix( at, mr );

	ldbm_datum_init( key );

	Debug( LDAP_DEBUG_TRACE,
	       "=> change_value( \"%c%s\", op=%s )\n",
	       prefix, val, (idl_func == idl_insert_key ? "ADD":"DELETE") );

	if ( prefix != UNKNOWN_PREFIX ) {
              unsigned int     len = strlen( val );

              if ( (len + 2) < sizeof(buf) ) {
			realval = buf;
	      } else {
			/* value + prefix + null */
			tmpval = (char *) ch_malloc( len + 2 );
			realval = tmpval;
	      }
              realval[0] = prefix;
              strcpy( &realval[1], val );
	}

	key.dptr = realval;
	key.dsize = strlen( realval ) + 1;

	rc = idl_func( be, db, key, id );

	if ( tmpval != NULL ) {
		free( tmpval );
	}

	ldap_pvt_thread_yield();

	Debug( LDAP_DEBUG_TRACE, "<= change_value %d\n", rc, 0, 0 );

	return( rc );

}/* static int change_value() */


int
index_change_values(
    Backend		*be,
    AttributeType	*at,
    struct berval	**vals,
    ID			id,
    unsigned int	op
)
{
	char		*val, *p, *code, *w;
	unsigned	i, j, len, ind;
	MatchingRule	**indexes;
	char		buf[SUBLEN + 1];
	char		vbuf[BUFSIZ];
	char		*bigbuf;
	struct dbcache	*db;

	int		(*idl_funct)(Backend *,
				    struct dbcache *,
				    Datum, ID);
	char		*at_cn;	/* Attribute canonical name */
	int		mode;

	at_cn = at_canonical_name( at );

	Debug( LDAP_DEBUG_TRACE,
	       "=> index_change_values( \"%s\", %ld, op=%s )\n", 
	       at_cn, id, ((op == __INDEX_ADD_OP) ? "ADD" : "DELETE" ) );

	
	if (op == __INDEX_ADD_OP) {

	    /* Add values */

	    idl_funct =  idl_insert_key;
	    mode = LDBM_WRCREAT;

	} else {

	    /* Delete values */

	    idl_funct = idl_delete_key;
	    mode = LDBM_WRITER;

	}

	attr_indexes( be->be_private, at, &indexes );

	if ( indexes == NULL ) {
		return( 0 );
	}

	if ( (db = ldbm_cache_open( be, at_cn, LDBM_SUFFIX, mode ))
	     == NULL ) {
		Debug( LDAP_DEBUG_ANY,
		       "<= index_change_values (couldn't open(%s%s),md=%s)\n",
		       at_cn,
		       LDBM_SUFFIX,
		       ((mode==LDBM_WRCREAT)?"LDBM_WRCREAT":"LDBM_WRITER") );
		return( -1 );
	}

	for ( ind = 0; indexes[ind] != NULL; ind++ ) {
		struct berval	**ivals;

		Debug( LDAP_DEBUG_TRACE,
		       "index_change_values syntax %s matching rule %s\n",
		       syn_canonical_name( at->sat_syntax ),
		       mr_canonical_name( indexes[ind] ), 0 );

		if ( indexes[ind]->smr_cindex( vals, &ivals ) == 0 ) {

			for ( i = 0; ivals[i] != NULL; i++ ) {

				change_value( be, db, at, indexes[ind],
					      ivals[i]->bv_val, id, idl_funct );
			}
			ber_bvecfree( ivals );

		}
	}
	ldbm_cache_close( be, db );

	return( 0 );

}/* int index_change_values() */

static int
index2prefix( AttributeType *at, MatchingRule *mr )
{
	int	prefix;
	MatchingRule *tmr;
	char	buf[512];

	if ( mr == at->sat_equality ) {
		prefix = EQ_PREFIX;
	} else if ( mr == at->sat_substr ) {
		prefix = SUB_PREFIX;
	} else if ( mr == ( tmr = mr_find( "*approx" ) ) ) {
		prefix = APPROX_PREFIX;
	} else {
		prefix = UNKNOWN_PREFIX;
	}

	return( prefix );
}
