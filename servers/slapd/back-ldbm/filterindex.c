/* filterindex.c - generate the list of candidate entries from a filter */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "back-ldbm.h"

static ID_BLOCK	*ava_candidates( Backend *be, Ava *ava, int type );
static ID_BLOCK	*presence_candidates( Backend *be, char *type );
static ID_BLOCK	*approx_candidates( Backend *be, Ava *ava );
static ID_BLOCK	*list_candidates( Backend *be, Filter *flist, int ftype );
static ID_BLOCK	*substring_candidates( Backend *be, Filter *f );
static ID_BLOCK	*extensible_candidates( Backend *be, Mra *mra );

ID_BLOCK *
index_candidates(
    Backend		*be,
    AttributeType	*at,
    MatchingRule	*mr,
    struct berval	*val
)
{
	struct berval	*vals[2];
	struct berval	**svals;
	int		i, j;
	ID_BLOCK	*idl, *idl1, *idl2, *tmp;

	/*
	 * First, decompose the value into its constituents.  If the
	 * matching rule does not know how to do it, then it is
	 * understood to be just one constituent and identical to our
	 * input.
	 */
	if ( mr->smr_skeys ) {
		mr->smr_skeys( val, &svals );
	} else {
		vals[0] = val;
		vals[1] = NULL;
		svals = vals;
	}

	idl = NULL;
	assert( mr->smr_sindex != NULL );
	/* Now take each piece and compute the indexing stems for it */
	for ( i = 0; svals[i]; i++ ) {
		struct berval	*isvals[2];
		struct berval	**ivals;

		isvals[0] = svals[i];
		isvals[1] = NULL;
		mr->smr_sindex( isvals, &ivals );
		idl1 = NULL;
		for ( j = 0; ivals[j]; j++ ) {
			idl2 = index_read( be, at, mr,
					  ivals[j]->bv_val );
			tmp = idl1;
			idl1 = idl_intersection( be, idl1, idl2 );
			idl_free( idl2 );
			idl_free( tmp );
		}
		tmp = idl;
		idl = idl_union( be, idl, idl1 );
		idl_free( idl1 );
		idl_free( tmp );
		ber_bvecfree( ivals );
	}

	if ( mr->smr_skeys ) {
		ber_bvecfree( svals );
	}
	return( idl );
}


ID_BLOCK *
filter_candidates(
    Backend	*be,
    Filter	*f
)
{
	ID_BLOCK	*result, *tmp1, *tmp2;

	Debug( LDAP_DEBUG_TRACE, "=> filter_candidates\n", 0, 0, 0 );

	result = NULL;
	switch ( f->f_choice ) {
	case LDAP_FILTER_EQUALITY:
		Debug( LDAP_DEBUG_FILTER, "\tEQUALITY\n", 0, 0, 0 );
		result = ava_candidates( be, &f->f_ava, LDAP_FILTER_EQUALITY );
		break;

	case LDAP_FILTER_SUBSTRINGS:
		Debug( LDAP_DEBUG_FILTER, "\tSUBSTRINGS\n", 0, 0, 0 );
		result = substring_candidates( be, f );
		break;

	case LDAP_FILTER_GE:
		Debug( LDAP_DEBUG_FILTER, "\tGE\n", 0, 0, 0 );
		result = ava_candidates( be, &f->f_ava, LDAP_FILTER_GE );
		break;

	case LDAP_FILTER_LE:
		Debug( LDAP_DEBUG_FILTER, "\tLE\n", 0, 0, 0 );
		result = ava_candidates( be, &f->f_ava, LDAP_FILTER_LE );
		break;

	case LDAP_FILTER_PRESENT:
		Debug( LDAP_DEBUG_FILTER, "\tPRESENT\n", 0, 0, 0 );
		result = presence_candidates( be, f->f_type );
		break;

	case LDAP_FILTER_APPROX:
		Debug( LDAP_DEBUG_FILTER, "\tAPPROX\n", 0, 0, 0 );
		result = approx_candidates( be, &f->f_ava );
		break;

	case LDAP_FILTER_EXTENDED:
		Debug( LDAP_DEBUG_FILTER, "\tEXTENSIBLE\n", 0, 0, 0 );
		result = extensible_candidates( be, &f->f_mra );
		break;

	case LDAP_FILTER_AND:
		Debug( LDAP_DEBUG_FILTER, "\tAND\n", 0, 0, 0 );
		result = list_candidates( be, f->f_and, LDAP_FILTER_AND );
		break;

	case LDAP_FILTER_OR:
		Debug( LDAP_DEBUG_FILTER, "\tOR\n", 0, 0, 0 );
		result = list_candidates( be, f->f_or, LDAP_FILTER_OR );
		break;

	case LDAP_FILTER_NOT:
		Debug( LDAP_DEBUG_FILTER, "\tNOT\n", 0, 0, 0 );
		tmp1 = idl_allids( be );
		tmp2 = filter_candidates( be, f->f_not );
		result = idl_notin( be, tmp1, tmp2 );
		idl_free( tmp2 );
		idl_free( tmp1 );
		break;
	}

	Debug( LDAP_DEBUG_TRACE, "<= filter_candidates %ld\n",
	    result ? ID_BLOCK_NIDS(result) : 0, 0, 0 );
	return( result );
}

static ID_BLOCK *
ava_candidates(
    Backend	*be,
    Ava		*ava,
    int		type
)
{
	ID_BLOCK	*idl;
	AttributeType	*at;

	Debug( LDAP_DEBUG_TRACE, "=> ava_candidates 0x%x\n", type, 0, 0 );

	switch ( type ) {
	case LDAP_FILTER_EQUALITY:
		at = at_find( ava->ava_type );
		if ( at && at->sat_equality ) {
			idl = index_candidates( be, at, at->sat_equality,
					  &ava->ava_value );
		} else {
			idl = NULL;
		}
		break;

	case LDAP_FILTER_GE:
		idl = idl_allids( be );
		break;

	case LDAP_FILTER_LE:
		idl = idl_allids( be );
		break;
	}

	Debug( LDAP_DEBUG_TRACE, "<= ava_candidates %ld\n",
	    idl ? ID_BLOCK_NIDS(idl) : 0, 0, 0 );
	return( idl );
}

static ID_BLOCK *
presence_candidates(
    Backend	*be,
    char	*type
)
{
	ID_BLOCK	*idl;

	Debug( LDAP_DEBUG_TRACE, "=> presence_candidates\n", 0, 0, 0 );

	idl = index_read( be, at_find( type ), 0, "*" );

	Debug( LDAP_DEBUG_TRACE, "<= presence_candidates %ld\n",
	    idl ? ID_BLOCK_NIDS(idl) : 0, 0, 0 );
	return( idl );
}

static ID_BLOCK *
extensible_candidates(
    Backend	*be,
    Mra		*mra
)
{
	AttributeType	*at;
	MatchingRule	*mr;
	ID_BLOCK	*idl;

	Debug( LDAP_DEBUG_TRACE, "=> extensible_candidates\n", 0, 0, 0 );

	at = at_find( mra->mra_type );
	mr = mr_find( mra->mra_rule );
	idl = index_candidates( be, at, mr, &mra->mra_value );
	/* FIXME: what about mra->mra_dnattrs */

	Debug( LDAP_DEBUG_TRACE, "<= extensible_candidates %ld\n",
	    idl ? ID_BLOCK_NIDS(idl) : 0, 0, 0 );
	return( idl );
}

static ID_BLOCK *
approx_candidates(
    Backend	*be,
    Ava		*ava
)
{
	AttributeType	*at;
	ID_BLOCK	*idl;

	Debug( LDAP_DEBUG_TRACE, "=> approx_candidates\n", 0, 0, 0 );

	at = at_find( ava->ava_type );
	idl = index_candidates( be, at, global_mr_approx,
				&ava->ava_value );

	Debug( LDAP_DEBUG_TRACE, "<= approx_candidates %ld\n",
	    idl ? ID_BLOCK_NIDS(idl) : 0, 0, 0 );
	return( idl );
}

static ID_BLOCK *
list_candidates(
    Backend	*be,
    Filter	*flist,
    int		ftype
)
{
	ID_BLOCK	*idl, *tmp, *tmp2;
	Filter	*f;

	Debug( LDAP_DEBUG_TRACE, "=> list_candidates 0x%x\n", ftype, 0, 0 );

	idl = NULL;
	for ( f = flist; f != NULL; f = f->f_next ) {
		if ( (tmp = filter_candidates( be, f )) == NULL &&
		    ftype == LDAP_FILTER_AND ) {
				Debug( LDAP_DEBUG_TRACE,
				    "<= list_candidates NULL\n", 0, 0, 0 );
				idl_free( idl );
				return( NULL );
		}

		tmp2 = idl;
		if ( idl == NULL ) {
			idl = tmp;
		} else if ( ftype == LDAP_FILTER_AND ) {
			idl = idl_intersection( be, idl, tmp );
			idl_free( tmp );
			idl_free( tmp2 );
		} else {
			idl = idl_union( be, idl, tmp );
			idl_free( tmp );
			idl_free( tmp2 );
		}
	}

	Debug( LDAP_DEBUG_TRACE, "<= list_candidates %ld\n",
	    idl ? ID_BLOCK_NIDS(idl) : 0, 0, 0 );
	return( idl );
}

static ID_BLOCK *
substring_candidates(
    Backend	*be,
    Filter	*f
)
{
	int	i;
	AttributeType	*at;
	ID_BLOCK	*idl;
	struct berval	*substrings;

	Debug( LDAP_DEBUG_TRACE, "=> substring_candidates\n", 0, 0, 0 );

	at = at_find( f->f_sub_type );
	substrings = make_substrs_berval( &f->f_sub );
	idl = index_candidates( be, at, global_mr_approx,
				substrings );

	ber_bvfree( substrings );

	Debug( LDAP_DEBUG_TRACE, "<= substring_candidates %ld\n",
	    idl ? ID_BLOCK_NIDS(idl) : 0, 0, 0 );
	return( idl );
}
