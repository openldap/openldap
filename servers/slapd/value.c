/* value.c - routines for dealing with values */

#include "portable.h"

#include <stdio.h>

#include <ac/ctype.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include <sys/stat.h>

#include "slap.h"

int
value_add_fast( 
    struct berval	***vals,
    struct berval	**addvals,
    int			nvals,
    int			naddvals,
    int			*maxvals
)
{
	int	need, i, j;

	if ( *maxvals == 0 ) {
		*maxvals = 1;
	}
	need = nvals + naddvals + 1;
	while ( *maxvals < need ) {
		*maxvals *= 2;
		*vals = (struct berval **) ch_realloc( (char *) *vals,
		    *maxvals * sizeof(struct berval *) );
	}

	for ( i = 0, j = 0; i < naddvals; i++, j++ ) {
		if ( addvals[i]->bv_len > 0 ) {
			(*vals)[nvals + j] = ber_bvdup( addvals[i] );
		}
	}
	(*vals)[nvals + j] = NULL;

	return( 0 );
}

int
value_add( 
    struct berval	***vals,
    struct berval	**addvals
)
{
	int	n, nn, i, j;

	for ( nn = 0; addvals != NULL && addvals[nn] != NULL; nn++ )
		;	/* NULL */

	if ( *vals == NULL ) {
		*vals = (struct berval **) ch_malloc( (nn + 1)
		    * sizeof(struct berval *) );
		n = 0;
	} else {
		for ( n = 0; (*vals)[n] != NULL; n++ )
			;	/* NULL */
		*vals = (struct berval **) ch_realloc( (char *) *vals,
		    (n + nn + 1) * sizeof(struct berval *) );
	}

	for ( i = 0, j = 0; i < nn; i++ ) {
		if ( addvals[i]->bv_len > 0 ) {
			(*vals)[n + j++] = ber_bvdup( addvals[i] );
		}
	}
	(*vals)[n + j] = NULL;

	return( 0 );
}

void
value_normalize(
    struct berval	*val,
    struct berval	**nval,
    MatchingRule	*mr
)
{
	if ( mr && mr->smr_normalize ) {
		mr->smr_normalize( val, nval );
	} else {
		*nval = ber_bvdup( val );
	}
}

int
value_cmp(
    struct berval	*v1,
    struct berval	*v2,
    MatchingRule	*mr
)
{
	int		rc;

	if ( mr && mr->smr_compare ) {
		rc = mr_smr_compare( v1, v2 );
	} else {
		rc = 0;
	}

	return( rc );
}

int
value_find(
    struct berval	**vals,
    struct berval	*v,
    MatchingRule	*mr
)
{
	int	i;

	for ( i = 0; vals[i] != NULL; i++ ) {
		if ( value_cmp( vals[i], v, mr ) == 0 ) {
			return( 0 );
		}
	}

	return( 1 );
}
