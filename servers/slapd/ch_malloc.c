/* ch_malloc.c - malloc routines that test returns from malloc and friends */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"

void *
ch_malloc(
    ber_len_t	size
)
{
	void	*new;

	if ( (new = (void *) malloc( size )) == NULL ) {
		Debug( LDAP_DEBUG_ANY, "malloc of %lu bytes failed\n",
			(long) size, 0, 0 );
		exit( 1 );
	}

	return( new );
}

void *
ch_realloc(
    void		*block,
    ber_len_t	size
)
{
	void	*new;

	if ( block == NULL ) {
		return( ch_malloc( size ) );
	}

	if ( (new = (void *) realloc( block, size )) == NULL ) {
		Debug( LDAP_DEBUG_ANY, "realloc of %lu bytes failed\n",
			(long) size, 0, 0 );
		exit( 1 );
	}

	return( new );
}

void *
ch_calloc(
    ber_len_t	nelem,
    ber_len_t	size
)
{
	void	*new;

	if ( (new = (void *) calloc( nelem, size )) == NULL ) {
		Debug( LDAP_DEBUG_ANY, "calloc of %lu elems of %lu bytes failed\n",
		  (long) nelem, (long) size, 0 );
		exit( 1 );
	}

	return( new );
}

char *
ch_strdup(
    const char *string
)
{
	char	*new;

	if ( (new = strdup( string )) == NULL ) {
		Debug( LDAP_DEBUG_ANY, "strdup(%s) failed\n", string, 0, 0 );
		exit( 1 );
	}

	return( new );
}

