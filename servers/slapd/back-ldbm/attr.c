/* attr.c - backend routines for dealing with attributes */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "back-ldbm.h"

static char **default_indexes = NULL;

static char *all_basic_indexes[] = {
	"pres",
	"eq",
	"approx",
	"sub",
	NULL
};

static int
ainfo_type_cmp(
    char		*type,
    struct attrinfo	*a
)
{
	return( strcasecmp( type, a->ai_type ) );
}

static int
ainfo_cmp(
    struct attrinfo	*a,
    struct attrinfo	*b
)
{
	return( strcasecmp( a->ai_type, b->ai_type ) );
}

/*
 * Called when a duplicate "index" line is encountered.
 *
 * returns 1 => original from init code, indexmask updated
 *	   2 => original not from init code, warn the user
 */

static int
ainfo_dup(
    struct attrinfo	*a,
    struct attrinfo	*b
)
{
	/*
	 * if the duplicate definition is because we initialized the attr,
	 * just add what came from the config file. otherwise, complain.
	 */
	if ( a->ai_predef ) {
		int	i_old, i_add;

		for ( i_add = 0; b->ai_indexes[i_add]; i_add++ ) {
			for ( i_old = 0; a->ai_indexes[i_old]; i_old++ ) {
				if ( a->ai_indexes[i_old] ==
				     b->ai_indexes[i_add] ) {
					break;
				}
			}
			if ( a->ai_indexes[i_old] == NULL ) {
				/* Was not there, add it */
				a->ai_indexes = ch_realloc( a->ai_indexes,
					(i_old+1) * sizeof( MatchingRule * ) );
				a->ai_indexes[i_old] = b->ai_indexes[i_add];
				a->ai_indexes[i_old+1] = NULL;
			}
		}

		return( 1 );
	}

	return( 2 );
}

void
attr_indexes(
    struct ldbminfo	*li,
    AttributeType	*at,
    MatchingRule	***indexes
)
{
	struct attrinfo	*a;
	char		*at_cn;

	at_cn = at_canonical_name( at );
	*indexes = NULL;
	if ( (a = (struct attrinfo *) avl_find( li->li_attrs, at_cn,
	    (AVL_CMP) ainfo_type_cmp )) == NULL ) {
		/*
		 * ARGGHH!!  FIXME
		 * we cannot do this!!!
		 * We would need a mutex to update the backend li_attrs!!
		 * If we build the list on the fly, then we have the
		 * problem on who is going to free it.  It seems we always
		 * have to return a new array and the caller has to free
		 * it.  Always.  C'est dommage...
		 */
		int	i, j, nind;
		MatchingRule	*mr;

		for ( nind = 0; default_indexes[nind]; nind++ )
			;
		a = (struct attrinfo *) ch_malloc( sizeof(struct attrinfo) );
		a->ai_type = ch_strdup( at_cn );
		a->ai_indexes =
			ch_calloc( nind + 1, sizeof( MatchingRule * ) );
		j = 0;
		for ( i = 0; default_indexes[i]; i++ ) {
			if ( strncasecmp( default_indexes[i],
					  "pres", 4 ) == 0 ) {
				a->ai_indexes[j++] = global_mr_presence;
			} else if ( strncasecmp( default_indexes[i],
						 "eq", 2 ) == 0 ) {
				if ( at->sat_equality ) {
					a->ai_indexes[j++] =
						at->sat_equality;
				}
			} else if ( strncasecmp( default_indexes[i],
						 "approx", 6 ) == 0 ) {
				a->ai_indexes[j++] = global_mr_approx;
			} else if ( strncasecmp( default_indexes[i],
						 "sub", 3 ) == 0 ) {
				if ( at->sat_substr ) {
					a->ai_indexes[j++] =
						at->sat_substr;
				}
			} else if ( strncasecmp( default_indexes[i],
						 "none", 4 ) == 0 ) {
				/* FIXME: Sheesh */
				j = 0;
				a->ai_indexes[j] = NULL;
			} else if ( ( mr = mr_find( default_indexes[i] ) ) !=
				    NULL ) {
				a->ai_indexes[j++] = mr;
			}
		}
		a->ai_predef = 0;
		switch (avl_insert( &li->li_attrs, (caddr_t) a,
			(AVL_CMP) ainfo_cmp, (AVL_DUP) ainfo_dup ))
		{
		case 1:		/* duplicate - updating init version */
		case 2:		/* user duplicate - ignore and warn */
			/* FIXME: syslog something here, something wrong
			   is going on */
			free( a->ai_type );
			free( a->ai_indexes );
			free( (char *) a );
			break;

		default:;	/* inserted ok */
			/* FALL */
		}
	}
	*indexes = a->ai_indexes;
}

static void
default_index_config(
    char		*fname,
    int			lineno,
    char		**indexes
)
{
	int	i, j;

	for ( i = 0; indexes[i]; i++ )
		;
	default_indexes = ch_calloc( i, sizeof( char * ) );

	j = 0;
	for ( i = 0; indexes[i]; i++ ) {
		if ( strncasecmp( indexes[j], "pres", 4 ) == 0 ||
		     strncasecmp( indexes[j], "eq", 2 ) == 0 ||
		     strncasecmp( indexes[j], "approx", 6 ) == 0 ||
		     strncasecmp( indexes[j], "sub", 3 ) == 0 ||
		     strncasecmp( indexes[j], "none", 4 ) == 0 ||
		     mr_find( indexes[j] ) != NULL ) {
			default_indexes[j++] = ch_strdup( indexes[i] );
		} else {
			fprintf( stderr,
			"%s: line %d: unknown index type \"%s\" (ignored)\n",
				 fname, lineno, indexes[j] );
			fprintf( stderr,
	"valid index types are \"pres\", \"eq\", \"approx\", \"sub\" or <matchingrule>\n" );
		}
	}
	default_indexes[j] = NULL;
}

void
attr_index_config(
    struct ldbminfo	*li,
    char		*fname,
    int			lineno,
    int			argc,
    char		**argv,
    int			init
)
{
	int		i, j, k, nind;
	char		**attrs, **indexes;
	AttributeType	*at;
	MatchingRule	*mr;
	struct attrinfo	*a;

	indexes = NULL;
	attrs = str2charray( argv[0], "," );
	if ( argc > 1 ) {
		indexes = str2charray( argv[1], "," );
	} else {
		indexes = all_basic_indexes;
	}
	for ( nind = 0; indexes[nind]; nind++ )
		;
	for ( i = 0; attrs[i] != NULL; i++ ) {
		if ( !strcasecmp( attrs[i], "default" ) ) {
			default_index_config( fname, lineno, indexes );
			continue;
		}
		at = at_find( attrs[i] );
		if ( !at ) {
			fprintf( stderr,
			"%s: line %d: unknown attribute type \"%s\" (ignored)\n",
				 fname, lineno, attrs[i] );
			continue;
		}
		k = 0;
		a = (struct attrinfo *) ch_malloc( sizeof(struct attrinfo) );
		a->ai_type = ch_strdup( attrs[i] );
		a->ai_indexes =
			ch_calloc( nind + 1, sizeof( MatchingRule * ) );
		for ( j = 0; indexes[j] != NULL; j++ ) {
			if ( strncasecmp( indexes[j], "pres", 4 ) == 0 ) {
				a->ai_indexes[k++] = global_mr_presence;
			} else if ( strncasecmp( indexes[j], "eq", 2 ) == 0 ) {
				if ( at->sat_equality ) {
					a->ai_indexes[k++] =
						at->sat_equality;
				} else {
					fprintf( stderr,
"%s: line %d: attribute type \"%s\" does not have an equality matching rule\n",
						 fname, lineno, attrs[i] );

				}
			} else if ( strncasecmp( indexes[j], "approx",
						 6 ) == 0 ) {
				a->ai_indexes[k++] = global_mr_approx;
			} else if ( strncasecmp( indexes[j], "sub", 3 )
				    == 0 ) {
				if ( at->sat_substr ) {
					a->ai_indexes[k++] =
						at->sat_substr;
				} else {
					fprintf( stderr,
"%s: line %d: attribute type \"%s\" does not have a substrings matching rule\n",
						 fname, lineno, attrs[i] );

				}
			} else if ( strncasecmp( indexes[j], "none", 4 )
				    == 0 ) {
				if ( a->ai_indexes[0] ) {
					fprintf( stderr,
"%s: line %d: index type \"none\" cannot be combined with other types\n",
						 fname, lineno );
				}
				/* FIXME: Possible leak */
				k = 0;
				a->ai_indexes[k] = NULL;
			} else if ( ( mr = mr_find( indexes[j] ) ) != NULL ) {
				a->ai_indexes[k++] = mr;
			} else {
				fprintf( stderr,
			"%s: line %d: unknown index type \"%s\" (ignored)\n",
					 fname, lineno, indexes[j] );
				fprintf( stderr,
	"valid index types are \"pres\", \"eq\", \"approx\", \"sub\", or <matchingrule>\n" );
			}
		}
		a->ai_predef = init;

		switch (avl_insert( &li->li_attrs, (caddr_t) a,
			(AVL_CMP) ainfo_cmp, (AVL_DUP) ainfo_dup ))
		{
		case 1:		/* duplicate - updating init version */
			free( a->ai_type );
			free( a->ai_indexes );
			free( (char *) a );
			break;

		case 2:		/* user duplicate - ignore and warn */
			fprintf( stderr,
    "%s: line %d: duplicate index definition for attr \"%s\" (ignored)\n",
			    fname, lineno, a->ai_type );
			free( a->ai_type );
			free( a->ai_indexes );
			free( (char *) a );
			break;

		default:;	/* inserted ok */
			/* FALL */
		}
	}
	charray_free( attrs );
	if ( argc > 1 )
		charray_free( indexes );
}


#ifdef SLAP_CLEANUP

static void
ainfo_free( void *attr )
{
	struct attrinfo *ai = attr;
	free( ai->ai_type );
	free( ai );
}

void
attr_index_destroy( Avlnode *tree )
{
	avl_free( tree, ainfo_free );
}

#endif /* SLAP_CLEANUP */
