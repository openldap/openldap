/* dsaschema.c */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2004-2024 The OpenLDAP Foundation.
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

#include <portable.h>

#include <ac/string.h>
#include <ac/ctype.h>
#include <ac/signal.h>
#include <ac/errno.h>
#include <ac/stdlib.h>
#include <ac/ctype.h>
#include <ac/time.h>
#include <ac/unistd.h>

#include <stdio.h>

/*
 * Schema reader that allows us to define DSA schema (including
 * operational attributes and non-user object classes)
 *
 * A kludge, at best, and in order to avoid including slapd
 * headers we use fprintf() rather than slapd's native logging,
 * which may confuse users...
 *
 */

#include <ldap.h>
#include <ldap_schema.h>

#include <slap.h>
#include <slap-config.h>

#define ARGS_STEP 512

static char *fp_getline(FILE *fp, int *lineno);
static void fp_getline_init(int *lineno);
static int fp_parse_line(int lineno, char *line);
static char *strtok_quote( char *line, char *sep );

static char **cargv = NULL;
static int cargv_size = 0;
static int cargc = 0;
static char *strtok_quote_ptr;

int init_module(int argc, char *argv[]);

static ConfigDriver dsaschema_config_attribute;

static ConfigTable dsaschemacfg[] = {
	/* Only attribute loading is currently restricted in slapd, rest can be
	 * delegated to default */
	{ "", "attribute", 2, 0, 0,
		ARG_PAREN|ARG_MAGIC,
		&dsaschema_config_attribute,
		"( OLcfgGlAt:4 NAME 'olcAttributeTypes' "
			"DESC 'OpenLDAP attributeTypes' "
			"EQUALITY caseIgnoreMatch "
			"SUBSTR caseIgnoreSubstringsMatch "
			"SYNTAX OMsDirectoryString X-ORDERED 'VALUES' )",
				NULL, NULL },
	{ NULL, NULL, 0, 0, 0, ARG_IGNORED }
};

static ConfigLDAPadd dsaschema_ldadd;

static ConfigOCs dsaschemaocs[] = {
	{ "( OLcfgCtOc:11.1 "
	  "NAME 'olcDSASchemaConfig' "
	  "DESC 'DSA schema object' "
	  "SUP olcSchemaConfig STRUCTURAL )",
	  Cft_Schema, dsaschemacfg,
	  dsaschema_ldadd,
	},
	{ NULL, 0, NULL }
};

static int
dsaschema_config_attribute( ConfigArgs *c )
{
	if ( c->op == SLAP_CONFIG_EMIT ) {
		return 1;
	} else if ( c->op == LDAP_MOD_DELETE ) {
		return 1;
	}

	if ( register_at( c->line, NULL, 0 ) ) {
		snprintf( c->cr_msg, sizeof( c->cr_msg ),
				"<%s> attribute definition invalid",
				c->argv[0] );
		Debug( LDAP_DEBUG_ANY, "%s: %s\n", c->log, c->cr_msg );
		return 1;
	}
}

static int
dsaschema_ldadd( CfEntryInfo *p, Entry *e, ConfigArgs *ca )
{
	if ( p->ce_type != Cft_Schema )
		return LDAP_CONSTRAINT_VIOLATION;

	return LDAP_SUCCESS;
}


static int dsaschema_parse_cr(const char *fname, int lineno, char *line, char **argv)
{
	struct config_args_s c = { .line = line };

	if ( parse_cr( &c, NULL ) ) {
		Debug( LDAP_DEBUG_ANY, "dsaschema_parse_cr: "
				"ditcontentrule definition invalid at %s:%d\n",
				fname, lineno );
		return 1;
	}

	return 0;
}

static int dsaschema_read_config(const char *fname, int depth)
{
	FILE *fp;
	char *line, *savefname, *saveline = NULL;
	int savelineno, lineno;
	int rc;

	if (depth == 0) {
		cargv = ch_calloc(ARGS_STEP + 1, sizeof(*cargv));
		cargv_size = ARGS_STEP + 1;
	}

	fp = fopen(fname, "r");
	if (fp == NULL) {
		char ebuf[128];
		int saved_errno = errno;
		fprintf(stderr, "could not open config file \"%s\": %s (%d)\n",
			fname, AC_STRERROR_R(saved_errno, ebuf, sizeof(ebuf)), saved_errno);
		return 1;
	}
	fp_getline_init(&lineno);

	while ((line = fp_getline(fp, &lineno)) != NULL) {
		/* skip comments and blank lines */
		if (line[0] == '#' || line[0] == '\0') {
			continue;
		}

		saveline = ch_strdup(line);

		if (fp_parse_line(lineno, line) != 0) {
			rc = 1;
			break;
		}

		if (cargc < 1) {
			continue;
		}

		if (strcasecmp(cargv[0], "attributetype") == 0 ||
		    strcasecmp(cargv[0], "attribute") == 0) {
			if (cargc < 2) {
				fprintf(stderr, "%s: line %d: illegal attribute type format\n",
					fname, lineno);
				rc = 1;
				break;
			} else if (*cargv[1] == '(' /*')'*/) {
				char *p;
	
				p = strchr(saveline, '(' /*')'*/);
				rc = register_at(p, NULL, 0);
				if (rc != 0) {
					Debug( LDAP_DEBUG_ANY, "dsaschema_read_config: "
							"attribute definition invalid at %s:%d\n",
							fname, lineno );
					break;
				}
			} else {
				fprintf(stderr, "%s: line %d: old attribute type format not supported\n",
					fname, lineno);
			}
		} else if (strcasecmp(cargv[0], "ditcontentrule") == 0) {
			char *p;
			p = strchr(saveline, '(' /*')'*/);
			rc = dsaschema_parse_cr(fname, lineno, p, cargv);
			if (rc != 0)
				break;
		} else if (strcasecmp(cargv[0], "objectclass") == 0) {
			if (cargc < 2) {
				fprintf(stderr, "%s: line %d: illegal objectclass format\n",
					fname, lineno);
				rc = 1;
				break;
			} else if (*cargv[1] == '(' /*')'*/) {
				char *p;

				p = strchr(saveline, '(' /*')'*/);
				rc = register_oc(p, NULL, 0);
				if (rc != 0) {
					Debug( LDAP_DEBUG_ANY, "dsaschema_read_config: "
							"objectclass definition invalid at %s:%d\n",
							fname, lineno );
					break;
				}
			} else {
				fprintf(stderr, "%s: line %d: object class format not supported\n",
					fname, lineno);
			}
		} else if (strcasecmp(cargv[0], "include") == 0) {
			if (cargc < 2) {
				fprintf(stderr, "%s: line %d: missing file name in \"include <filename>\" line",
					fname, lineno);
				rc = 1;
				break;
			}
			savelineno = lineno;
			savefname = ch_strdup(cargv[1]);

			rc = dsaschema_read_config(savefname, depth + 1);
			ch_free(savefname);
			lineno = savelineno - 1;
			if (rc != 0) {
				break;
			}
		} else {
			fprintf(stderr, "%s: line %d: unknown directive \"%s\" (ignored)\n",
				fname, lineno, cargv[0]);
		}

		ch_free(saveline);
		saveline = NULL;
	}

	fclose(fp);

	if (depth == 0)
		ch_free(cargv);

	if (saveline != NULL)
		ch_free(saveline);

	return rc;
}

int init_module(int argc, char *argv[])
{
	int i;
	int rc;

	for (i = 0; i < argc; i++) {
		rc = dsaschema_read_config(argv[i], 0);
		if (rc != 0) {
			return rc;
		}
	}

	return config_register_schema( dsaschemacfg, dsaschemaocs );
}


static int
fp_parse_line(
    int		lineno,
    char	*line
)
{
	char *	token;

	cargc = 0;
	token = strtok_quote( line, " \t" );

	if ( strtok_quote_ptr ) {
		*strtok_quote_ptr = ' ';
	}

	if ( strtok_quote_ptr ) {
		*strtok_quote_ptr = '\0';
	}

	for ( ; token != NULL; token = strtok_quote( NULL, " \t" ) ) {
		if ( cargc == cargv_size - 1 ) {
			char **tmp;
			tmp = ch_realloc( cargv, (cargv_size + ARGS_STEP) *
					    sizeof(*cargv) );
			cargv = tmp;
			cargv_size += ARGS_STEP;
		}
		cargv[cargc++] = token;
	}
	cargv[cargc] = NULL;
	return 0;
}

static char *
strtok_quote( char *line, char *sep )
{
	int		inquote;
	char		*tmp;
	static char	*next;

	strtok_quote_ptr = NULL;
	if ( line != NULL ) {
		next = line;
	}
	while ( *next && strchr( sep, *next ) ) {
		next++;
	}

	if ( *next == '\0' ) {
		next = NULL;
		return( NULL );
	}
	tmp = next;

	for ( inquote = 0; *next; ) {
		switch ( *next ) {
		case '"':
			if ( inquote ) {
				inquote = 0;
			} else {
				inquote = 1;
			}
			AC_MEMCPY( next, next + 1, strlen( next + 1 ) + 1 );
			break;

		case '\\':
			if ( next[1] )
				AC_MEMCPY( next,
					    next + 1, strlen( next + 1 ) + 1 );
			next++;		/* dont parse the escaped character */
			break;

		default:
			if ( ! inquote ) {
				if ( strchr( sep, *next ) != NULL ) {
					strtok_quote_ptr = next;
					*next++ = '\0';
					return( tmp );
				}
			}
			next++;
			break;
		}
	}

	return( tmp );
}

static char	buf[BUFSIZ];
static char	*line;
static size_t lmax, lcur;

#define CATLINE( buf ) \
	do { \
		size_t len = strlen( buf ); \
		while ( lcur + len + 1 > lmax ) { \
			lmax += BUFSIZ; \
			line = (char *) ch_realloc( line, lmax ); \
		} \
		strcpy( line + lcur, buf ); \
		lcur += len; \
	} while( 0 )

static char *
fp_getline( FILE *fp, int *lineno )
{
	char		*p;

	lcur = 0;
	CATLINE( buf );
	(*lineno)++;

	/* hack attack - keeps us from having to keep a stack of bufs... */
	if ( strncasecmp( line, "include", 7 ) == 0 ) {
		buf[0] = '\0';
		return( line );
	}

	while ( fgets( buf, sizeof(buf), fp ) != NULL ) {
		/* trim off \r\n or \n */
		if ( (p = strchr( buf, '\n' )) != NULL ) {
			if( p > buf && p[-1] == '\r' ) --p;
			*p = '\0';
		}
		
		/* trim off trailing \ and append the next line */
		if ( line[ 0 ] != '\0' 
				&& (p = line + strlen( line ) - 1)[ 0 ] == '\\'
				&& p[ -1 ] != '\\' ) {
			p[ 0 ] = '\0';
			lcur--;

		} else {
			if ( ! isspace( (unsigned char) buf[0] ) ) {
				return( line );
			}

			/* change leading whitespace to a space */
			buf[0] = ' ';
		}

		CATLINE( buf );
		(*lineno)++;
	}
	buf[0] = '\0';

	return( line[0] ? line : NULL );
}

static void
fp_getline_init( int *lineno )
{
	*lineno = -1;
	buf[0] = '\0';
}

