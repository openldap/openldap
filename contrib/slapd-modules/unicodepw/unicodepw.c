/* unicodepw.c - acceppt only password change for MS Active Directory */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2021 The OpenLDAP Foundation.
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
 /* ACKNOLEDGEDMENTS:
 * This work was initially developed by Ingo Voss (ingo.voss@gmail.com)
 * for inclusion in OpenLDAP Software.
 */

#include "portable.h"

#ifdef SLAPD_OVER_UNICODEPW

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "lber.h"


typedef struct	unicodepw_conf {
	struct	berval	attr;
	struct	berval	userbase;
	int	log_activity;
	int	subtree_search;
} unicodepw_conf;


static int 
unicodepw_mod( Operation *op, SlapReply *rs ) {

	slap_overinst		*on = (slap_overinst *) op->o_bd->bd_info;
	unicodepw_conf		*u_conf = (unicodepw_conf *) on->on_bi.bi_private;
	int			deny = 0;
	int			i = 1;
	Modifications		*m;

	/* from Config for container, where users are located */
	struct berval user_base_ndn;
	dnNormalize( 0, NULL, NULL, &u_conf->userbase, &user_base_ndn, op->o_tmpmemctx );

	/* get parent DN from user, who is changed */
	struct berval user_parent_ndn;
	dnParent( &op->o_req_ndn, &user_parent_ndn );

	if ( u_conf->log_activity == 1 ) {
    		/* logging config */
		Debug( LDAP_DEBUG_STATS,
			"conn=%lu op=%lu unicodepw: INFO => configured UsersBase nDN => <%s>\n",
			op->o_connid, op->o_opid, user_base_ndn.bv_val );
		Debug( LDAP_DEBUG_STATS,
			"conn=%lu op=%lu unicodepw: INFO => configured pwattr => <%s>\n",
			op->o_connid, op->o_opid, u_conf->attr.bv_val );
		Debug( LDAP_DEBUG_STATS,
			"conn=%lu op=%lu unicodepw: INFO => configured logactivity => <%d>\n",
			op->o_connid, op->o_opid, u_conf->log_activity );
		Debug( LDAP_DEBUG_STATS,
			"conn=%lu op=%lu unicodepw: INFO => configured subtree => <%d>\n",
			op->o_connid, op->o_opid, u_conf->subtree_search );
		Debug( LDAP_DEBUG_STATS,
			"conn=%lu op=%lu unicodepw: INFO => User, who is changed  <%s>\n",
			op->o_connid, op->o_opid, op->o_req_ndn.bv_val );
		/* logging User and parent DN */
		Debug( LDAP_DEBUG_STATS, 
			"conn=%lu op=%lu unicodepw: INFO => Parent DN from user, who is changed => <%s>\n",
			op->o_connid, op->o_opid, user_parent_ndn.bv_val );
	}

	/* check if user is in configured UserBase */
	if ( u_conf->subtree_search == 1 ) {
		int found = 0;
		while (!BER_BVISEMPTY( &user_parent_ndn )) {
			if ( u_conf->log_activity == 1 ) {
				Debug( LDAP_DEBUG_STATS,
					"conn=%lu op=%lu unicodepw: DEBUG => <%s>\n",
					op->o_connid, op->o_opid, user_parent_ndn.bv_val );
			}
			if ( strcmp( user_parent_ndn.bv_val, user_base_ndn.bv_val ) == 0 ) {
				found = 1;
				if ( u_conf->log_activity == 1 ) {
					Debug( LDAP_DEBUG_STATS,
						"conn=%lu op=%lu unicodepw: INFO: Found User under => <%s>\n",
						op->o_connid, op->o_opid, user_parent_ndn.bv_val );
				}
				break;
			}
			dnParent( &user_parent_ndn , &user_parent_ndn );
		}
		if ( found == 0 ) {
			if ( u_conf->log_activity == 1 ) {
				Debug( LDAP_DEBUG_STATS,
					"conn=%lu op=%lu unicodepw: DENY => UserBase from <%s> is not in configured UserBase\n",
					op->o_connid, op->o_opid, op->o_req_dn.bv_val );
			}
			deny = 1;
		}
	} else {
		if ( strcmp( user_parent_ndn.bv_val, user_base_ndn.bv_val ) != 0 ) {
			if ( u_conf->log_activity == 1 ) {
				Debug( LDAP_DEBUG_STATS,
					"conn=%lu op=%lu unicodepw: DENY => UserBase from <%s> is not in configured UserBase\n",
					op->o_connid, op->o_opid, op->o_req_dn.bv_val );
			}
			deny = 1;
		}
	}


	/* load Modifications and process */
	if ( !(m = op->orm_modlist) ) {
		op->o_bd->bd_info = (BackendInfo *) on->on_info;
		send_ldap_error( op, rs, LDAP_INVALID_SYNTAX, "unique_modify() got null op.orm_modlist" );
		return rs->sr_err;
	}

	/* successful load */
	for ( ; m; m = m->sml_next ) {
		/* only attribute UnicodePwd allowed! */
		if ( strcasecmp( m->sml_type.bv_val, u_conf->attr.bv_val ) != 0 ) {
			if ( u_conf->log_activity == 1 ) {
				Debug( LDAP_DEBUG_STATS,
					"conn=%lu op=%lu unicodepw: DENY => Attribute in Modification (%s) is not the configured pwattr!\n",
					op->o_connid, op->o_opid,
					m->sml_op == LDAP_MOD_ADD ? "ADD" : (m->sml_op == LDAP_MOD_DELETE ? "DEL" : "other") );
			}
			deny = 1;
		} else {
			if ( u_conf->log_activity == 1 ) {
				Debug( LDAP_DEBUG_STATS,
					"conn=%lu op=%lu unicodepw: OK => Attribute in Modification (%s) is the configured pwattr!\n",
					op->o_connid, op->o_opid,
					m->sml_op == LDAP_MOD_ADD ? "ADD" : (m->sml_op == LDAP_MOD_DELETE ? "DEL" : "other") );
			}
		}

		/* only DEL and ADD allowed */
		if ( m->sml_op == LDAP_MOD_DELETE || m->sml_op == LDAP_MOD_ADD ) {
			if ( m->sml_op == LDAP_MOD_DELETE && i != 1 ) {
				if ( u_conf->log_activity == 1 ) {
					Debug( LDAP_DEBUG_STATS,
						"conn=%lu op=%lu unicodepw: DENY => Modification DEL not in first place!%s\n",
						op->o_connid, op->o_opid, "" );
				}
				deny = 1;
			} else if ( m->sml_op == LDAP_MOD_ADD && i != 2 ) {
				if ( u_conf->log_activity == 1 ) {
					Debug( LDAP_DEBUG_STATS,
						"conn=%lu op=%lu unicodepw: DENY => Modification ADD not in second place!%s\n",
						op->o_connid, op->o_opid, "" );
				}
				deny = 1;
			}
		} else {
			if ( u_conf->log_activity == 1 ) {
				Debug( LDAP_DEBUG_STATS,
					"conn=%lu op=%lu unicodepw: DENY => Modification not in ADD or DEL!%s\n",
					op->o_connid, op->o_opid, "" );
			}
			deny = 1;
		}
		i++;
	}

	if ( i != 3 ) {
		if ( u_conf->log_activity == 1 ) {
			Debug( LDAP_DEBUG_STATS,
				"conn=%lu op=%lu unicodepw: DENY => More or less than TWO modifications!%s\n",
				op->o_connid, op->o_opid, "" );
		}
		deny = 1;
	}

	if ( !deny ) {
		if ( u_conf->log_activity == 1 ) {
			Debug( LDAP_DEBUG_STATS,
				"conn=%lu op=%lu unicodepw: ACCEPT => UnicodePwd changing is permitted!%s\n",
				op->o_connid, op->o_opid, "" );
		}
		return SLAP_CB_CONTINUE;
	}

	op->o_bd->bd_info = (BackendInfo *)on->on_info;
	send_ldap_error( op, rs, LDAP_UNWILLING_TO_PERFORM, "operation not allowed by unicodepw!" );
	return 0;
}


static int 
unicodepw_config(
	BackendDB	*be,
	const char	*fname,
	int		lineno,
	int		argc,
	char		**argv )
{
	slap_overinst	*on = (slap_overinst *) be->bd_info;
	unicodepw_conf	*u_conf = (unicodepw_conf *) on->on_bi.bi_private;

	Debug( LDAP_DEBUG_CONFIG,
		"\tlline: %d,\t argv[1]: %s,\t argv[2]: %s\n",
		lineno, argv[1], argv[2] );

	if ( strcasecmp( argv[0], "unicodepw" ) == 0 ) {
		if ( argc != 3 ) {
			Debug( LDAP_DEBUG_ANY,
				"%s: line %d: "	"wrong configuration line, use: " "\"unicodepw <param> <value>\" line.%s\n",
				fname, lineno, "" );
			return  1;
		}
		Debug( LDAP_DEBUG_CONFIG,
			"unicodepw:  config => param: %s, value: %s%s\n",
			argv[1] ,argv[2], "" );
		if ( strcasecmp(argv[1], "pwattr" ) == 0 ) {
			if ( u_conf->attr.bv_val ) {
				/* if already defined! */
				ch_free( u_conf->attr.bv_val );
			}
			ber_str2bv( argv[ 2 ], 0, 1, &u_conf->attr );
		} else if ( strcasecmp(argv[1], "userbase" ) == 0 ) {
			if ( u_conf->userbase.bv_val ) {
				/* if already defined! */
				ch_free( u_conf->userbase.bv_val );
			}
			ber_str2bv( argv[ 2 ], 0, 1, &u_conf->userbase );
		} else if ( strcasecmp(argv[1], "logactivity" ) == 0 ) {
			if ( strcasecmp( argv[ 2 ], "yes" ) == 0 ) {
				u_conf->log_activity = 1;
			} else if ( strcasecmp( argv[ 2 ], "no" ) == 0 ) {
				u_conf->log_activity = 0;
			} else {
				Debug( LDAP_DEBUG_ANY,
					"%s: line %d: "	"wrong configuration line, use: " "\"unicodepw logactivity <yes|no>\" line.%s\n",
					fname, lineno, "" );
				return SLAP_CONF_UNKNOWN;
			}
		} else if ( strcasecmp(argv[1], "subtree" ) == 0 ) {
			if ( strcasecmp( argv[ 2 ], "yes" ) == 0 ) {
				u_conf->subtree_search = 1;
			} else if ( strcasecmp( argv[ 2 ], "no" ) == 0 ) {
				u_conf->subtree_search = 0;
			} else {
				Debug( LDAP_DEBUG_ANY,
					"%s: line %d: "	"wrong configuration line, use: " "\"unicodepw subtree <yes|no>\" line.%s\n",
					fname, lineno, "" );
				return SLAP_CONF_UNKNOWN;
			}
		} else {
			return SLAP_CONF_UNKNOWN;
		}
	} else {
		return SLAP_CONF_UNKNOWN;
	}
	return 0;
}

static int 
unicodepw_over_init( BackendDB *be )
{
	slap_overinst	*on = (slap_overinst *) be->bd_info;
	unicodepw_conf	*u_conf;

	u_conf = (unicodepw_conf *)ch_malloc( sizeof(unicodepw_conf) );
	memset( u_conf, 0, sizeof(unicodepw_conf) );
	on->on_bi.bi_private = u_conf;
	return 0;
}

static int 
unicodepw_destroy( BackendDB *be )
{
	slap_overinst	*on = (slap_overinst *) be->bd_info;
	unicodepw_conf	*u_conf = (unicodepw_conf *) on->on_bi.bi_private;

	if ( u_conf ) {
		ch_free ( u_conf );
	}
	return 0;
}

static slap_overinst unicodepw;

int
unicodepw_initialize( void ) {
	memset( &unicodepw, 0, sizeof( slap_overinst ) );

	unicodepw.on_bi.bi_type = "unicodepw";
	unicodepw.on_bi.bi_db_init = unicodepw_over_init;
	unicodepw.on_bi.bi_db_config = unicodepw_config;
	unicodepw.on_bi.bi_db_destroy = unicodepw_destroy;

	unicodepw.on_bi.bi_op_modify = unicodepw_mod;
	unicodepw.on_response = NULL /* unicodepw_response */;

	return overlay_register( &unicodepw );
}

#if SLAPD_OVER_UNICODEPW == SLAPD_MOD_DYNAMIC
int
init_module( int argc, char *argv[] ) {
	return unicodepw_initialize();
}
#endif /* SLAPD_OVER_UNICODEPW == SLAPD_MOD_DYNAMIC */

#endif /* defined(SLAPD_OVER_UNICODEPW) */
