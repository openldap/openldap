/* restrictop.c - routines to parse and check extop/control policy */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2026 The OpenLDAP Foundation.
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
/* Portions Copyright (c) 1995 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/regex.h>
#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "lber_pvt.h"
#include "lutil.h"
#include "slap-config.h"

static void
restrictop_by_free( RestrictOpBy *by )
{
	RestrictOpBy *next;

	for ( ; by; by = next ) {
		next = by->rb_next;
		Access *a = &by->rb_a;

		if ( !BER_BVISNULL( &by->rb_drop_oid ) ) {
			ch_free( by->rb_drop_oid.bv_val );
		}
		access_free( a );
	}
}

void
restrictop_free( RestrictOp *r )
{
	RestrictOp *next;
	int i;

	for ( ; r; r = next ) {
		next = r->r_next;

		ch_free( r->r_exop_oid.bv_val );
		ch_free( r->r_exop_orig.bv_val );
		for ( i=0; i < r->r_ncontrols; i++ ) {
			ch_free( r->r_control_orig[i].bv_val );
		}
		ch_free( r->r_control_orig );
		ch_free( r->r_control_cids );
		restrictop_by_free( r->r_by );
		ch_free( r );
	}
}

static int
parse_restrictop_by(
	struct config_args_s *c,
	RestrictOpBy **byp,
	char **argv,
	int argc )
{
	int i = 0;
	RestrictOpBy *by, **nextp = byp;
	char *left, *right;

	while ( i < argc ) {
		if ( strcasecmp( argv[i], "by" ) != 0 ) {
			snprintf( c->cr_msg, sizeof( c->cr_msg ),
				"unexpected keyword to start the \"by\" clause: %s", argv[i] );
			goto fail;
		}

		if ( ++i == argc ) {
			snprintf( c->cr_msg, sizeof( c->cr_msg ),
				"premature EOL: expecting <who>");
			goto fail;
		}

		by = *nextp = ch_calloc( 1, sizeof(RestrictOpBy) );
		nextp = &by->rb_next;

		if ( acl_parse_who( c, &by->rb_a, argv, argc, &i, &left ) ) {
			goto fail;
		}

		if ( by->rb_a.a_dn.a_style == ACL_STYLE_EXPAND ||
				by->rb_a.a_dn.a_expand ||
				by->rb_a.a_realdn.a_style == ACL_STYLE_EXPAND ||
				by->rb_a.a_realdn.a_expand ) {
			snprintf( c->cr_msg, sizeof( c->cr_msg ),
				"expand patterns not supported in restrictop." );
			goto fail;
		}

		if ( by->rb_a.a_dn.a_style == ACL_STYLE_SELF ||
				by->rb_a.a_realdn.a_style == ACL_STYLE_SELF ) {
			snprintf( c->cr_msg, sizeof( c->cr_msg ),
				"self patterns not supported in restrictop." );
			goto fail;
		}

		if ( by->rb_a.a_dn_at || by->rb_a.a_realdn_at ) {
			snprintf( c->cr_msg, sizeof( c->cr_msg ),
				"dnattr clauses not supported in restrictop." );
			goto fail;
		}

		if ( !BER_BVISNULL( &by->rb_a.a_set_pat ) ) {
			snprintf( c->cr_msg, sizeof( c->cr_msg ),
				"set clauses not yet supported in restrictop." );
			goto fail;
		}

#ifdef SLAP_DYNACL
		if ( by->rb_a.a_dynacl ) {
			snprintf( c->cr_msg, sizeof( c->cr_msg ),
				"dynacl clauses not yet supported in restrictop." );
			goto fail;
		}
#endif /* SLAP_DYNACL */

		if ( strcasecmp( left, "break" ) == 0 ) {
			by->rb_action = SLAP_RESTRICT_OP_MISSING;
			by->rb_a.a_type = ACL_BREAK;
			i++;
			continue;
		} else if ( strcasecmp( left, "allow" ) == 0 ) {
			by->rb_action = SLAP_RESTRICT_OP_ALLOW;
		} else if ( strcasecmp( left, "reject" ) == 0 ) {
			by->rb_action = SLAP_RESTRICT_OP_REJECT;
		} else if ( strcasecmp( left, "drop" ) == 0 ) {
			char *oid;

			by->rb_action = SLAP_RESTRICT_OP_DROP;

			if ( ++i == argc ) {
				snprintf( c->cr_msg, sizeof( c->cr_msg ),
					"premature EOL: expecting control=<oid>");
				goto fail;
			}

			left = argv[i];
			right = strchr( left, '=' );
			if ( !right ) {
				snprintf( c->cr_msg, sizeof( c->cr_msg ),
					"missing \"=\" in \"%s\" in drop clause", left );
				goto fail;
			}
			*right++ = '\0';

			oid = oidm_find( right );
			if ( !oid ) {
				snprintf( c->cr_msg, sizeof(c->cr_msg),
					"bad control OID \"%s\"", right );
				goto fail;
			}

			if ( slap_find_control_id( oid, &by->rb_drop_cid ) != LDAP_SUCCESS ) {
				if ( oid != right ) {
					ch_free( oid );
				}
				snprintf( c->cr_msg, sizeof(c->cr_msg),
					"unknown control \"%s\"", right );
				goto fail;
			}
			if ( oid != right ) {
				ch_free( oid );
			}

			ber_str2bv( right, 0, 1, &by->rb_drop_oid );
		} else {
			snprintf( c->cr_msg, sizeof( c->cr_msg ),
				"unrecognised keyword in \"by\" clause: %s", left );
			goto fail;
		}

		if ( ++i == argc ) {
			by->rb_a.a_type = ACL_STOP;
			continue;
		}

		left = argv[i];
		if ( strcasecmp( left, "by" ) == 0 ) {
			by->rb_a.a_type = ACL_STOP;
			continue;
		}

		if ( strcasecmp( left, "stop" ) == 0 ) {
			by->rb_a.a_type = ACL_STOP;
		} else if ( strcasecmp( left, "continue" ) == 0 ) {
			by->rb_a.a_type = ACL_CONTINUE;
		} else if ( strcasecmp( left, "break" ) == 0 ) {
			by->rb_a.a_type = ACL_BREAK;
		} else {
			snprintf( c->cr_msg, sizeof( c->cr_msg ),
				"unrecognised keyword in \"by\" clause: %s", left );
			goto fail;
		}
		i++;
	}

	return 0;

fail:
	Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg );
	return 1;
}

/*
 * restrictop <op>+ [control=<oid>]*
 *   [by <who>+ <allow|reject|drop control=<oid>> [stop|continue|break]]+
 * op -> all | <optype> | read | write | extended[=<oid>]
 *
 * We can validate controls are known but we can't check extop OIDs.
 */
int
parse_restrictop(
	struct config_args_s *c,
	int		pos )
{
	int		i;
	char		*left, *right, *style, *oid;
	struct berval	bv;
	RestrictOp *rule, **rulep;
	int rc, cid;

	rule = ch_calloc( 1, sizeof(RestrictOp) );

	for ( i = 1; i < c->argc; i++ ) {
		left = c->argv[i];
		if ( strcasecmp( c->argv[i], "by" ) == 0 ) {
			break;
		}

		if ( strncasecmp( left, "control=",
					STRLENOF("control=") ) == 0 ) {
			right = left + STRLENOF("control=");
			oid = oidm_find( right );
			if ( !oid ) {
				snprintf( c->cr_msg, sizeof(c->cr_msg),
					"bad control OID \"%s\"", right );
				goto fail;
			}

			if ( slap_find_control_id( oid, &cid ) != LDAP_SUCCESS ) {
				if ( oid != right ) {
					ch_free( oid );
				}
				snprintf( c->cr_msg, sizeof(c->cr_msg),
					"unknown control \"%s\"", right );
				goto fail;
			}

			rule->r_ncontrols++;
			rule->r_control_cids = ch_realloc( rule->r_control_cids,
				rule->r_ncontrols * sizeof(int) );
			rule->r_control_cids[rule->r_ncontrols - 1] = cid;

			ber_str2bv( right, 0, 1, &bv );
			ber_bvarray_add( &rule->r_control_orig, &bv );

			if ( oid != right ) {
				ch_free( oid );
			}
		} else {
			right = strchr( left, '=' );
			if ( right && strncasecmp( left, "extended",
						STRLENOF("extended") ) == 0 )
			{
				if ( rule->r_ops & SLAP_RESTRICT_OP_EXTENDED ) {
					snprintf( c->cr_msg, sizeof(c->cr_msg),
						"duplicate operation type in rule \"%s\"", c->line );
					goto fail;
				}

				rule->r_ops |= SLAP_RESTRICT_OP_EXTENDED;

				*right++ = '\0';
				oid = oidm_find( right );
				if ( !oid ) {
					snprintf( c->cr_msg, sizeof(c->cr_msg),
						"bad extop OID \"%s\"", right );
					goto fail;
				}

				ber_str2bv( oid, 0, oid == right, &rule->r_exop_oid );
				ber_str2bv( right, 0, 1, &rule->r_exop_orig );
			} else {
				int j = verb_to_mask( left, slap_restrictable_ops );
				slap_mask_t opmask = slap_restrictable_ops[j].mask;

				opmask &= SLAP_RESTRICT_OP_MASK;
				if ( !opmask ) {
					snprintf( c->cr_msg, sizeof(c->cr_msg),
						"unknown operation \"%s\"", left );
					goto fail;
				}

				if ( opmask & rule->r_ops ) {
					snprintf( c->cr_msg, sizeof(c->cr_msg),
						"duplicate or overlapping operation type in rule \"%s\"",
						c->line );
					goto fail;
				}
				rule->r_ops |= opmask;
			}
		}
	}

	if ( !rule->r_ops ) {
		snprintf( c->cr_msg, sizeof(c->cr_msg),
				"rule missing operation \"%s\"", c->line );
		goto fail;
	}

	if ( parse_restrictop_by( c, &rule->r_by, c->argv + i, c->argc - i ) ) {
		goto fail;
	}

	if ( !rule->r_by ) {
		snprintf( c->cr_msg, sizeof(c->cr_msg),
			"restrictop rule has no \"by\" clause \"%s\"", c->line );
		goto fail;
	}

	rulep = &c->be->be_restrictop_rules;
	for ( i=0; i != pos && *rulep; rulep = &(*rulep)->r_next, i++ )
		/* empty */;
	rule->r_next = *rulep;
	*rulep = rule;

	return 0;

fail:
	Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg );
	restrictop_free( rule );
	return 1;
}

int
restrictop_apply( Operation *op, RestrictOp *r )
{
	slap_restrict_action_t decision = SLAP_RESTRICT_OP_MISSING;
	Entry e = { .e_name = BER_BVNULL, .e_nname = BER_BVNULL };
	slap_op_t optype = slap_req2op( op->o_tag );
	int i, j;

	if ( LogTest( LDAP_DEBUG_ACL ) ) {
		if ( op->o_tag == LDAP_REQ_EXTENDED ) {
			Debug( LDAP_DEBUG_ACL, "%s restrictop: "
				"permission to process extended operation \"%s\","
				"by \"%s\" requested\n",
				op->o_log_prefix, op->ore_reqoid.bv_val, op->o_dn.bv_val );
		} else {
			struct berval bv = BER_BVC("unknown");
			enum_to_verb( slap_ops, optype, &bv );
			Debug( LDAP_DEBUG_ACL, "%s restrictop: "
				"permission to process %s by \"%s\" requested\n",
				op->o_log_prefix, bv.bv_val,
				op->o_dn.bv_val ? op->o_dn.bv_val : "(anonymous)" );
		}
	}

	/* grant database root access */
	if ( be_isroot( op ) ) {
		Debug( LDAP_DEBUG_ACL, "%s restrictop: root access granted\n",
			op->o_log_prefix );
		return 0;
	}

	for ( i=0; r; r = r->r_next, i++ ) {
		RestrictOpBy *by;

		if ( r->r_ops ) {
			if ( !(SLAP_OP2RESTRICT(optype) & r->r_ops) ) {
				continue;
			}

			if ( optype == SLAP_OP_EXTENDED &&
					!BER_BVISNULL( &r->r_exop_oid ) &&
					ber_bvcmp( &r->r_exop_oid, &op->ore_reqoid ) != 0 ) {
				continue;
			}
		}

		if ( r->r_ncontrols ) {
			int match = 1;
			for ( j=0; j < r->r_ncontrols; j++ ) {
				int cid = r->r_control_cids[j];
				Debug( LDAP_DEBUG_ACL, "%s RestrictOp[%d]: "
						"check r_control_cids[%d] %s\n",
						op->o_log_prefix, i, j, r->r_control_orig[j].bv_val );
				if ( cid >= 0 && cid < SLAP_MAX_CIDS &&
						_SCM(op->o_ctrlflag[cid]) <= SLAP_CONTROL_IGNORED )
				{
					match = 0;
					break;
				}
			}
			Debug( LDAP_DEBUG_ACL, "%s RestrictOp[%d]: controls %smatch\n",
					op->o_log_prefix, i, match ? "" : "do not " );
			if ( !match ) continue;
		}

		for ( by = r->r_by, j=0; by; by = by->rb_next, j++ ) {
			if ( acl_check_who( op, &e, NULL, NULL, &by->rb_a, NULL, 0 ) ) {
				Debug( LDAP_DEBUG_ACL, "%s RestrictOpBy[%d][%d]: "
						"<who> was not a match\n",
						op->o_log_prefix, i, j );
				continue;
			}

			if ( by->rb_action == SLAP_RESTRICT_OP_ALLOW ) {
				decision = SLAP_RESTRICT_OP_ALLOW;
				goto done;
			} else if ( by->rb_action == SLAP_RESTRICT_OP_DROP ) {
				int cid = by->rb_drop_cid;
				/* Allow and drop specified control if present, but if
				 * critical, reject instead, keeping control intact.
				 *
				 * FIXME: This makes the semantics much more powerful (if used
				 * with break/continue), but is it good powerful or just
				 * confusing?
				 */
				if ( cid >= 0 && cid < SLAP_MAX_CIDS &&
						_SCM(op->o_ctrlflag[cid]) > SLAP_CONTROL_IGNORED )
				{
					if ( _SCM(op->o_ctrlflag[cid]) == SLAP_CONTROL_CRITICAL ) {
						decision = SLAP_RESTRICT_OP_REJECT;

						Debug( LDAP_DEBUG_ACL, "%s RestrictOpBy[%d][%d]: "
								"control %s critical, rejecting\n",
								op->o_log_prefix, i, j, by->rb_drop_oid.bv_val );
						goto done;
					} else {
						op->o_ctrlflag[cid] = SLAP_CONTROL_IGNORED;
						decision = SLAP_RESTRICT_OP_ALLOW;

						Debug( LDAP_DEBUG_ACL, "%s RestrictOpBy[%d][%d]: "
								"control %s dropped\n",
								op->o_log_prefix, i, j, by->rb_drop_oid.bv_val );
					}
				}
			} else if ( by->rb_action != SLAP_RESTRICT_OP_MISSING ) {
				/* "reject" or unknown action */
				decision = SLAP_RESTRICT_OP_REJECT;
				goto done;
			}

			if ( LogTest( LDAP_DEBUG_ACL ) ) {
				char *control = by->rb_a.a_type == ACL_CONTINUE ? "continue" :
						by->rb_a.a_type == ACL_BREAK ? "break" : "stop";
				if ( by->rb_action != SLAP_RESTRICT_OP_MISSING ) {
					Debug( LDAP_DEBUG_ACL, "%s RestrictOpBy[%d][%d]: "
							"applying %s %s\n",
							op->o_log_prefix, i, j,
							decision == SLAP_RESTRICT_OP_ALLOW ?
								"allow" : "reject", control );
				} else {
					Debug( LDAP_DEBUG_ACL, "%s RestrictOpBy[%d][%d]: "
							"applying %s\n",
							op->o_log_prefix, i, j, control );
				}
			}
			if ( by->rb_a.a_type != ACL_CONTINUE ) {
				break;
			}
		}

		if ( !by || by->rb_a.a_type != ACL_BREAK ) {
			/*
			 * In the ACL world, "continue" on the last rule falls into the
			 * implicit "by * +0 stop". Retain this semantics.
			 */
			Debug( LDAP_DEBUG_ACL, "%s RestrictOp[%d]: "
				"applying %s stop\n",
				op->o_log_prefix, i, by ? "a" : "implicit" );
			break;
		}
	}

done:
	Debug( LDAP_DEBUG_ACL, "%s restrictop: %s\n",
		op->o_log_prefix,
		decision == SLAP_RESTRICT_OP_ALLOW ? "permitted" : "rejected" );
	return decision != SLAP_RESTRICT_OP_ALLOW;
}
