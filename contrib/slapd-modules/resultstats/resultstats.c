/* resultstats.c - gather result code statistics per operation */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2005-2026 The OpenLDAP Foundation.
 * Copyright 2025 Symas Corp. All Rights Reserved.
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
/* ACKNOWLEDGEMENTS:
 * This work was developed by Nadezhda Ivanova for Symas Corp. for inclusion
 * in OpenLDAP Software.
 */

#include "portable.h"

#ifdef SLAPD_OVER_RESULTSTATS

#include <stdio.h>

#include <ac/unistd.h>
#include <ac/string.h>
#include <ac/ctype.h>
#include <ac/socket.h>

#include "slap.h"
#include "slap-config.h"
#include "lutil.h"
#include "back-monitor/back-monitor.h"

static slap_overinst		resultstats;

#define STATS_SIZE LDAP_OTHER+2

static struct resultstats_ops_t {
	struct berval	rdn;
	struct berval	nrdn;
} resultstats_op[] = {
	{ BER_BVC( "cn=Bind" ),		BER_BVC( "cn=bind" ), },
	{ BER_BVC( "cn=Unbind" ),	BER_BVC( "cn=unbind" ), },
	{ BER_BVC( "cn=Search" ),	BER_BVC( "cn=search" ), },
	{ BER_BVC( "cn=Compare" ),	BER_BVC( "cn=compare" ), },
	{ BER_BVC( "cn=Modify" ),	BER_BVC( "cn=modify" ), },
	{ BER_BVC( "cn=Modrdn" ),	BER_BVC( "cn=modrdn" ), },
	{ BER_BVC( "cn=Add" ),		BER_BVC( "cn=add" ), },
	{ BER_BVC( "cn=Delete" ),	BER_BVC( "cn=delete" ), },
	{ BER_BVC( "cn=Abandon" ),	BER_BVC( "cn=abandon" ), },
	{ BER_BVC( "cn=Extended" ),	BER_BVC( "cn=extended" ), },
	{ BER_BVNULL,			BER_BVNULL }
};

typedef struct resultstats_t {
	uintptr_t stats[ SLAP_OP_LAST ][ STATS_SIZE ];
	struct berval		monitor_ndn;
	struct berval       rslt_rdn;
	struct berval       mss_ndn;
	monitor_subsys_t    *mss;
} resultstats_t;


static int resultstats_monitor_db_init( void );
static int resultstats_monitor_db_open( BackendDB *be );
static int resultstats_monitor_db_close( BackendDB *be );
//static int resultstats_monitor_db_destroy( BackendDB *be );

static AttributeDescription	*ad_olmResultCodeStat;
static ObjectClass		*oc_olmResultStatOperation;
static ObjectClass		*oc_monitorContainer;


static struct {
	char		*desc;
	ObjectClass	**ocp;
}		s_oc[] = {
	{ "( OLcfgCtOc:12.1 "
	  "NAME ( 'olmResultStatOperation' ) "
	  "SUP monitoredObject "
	  "MAY ( "
	  "olmResultCodeStat"
	  " ) )",
	  &oc_olmResultStatOperation },

	{ NULL }
};

static struct {
	char	*desc;
	AttributeDescription **adp;
} s_ad[] = {
	{ "( OLcfgCtAt:12.1 "
	  "NAME 'olmResultCodeStat' "
	  "DESC 'Number of times an LDAP code result has been sent for this operation type' "
	  "EQUALITY integerMatch "
	  "ORDERING integerOrderingMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )",
	  &ad_olmResultCodeStat },

	{ NULL }
};

static AttributeDescription *ads[ STATS_SIZE ];

static int
resultstats_monitor_ops_update(
	Operation	*op,
	SlapReply	*rs,
	Entry		*e,
	void		*priv )
{
	uintptr_t *stats = (uintptr_t *)priv;
	int i, rc;
	for ( i = 0; i < STATS_SIZE; i++ ) {
		Attribute *a;
		AttributeDescription *ad = NULL;
		char name_buf[ BUFSIZ ];
		char val_buf[ BUFSIZ ];
		const char *text;
		struct berval bv;
		unsigned long int value = __atomic_load_n( &stats[i], __ATOMIC_RELAXED );
		if ( value == 0 ) {
			continue;
		}

		/* TODO This should be optimised by maintaining the attributes in the entry sorted by code,
		   and avoid searching through the full list every time */
		ad = ads[i];
		if ( ad == NULL ) {
			if ( i <= LDAP_OTHER )
				snprintf( name_buf, sizeof( name_buf ), "olmResultCodeStat;x-resultcode-%d", i );
			else
				snprintf( name_buf, sizeof( name_buf ), "olmResultCodeStat;x-resultcode-more");

			rc = slap_str2ad( name_buf, &ad, &text );
			if ( rc != 0 ) {
				Debug( LDAP_DEBUG_ANY, "resultstats_monitor_ops_update: "
					   "unable to find attribute description %s \n ", name_buf );
				return 0;
			}
		}
		ads[i] = ad;
		bv.bv_val = val_buf;
		bv.bv_len = snprintf( val_buf, sizeof( val_buf ), "%lu", value );
		a = attr_find( e->e_attrs, ad );
		if ( a != NULL ) {
			ber_bvreplace( &a->a_vals[ 0 ], &bv );
		} else {
			attr_merge_one( e, ad, &bv, NULL );
		}
	}
	return SLAP_CB_CONTINUE;
}

static int
resultstats_monitor_initialize( void )
{
	static int	resultstats_monitor_initialized = 0;
	int code, i;

	if ( backend_info( "monitor" ) == NULL ) {
		Debug( LDAP_DEBUG_ANY,
			   "resultstats_monitor_initialize: resultstats overlay requires cn=monitor");
		return -1;
	}

	if ( resultstats_monitor_initialized++ ) {
		return 0;
	}

	ad_define_option( "x-resultcode-", __FILE__, __LINE__ );
	for ( i = 0; s_ad[i].desc != NULL; i++ ) {
		code = register_at( s_ad[i].desc, s_ad[i].adp, 0 );
		if ( code ) {
			Debug( LDAP_DEBUG_ANY,
				   "resultstats_monitor_initialize: register_at #%d failed\n", i );
			return code;
		}
	}

	for ( i = 0; s_oc[i].desc != NULL; i++ ) {
		code = register_oc( s_oc[i].desc, s_oc[i].ocp, 0 );
		if ( code ) {
			Debug( LDAP_DEBUG_ANY,
				   "resultstat_monitor_initialize: register_oc #%d failed\n", i );
			return code;
		}
	}

	oc_monitorContainer = oc_find( "monitorContainer" );
	if ( !oc_monitorContainer ) {
		Debug( LDAP_DEBUG_ANY,
			   "resultstats_monitor_initialize: failed to find objectClass (monitorContainer)\n" );
		return 5;
	}
	return 0;
}

static int
resultstats_monitor_register_entries( monitor_extra_t	*mbe,
									  resultstats_t	*rslt,
									  monitor_subsys_t	*ms,
									  Entry *parent )
{
	int i, rc;
	Entry *e;
	for ( i = 0; i < SLAP_OP_LAST; i++ ) {
		monitor_callback_t *cb;

		e = mbe->entry_stub( &ms->mss_dn, &ms->mss_ndn,
							 &resultstats_op[i].rdn,
							 oc_olmResultStatOperation, NULL, NULL );
		if ( e == NULL ) {
			Debug( LDAP_DEBUG_ANY,
				   "resultstats_monitor_register_entries: "
				   "unable to create entry \"%s,%s\"\n",
				   resultstats_op[i].rdn.bv_val,
				   rslt->monitor_ndn.bv_val );
			return( -1 );
		}
		cb = ch_calloc( sizeof( monitor_callback_t ), 1 );
		cb->mc_update = resultstats_monitor_ops_update;
		cb->mc_private = (void *)rslt->stats[i];

		rc = mbe->register_entry( e, cb, ms, 0 );
		if ( rc != LDAP_SUCCESS ) {
			Debug( LDAP_DEBUG_ANY,
				   "resultstats_monitor_register_entries: "
				   "unable to register entry \"%s\" for monitoring\n",
				   e->e_name.bv_val );
			ch_free( cb );
			entry_free( e );
			return rc;
		}
		entry_free( e );
	}
	return 0;
}

static int
resultstats_monitor_db_init( void )
{
	return resultstats_monitor_initialize();
}

static int
resultstats_monitor_mss_init(
	BackendDB		*be,
	monitor_subsys_t	*ms )
{
	slap_overinst	*on = (slap_overinst *)ms->mss_private;
	resultstats_t	*rslt = (resultstats_t *)on->on_bi.bi_private;
	monitor_extra_t	*mbe;

	Entry	*parent;
	int		rc;

	assert( be != NULL );
	mbe = (monitor_extra_t *) be->bd_info->bi_extra;

	parent = mbe->entry_stub( &rslt->monitor_ndn, &rslt->monitor_ndn,
							  &rslt->rslt_rdn, oc_monitorContainer, NULL, NULL );
	if ( parent == NULL ) {
		Debug( LDAP_DEBUG_ANY,
			   "resultstats_monitor_mss_init: "
			   "unable to create entry \"%s,%s\"\n",
			   rslt->rslt_rdn.bv_val,
			   rslt->monitor_ndn.bv_val );
		return( -1 );
	}

	ber_dupbv( &ms->mss_dn, &parent->e_name );
	ber_dupbv( &ms->mss_ndn, &parent->e_nname );
	ber_dupbv( &ms->mss_rdn, &rslt->rslt_rdn );

	rc = mbe->register_entry( parent, NULL, ms, MONITOR_F_PERSISTENT_CH );
	if ( rc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_ANY,
			   "resultstats_monitor_mss_init: "
			   "unable to register entry \"%s,%s\"\n",
			   ms->mss_rdn.bv_val,
			   ms->mss_ndn.bv_val );
		entry_free( parent );
		return ( -1 );
	}

	rc = resultstats_monitor_register_entries( mbe, rslt, ms, parent );

	entry_free( parent );

	return rc;
}

static int
resultstats_monitor_mss_destroy (
	BackendDB		*be,
	monitor_subsys_t	*ms )
{
	if ( ms->mss_ndn.bv_len > 0 ) {
		ch_free( ms->mss_ndn.bv_val );
	}
	if ( ms->mss_dn.bv_len > 0 ) {
		ch_free( ms->mss_dn.bv_val );
	}
	return 0;
}

static int
resultstats_monitor_db_open( BackendDB *be )
{
	slap_overinst	*on = (slap_overinst *)be->bd_info;
	resultstats_t	*rslt = (resultstats_t *)on->on_bi.bi_private;
	BackendInfo		*bi;
	int rc = 0;
	monitor_extra_t		*mbe;
	Entry * parent;

	/* check if monitor is configured and usable */
	bi = backend_info( "monitor" );
	if ( !bi || !bi->bi_extra ) {
		return -1;
	}
	mbe = bi->bi_extra;

	/* don't bother if monitor is not configured */
	if ( !mbe->is_configured() ) {
		Debug( LDAP_DEBUG_CONFIG, "resultstats_monitor_db_open: "
			   "monitoring disabled; "
			   "configure monitor database to enable\n" );
		return -1;
	}

	BER_BVZERO( &rslt->monitor_ndn );
	if ( ( rc = mbe->register_overlay( be, on, &rslt->monitor_ndn ) ) != 0 ) {
		return rc;
	}
	parent = mbe->entry_stub( &rslt->monitor_ndn, &rslt->monitor_ndn,
							  &rslt->rslt_rdn, oc_monitorContainer, NULL, NULL );
	if ( parent == NULL ) {
		Debug( LDAP_DEBUG_ANY,
			   "resultstats_monitor_mss_init: "
			   "unable to create entry \"%s,%s\"\n",
			   rslt->rslt_rdn.bv_val,
			   rslt->monitor_ndn.bv_val );
		return( -1 );
	}

	ber_dupbv( &rslt->mss_ndn, &parent->e_nname );
	/* Check if the subsystem already exsists. This can happen if the overlay
	   has previously added and removed. For now it is safe to assume
	   that the dn will be unique, as databases cannot be removed.
	   This should be re-done when we enable database removal and fix monitor
	   so that subsystems can be unregistered */
	rslt->mss = monitor_back_get_subsys_by_dn( &rslt->mss_ndn, 0 );
	if ( rslt->mss == NULL ) {
		/* this will leak at monitor_db_destroy, but it can't be helped */
		rslt->mss = (monitor_subsys_t *)ch_calloc( 1, sizeof( monitor_subsys_t ) );
		rslt->mss->mss_name = "Result code statistics";
		rslt->mss->mss_flags = MONITOR_F_PERSISTENT_CH;
		rslt->mss->mss_open = resultstats_monitor_mss_init;
		rslt->mss->mss_destroy = resultstats_monitor_mss_destroy;
		rslt->mss->mss_private = on;

		if ( mbe->register_subsys_late( rslt->mss ) ) {
			Debug( LDAP_DEBUG_ANY,
				   "resultsats_monitor_db_open: "
				   "failed to register result statistics subsystem" );
			return -1;
		}
	} else {
		rslt->mss->mss_private = on;
		rc = mbe->register_entry( parent, NULL, rslt->mss, MONITOR_F_PERSISTENT_CH );
		if ( rc != LDAP_SUCCESS ) {
			Debug( LDAP_DEBUG_ANY,
				   "resultstats_monitor_db_open: "
				   "unable to register entry \"%s,%s\"\n",
				   rslt->mss->mss_rdn.bv_val,
				   rslt->mss->mss_ndn.bv_val );
			entry_free( parent );
			return ( -1 );
		}
		rc = resultstats_monitor_register_entries( mbe, rslt, rslt->mss, parent );
	}
	entry_free( parent );

	return rc;
}

static int
resultstats_monitor_db_close( BackendDB *be )
{

	slap_overinst *on = (slap_overinst *)be->bd_info;
	resultstats_t	*rslt = (resultstats_t *)on->on_bi.bi_private;
	monitor_extra_t *mbe;
	BackendInfo		*mi = backend_info( "monitor" );
	
	if ( mi && mi->bi_extra ) {
		int i;
		mbe = mi->bi_extra;
		for ( i = 0; i < SLAP_OP_LAST; i++ ) {
			struct berval  bv;
			char        buf[ BACKMONITOR_BUFSIZE ];
			bv.bv_len = snprintf( buf, sizeof( buf ), "%s,%s",
								  resultstats_op[i].nrdn.bv_val,
								  rslt->mss_ndn.bv_val );
			bv.bv_val = buf;
			mbe->unregister_entry( &bv );

		}
		mbe->unregister_entry( &rslt->mss_ndn );
	}
	if ( !BER_BVISNULL(&rslt->mss_ndn) ) {
		ch_free( rslt->mss_ndn.bv_val );
		BER_BVZERO( &rslt->mss_ndn );
	}
	/* Make sure this does not point to a non-existent overlay instance */
	rslt->mss->mss_private = NULL;
	return 0;
}

static int
resultstats_response( Operation *op, SlapReply *rs )
{
	slap_overinst	*on = (slap_overinst *)op->o_bd->bd_info;
	resultstats_t	*rslt = (resultstats_t *)on->on_bi.bi_private;
	int code, opidx;

	/* skip internal ops */
	if ( rs->sr_type != REP_RESULT || op->o_do_not_cache ) {
		return SLAP_CB_CONTINUE;
	}

	code = slap_map_api2result( rs );
	if ( code > LDAP_OTHER )
		code = LDAP_OTHER+1;

	opidx = slap_req2op( op->o_tag );
	__atomic_fetch_add( &(rslt->stats[opidx][code]), 1, __ATOMIC_RELAXED );

	return SLAP_CB_CONTINUE;
}

static int
resultstats_db_init( BackendDB *be, ConfigReply *cr )
{
	slap_overinst	*on = (slap_overinst *)be->bd_info;
	resultstats_t	*rslt;

	rslt = (resultstats_t *)ch_calloc( 1, sizeof( resultstats_t ) );

	on->on_bi.bi_private = (void *)rslt;
	ber_str2bv( "cn=Result Stats", 0, 1,
				&rslt->rslt_rdn );
	return resultstats_monitor_db_init();
}

static int
resultstats_db_open( BackendDB *be, ConfigReply *cr )
{
	return resultstats_monitor_db_open( be );
}

static int
resultstats_db_destroy( BackendDB *be, ConfigReply *cr )
{
	slap_overinst	*on = (slap_overinst *)be->bd_info;
	resultstats_t	*rslt = (resultstats_t *)on->on_bi.bi_private;
	if ( rslt->rslt_rdn.bv_len > 0 ) {
		ch_free( rslt->rslt_rdn.bv_val );
	}
	ch_free( rslt );
	return 0;
}

static int
resultstats_db_close( BackendDB *be, ConfigReply *cr )
{
	return resultstats_monitor_db_close( be );
}

int
resultstats_initialize( void )
{
	int		code;

	resultstats.on_bi.bi_type = "resultstats";
	resultstats.on_bi.bi_db_init = resultstats_db_init;
	resultstats.on_bi.bi_db_open = resultstats_db_open;
	resultstats.on_bi.bi_db_destroy = resultstats_db_destroy;
	resultstats.on_bi.bi_db_close = resultstats_db_close;
	resultstats.on_bi.bi_flags = SLAPO_BFLAG_SINGLE;
	resultstats.on_response = resultstats_response;

	code = resultstats_monitor_initialize();
	if ( code != 0)
		return code;

	return overlay_register( &resultstats );
}

#if SLAPD_OVER_RESULTSTATS == SLAPD_MOD_DYNAMIC
int
init_module( int argc, char *argv[] )
{
	return resultstats_initialize();
}
#endif /* SLAPD_OVER_RESULTSTATS == SLAPD_MOD_DYNAMIC */

#endif /* SLAPD_OVER_RESULTSTATS */
