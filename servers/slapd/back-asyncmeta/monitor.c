/* monitor.c - monitor asyncmeta backend */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 * * Copyright 2016-2026 The OpenLDAP Foundation.
 * Portions Copyright 2016 Symas Corporation.
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
 * This work was developed by Symas Corporation
 * based on back-meta module for inclusion in OpenLDAP Software.
 * This work was sponsored by Ericsson. */


#include "portable.h"

#include <stdio.h>
#include <ac/string.h>
#include <ac/unistd.h>
#include <ac/stdlib.h>
#include <ac/errno.h>
#include <sys/stat.h>
#include "lutil.h"
#include "slap.h"
#include "../back-ldap/back-ldap.h"
#include "back-asyncmeta.h"

#include "slap-config.h"

static ObjectClass		*oc_olmAsyncmetaDatabase;
static ObjectClass		*oc_olmAsyncmetaTarget;
static ObjectClass		*oc_olmAsyncmetaConnectionGroup;
static ObjectClass		*oc_olmAsyncmetaTargetConnection;

static ObjectClass		*oc_monitorContainer;
static ObjectClass		*oc_monitorCounterObject;
/* Database Attributes */
static AttributeDescription	*ad_olmDbNextConnectionGroup; /*mi_next_conn*/
/* Target Attributes */
static AttributeDescription	*ad_olmTgtURIList; /* mt_uri */
static AttributeDescription	*ad_olmTgtQuarantined; /*mt_isquarantined*/
static AttributeDescription	*ad_olmTgtConnLastReset; /*msc_reset_time*/
static AttributeDescription	*ad_olmTgtTimeoutOps; /*mt_timeout_ops*/
/* Connection Group (a_metaconn_t) attributes */
static AttributeDescription	*ad_olmCGID;
static AttributeDescription	*ad_olmCGPendingOps;
/* individual target connections, one per each target per connection group (a_metasingleconn_t) */
static AttributeDescription	*ad_olmTargetConnLastUseTime; /* msc_time */
static AttributeDescription	*ad_olmTargetConnBoundTime; /* msc_binding_time */
static AttributeDescription	*ad_olmTargetConnResultTime; /* msc_result_time */
static AttributeDescription *ad_olmTargetConnEstablishedTime; /* msc_established_time */
static AttributeDescription	*ad_olmTargetConnResetTime; /* msc_reset_time */
static AttributeDescription	*ad_olmTargetConnFlags; /* msc_mscflags */
static AttributeDescription	*ad_olmTargetConnURI;
static AttributeDescription	*ad_olmTargetConnPeerAddress;


/* Corresponds to connection flags in back-ldap.h and back-asyncmeta.h */
static struct {
	unsigned	flag;
	struct berval	name;
}		s_flag[] = {
	{ LDAP_BACK_FCONN_ISBOUND,	BER_BVC( "bound" ) },
	{ LDAP_BACK_FCONN_ISANON,	BER_BVC( "anonymous" ) },
	{ LDAP_BACK_FCONN_ISPRIV,	BER_BVC( "privileged" ) },
	{ LDAP_BACK_FCONN_ISTLS,	BER_BVC( "TLS" ) },
	{ LDAP_BACK_FCONN_BINDING,	BER_BVC( "binding" ) },
	{ LDAP_BACK_FCONN_TAINTED,	BER_BVC( "tainted" ) },
	{ LDAP_BACK_FCONN_ABANDON,	BER_BVC( "abandon" ) },
	{ LDAP_BACK_FCONN_ISIDASR,	BER_BVC( "idassert" ) },
	{ LDAP_BACK_FCONN_CACHED,	BER_BVC( "cached" ) },
	{ META_BACK_FCONN_INITED,	BER_BVC( "initialized" ) },
	{ META_BACK_FCONN_CREATING,	BER_BVC( "creating" ) },
	{ META_BACK_FCONN_INVALID,	BER_BVC( "invalid" ) },
	{ META_BACK_FCONN_CLOSING,	BER_BVC( "closing" ) },
	{ 0 }
};


/*
 * NOTE: there's some confusion in monitor OID arc;
 * by now, let's consider:
 *
 * Subsystems monitor attributes	1.3.6.1.4.1.4203.666.1.55.0
 * Databases monitor attributes		1.3.6.1.4.1.4203.666.1.55.0.1
 * Asyncmeta database monitor attributes	1.3.6.1.4.1.4203.666.1.55.0.1.4
 *
 * Subsystems monitor objectclasses	1.3.6.1.4.1.4203.666.3.16.0
 * Databases monitor objectclasses	1.3.6.1.4.1.4203.666.3.16.0.1
 * Asyncmeta database monitor objectclasses	1.3.6.1.4.1.4203.666.3.16.0.1.4
 */

static struct {
	char			*name;
	char			*oid;
}		s_oid[] = {
	{ "olmAsyncmetaAttributes",			"olmDatabaseAttributes:4" },
	{ "olmAsyncmetaObjectClasses",		"olmDatabaseObjectClasses:4" },

	{ NULL }
};

static struct {
	char			*desc;
	AttributeDescription	**ad;
}		s_at[] = {
	{ "( olmAsyncmetaAttributes:1 "
	  "NAME ( 'olmDbNextConnectionGroup' ) "
	  "DESC 'ID of the next connection group to be used' "
	  "SUP monitorCounter "
	  "SINGLE-VALUE "
	  "NO-USER-MODIFICATION "
	  "USAGE dSAOperation )",
	  &ad_olmDbNextConnectionGroup },
	{ "( olmAsyncmetaAttributes:2 "
	  "NAME ( 'olmTgtURIList' ) "
	  "DESC 'List of URIs a target is serving' "
	  "SUP monitoredInfo	"
	  "NO-USER-MODIFICATION "
	  "USAGE dSAOperation )",
	  &ad_olmTgtURIList },
	{ "( olmAsyncmetaAttributes:3 "
	  "NAME ( 'olmTgtQuarantined' ) "
	  "DESC 'Is this target quanatined' "
	  "EQUALITY booleanMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 "
	  "SINGLE-VALUE "
	  "NO-USER-MODIFICATION "
	  "USAGE dSAOperation )",
	  &ad_olmTgtQuarantined },
	{ "( olmAsyncmetaAttributes:4 "
	  "NAME ( 'olmTgtTimeoutOps' ) "
	  "DESC 'Total number of timed out operations for this target since it was last quarantined' "
	  "SUP monitorCounter "
	  "SINGLE-VALUE "
	  "NO-USER-MODIFICATION "
	  "USAGE dSAOperation )",
	  &ad_olmTgtTimeoutOps },
	{ "( olmAsyncmetaAttributes:5 "
	  "NAME ( 'olmCGID' ) "
	  "DESC 'Connection Group ID' "
	  "SUP monitorCounter "
	  "SINGLE-VALUE "
	  "NO-USER-MODIFICATION "
	  "USAGE dSAOperation )",
	  &ad_olmCGID },
	{ "( olmAsyncmetaAttributes:6 "
	  "NAME ( 'olmCGPendingOps' ) "
	  "DESC 'Operations waiting for a result in this connection group queue' "
	  "SUP monitorCounter "
	  "SINGLE-VALUE "
	  "NO-USER-MODIFICATION "
	  "USAGE dSAOperation )",
	  &ad_olmCGPendingOps },
	{ "( olmAsyncmetaAttributes:7 "
	  "NAME ( 'olmTargetConnLastUseTime' ) "
	  "DESC 'Time the connection was last used to proxy an operation, 0 if the connection is not established' "
	  "EQUALITY integerMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 "
	  "SINGLE-VALUE "
	  "NO-USER-MODIFICATION "
	  "USAGE dSAOperation )",
	  &ad_olmTargetConnLastUseTime },
	{ "( olmAsyncmetaAttributes:8 "
	  "NAME ( 'olmTargetConnBoundTime' ) "
	  "DESC 'Time the connection was bound, 0 if the connection is not established' "
	  "EQUALITY integerMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 "
	  "SINGLE-VALUE "
	  "NO-USER-MODIFICATION "
	  "USAGE dSAOperation )",
	  &ad_olmTargetConnBoundTime },
	{ "( olmAsyncmetaAttributes:9 "
	  "NAME ( 'olmTargetConnResultTime' ) "
	  "DESC 'Last time a result was received, 0 if the connection is not established' "
	  "EQUALITY integerMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 "
	  "SINGLE-VALUE "
	  "NO-USER-MODIFICATION "
	  "USAGE dSAOperation )",
	  &ad_olmTargetConnResultTime },
	{ "( olmAsyncmetaAttributes:10 "
	  "NAME ( 'olmTargetConnFlags' ) "
	  "DESC 'Target Connection Flags' "
	  "SUP monitoredInfo "
	  "NO-USER-MODIFICATION "
	  "USAGE dSAOperation )",
	  &ad_olmTargetConnFlags },
	{ "( olmAsyncmetaAttributes:11 "
	  "NAME ( 'olmTargetConnURI' ) "
	  "DESC 'Target connection URI' "
	  "SUP monitorConnectionPeerAddress "
	  "NO-USER-MODIFICATION "
	  "USAGE dSAOperation )",
	  &ad_olmTargetConnURI },
	{ "( olmAsyncmetaAttributes:12 "
	  "NAME ( 'olmTargetConnPeerAddress' ) "
	  "DESC 'Target connection peer address' "
	  "SUP monitorConnectionPeerAddress "
	  "NO-USER-MODIFICATION "
	  "USAGE dSAOperation )",
	  &ad_olmTargetConnPeerAddress },
	{ "( olmAsyncmetaAttributes:13 "
	  "NAME ( 'olmTargetConnEstablishedTime' ) "
	  "DESC 'Time the connection was established' "
	  "EQUALITY integerMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 "
	  "SINGLE-VALUE "
	  "NO-USER-MODIFICATION "
	  "USAGE dSAOperation )",
	  &ad_olmTargetConnEstablishedTime },
	{ "( olmAsyncmetaAttributes:14 "
	  "NAME ( 'olmTargetConnResetTime' ) "
	  "DESC 'Last time the connection was reset' "
	  "EQUALITY integerMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 "
	  "SINGLE-VALUE "
	  "NO-USER-MODIFICATION "
	  "USAGE dSAOperation )",
	  &ad_olmTargetConnResetTime },
	{ "( olmAsyncmetaAttributes:15 "
	  "NAME ( 'olmTgtConnLastReset' ) "
	  "DESC 'Last time a connection to this target was reset' "
	  "EQUALITY integerMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 "
	  "SINGLE-VALUE "
	  "NO-USER-MODIFICATION "
	  "USAGE dSAOperation )",
	  &ad_olmTgtConnLastReset },
	{ NULL }
};

static struct {
	char		*name;
	ObjectClass	**oc;
}		s_moc[] = {
	{ "monitorContainer", &oc_monitorContainer },
	{ "monitorCounterObject", &oc_monitorCounterObject },

	{ NULL }
};

static struct {
	char		*desc;
	ObjectClass	**oc;
}		s_oc[] = {
	/* augments an existing object, so it must be AUXILIARY */
	{ "( olmAsyncmetaObjectClasses:1 "
		"NAME ( 'olmAsyncmetaDatabase' ) "
		"SUP top AUXILIARY "
		"MAY ( "
			"olmDbNextConnectionGroup "
			") )",
		&oc_olmAsyncmetaDatabase },
	{ "( olmAsyncmetaObjectClasses:2 "
		"NAME ( 'olmAsyncmetaTarget' ) "
		"SUP monitorConnection STRUCTURAL "
		"MAY ( "
	         "olmTgtURIList "
	         "$ olmTgtQuarantined "
	         "$ olmTgtConnLastReset "
	         "$ olmTgtTimeoutOps "
			") )",
		&oc_olmAsyncmetaTarget },
	{ "( olmAsyncmetaObjectClasses:3 "
		"NAME ( 'olmAsyncmetaConnectionGroup' ) "
		"SUP monitorConnection STRUCTURAL "
		"MAY ( "
	         "olmCGID "
	         "$ olmCGPendingOps "
			") )",
		&oc_olmAsyncmetaConnectionGroup },
	{ "( olmAsyncmetaObjectClasses:4 "
		"NAME ( 'olmAsyncmetaTargetConnection' ) "
		"SUP monitorConnection STRUCTURAL "
		"MAY ( "
	         "olmTargetConnLastUseTime "
	         "$ olmTargetConnBoundTime "
	         "$ olmTargetConnResultTime "
	         "$ olmTargetConnResetTime "
	         "$ olmTargetConnEstablishedTime "
	         "$ olmTargetConnFlags "
	         "$ olmTargetConnURI "
	         "$ olmTargetConnPeerAddress"
			") )",
		&oc_olmAsyncmetaTargetConnection },

	{ NULL }
};

/* stolen from mdb_monitor_free */
static int
asyncmeta_monitor_free(
	Entry		*e,
	ObjectClass *oc,
	void		**priv )
{
	struct berval	values[ 2 ];
	Modification	mod = { 0 };

	const char	*text;
	char		textbuf[ SLAP_TEXT_BUFLEN ];

	int		i;

	/* NOTE: if slap_shutdown != 0, priv might have already been freed */
	*priv = NULL;

	/* Remove objectClass */
	mod.sm_op = LDAP_MOD_DELETE;
	mod.sm_desc = slap_schema.si_ad_objectClass;
	mod.sm_values = values;
	mod.sm_numvals = 1;
	values[ 0 ] = oc->soc_cname;
	BER_BVZERO( &values[ 1 ] );

	 modify_delete_values( e, &mod, 1, &text,
		textbuf, sizeof( textbuf ) );

	/* remove attrs */
	mod.sm_values = NULL;
	mod.sm_numvals = 0;
	for ( i = 0; s_at[ i ].desc != NULL; i++ ) {
		mod.sm_desc = *s_at[ i ].ad;
		modify_delete_values( e, &mod, 1, &text,
			textbuf, sizeof( textbuf ) );
	}

	return SLAP_CB_CONTINUE;
}


static int
asyncmeta_back_monitor_subsystem_destroy(
	BackendDB		*be,
	monitor_subsys_t	*ms)
{
	free(ms->mss_dn.bv_val);
	BER_BVZERO(&ms->mss_dn);

	free(ms->mss_ndn.bv_val);
	BER_BVZERO(&ms->mss_ndn);

	return LDAP_SUCCESS;
}


/* code stolen from back-ldap, stolen from daemon.c */
static int
asyncmeta_back_monitor_conn_peername(
	LDAP		*ld,
	struct berval	*bv)
{
	Sockbuf *sockbuf;
	ber_socket_t socket;
	Sockaddr sa;
	socklen_t salen = sizeof(sa);
	const char *peeraddr = NULL;
	/* we assume INET6_ADDRSTRLEN > INET_ADDRSTRLEN */
	char addr[INET6_ADDRSTRLEN];
#ifdef LDAP_PF_LOCAL
	char peername[MAXPATHLEN + sizeof("PATH=")];
#elif defined(LDAP_PF_INET6)
	char peername[sizeof("IP=[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535")];
#else /* ! LDAP_PF_LOCAL && ! LDAP_PF_INET6 */
	char peername[sizeof("IP=255.255.255.255:65336")];
#endif /* LDAP_PF_LOCAL */

	assert( bv != NULL );

	ldap_get_option( ld, LDAP_OPT_SOCKBUF, (void **)&sockbuf );
	ber_sockbuf_ctrl( sockbuf, LBER_SB_OPT_GET_FD, &socket );
	getpeername( socket, (struct sockaddr *)&sa, &salen );

	switch ( sa.sa_addr.sa_family ) {
#ifdef LDAP_PF_LOCAL
		case AF_LOCAL:
			sprintf( peername, "PATH=%s", sa.sa_un_addr.sun_path );
			break;
#endif /* LDAP_PF_LOCAL */

#ifdef LDAP_PF_INET6
		case AF_INET6:
			if ( IN6_IS_ADDR_V4MAPPED(&sa.sa_in6_addr.sin6_addr) ) {
#if defined( HAVE_GETADDRINFO ) && defined( HAVE_INET_NTOP )
				peeraddr = inet_ntop( AF_INET,
						((struct in_addr *)&sa.sa_in6_addr.sin6_addr.s6_addr[12]),
						addr, sizeof(addr) );
#else /* ! HAVE_GETADDRINFO || ! HAVE_INET_NTOP */
				peeraddr = inet_ntoa( *((struct in_addr *)
							&sa.sa_in6_addr.sin6_addr.s6_addr[12]) );
#endif /* ! HAVE_GETADDRINFO || ! HAVE_INET_NTOP */
				if ( !peeraddr ) peeraddr = SLAP_STRING_UNKNOWN;
				sprintf( peername, "IP=%s:%d", peeraddr,
						(unsigned) ntohs( sa.sa_in6_addr.sin6_port ) );
			} else {
				peeraddr = inet_ntop( AF_INET6,
						&sa.sa_in6_addr.sin6_addr,
						addr, sizeof addr );
				if ( !peeraddr ) peeraddr = SLAP_STRING_UNKNOWN;
				sprintf( peername, "IP=[%s]:%d", peeraddr,
						(unsigned) ntohs( sa.sa_in6_addr.sin6_port ) );
			}
			break;
#endif /* LDAP_PF_INET6 */

		case AF_INET: {
#if defined( HAVE_GETADDRINFO ) && defined( HAVE_INET_NTOP )
				      peeraddr = inet_ntop( AF_INET, &sa.sa_in_addr.sin_addr,
						      addr, sizeof(addr) );
#else /* ! HAVE_GETADDRINFO || ! HAVE_INET_NTOP */
				      peeraddr = inet_ntoa( sa.sa_in_addr.sin_addr );
#endif /* ! HAVE_GETADDRINFO || ! HAVE_INET_NTOP */
				      if ( !peeraddr ) peeraddr = SLAP_STRING_UNKNOWN;
				      sprintf( peername, "IP=%s:%d", peeraddr,
						      (unsigned) ntohs( sa.sa_in_addr.sin_port ) );
			      } break;

		default:
			      sprintf( peername, SLAP_STRING_UNKNOWN );
	}

	ber_str2bv( peername, 0, 1, bv );
	return LDAP_SUCCESS;
}


static int
asyncmeta_back_monitor_target_conn_update(
	Operation	*op,
	SlapReply	*rs,
	Entry *e,
	void *priv)
{
	a_metasingleconn_t *msc = ( a_metasingleconn_t* )priv;
	Attribute *a;
	char buf[ BUFSIZ ];
	struct berval bv;
	char *ptr;
	int i;

	a = attr_find( e->e_attrs, ad_olmTargetConnLastUseTime );
	assert( a != NULL );
	bv.bv_val = buf;
	bv.bv_len = snprintf( buf, sizeof( buf ), "%lu", msc->msc_time );
	ber_bvreplace( &a->a_vals[ 0 ], &bv );

	a = attr_find( e->e_attrs, ad_olmTargetConnBoundTime );
	assert( a != NULL );
	bv.bv_val = buf;
	bv.bv_len = snprintf( buf, sizeof( buf ), "%lu", msc->msc_binding_time );
	ber_bvreplace( &a->a_vals[ 0 ], &bv );

	a = attr_find( e->e_attrs, ad_olmTargetConnResultTime );
	assert( a != NULL );
	bv.bv_val = buf;
	bv.bv_len = snprintf( buf, sizeof( buf ), "%lu", msc->msc_result_time );
	ber_bvreplace( &a->a_vals[ 0 ], &bv );

	a = attr_find( e->e_attrs, ad_olmTargetConnResetTime );
	assert( a != NULL );
	bv.bv_val = buf;
	bv.bv_len = snprintf( buf, sizeof( buf ), "%lu", msc->msc_reset_time );
	ber_bvreplace( &a->a_vals[ 0 ], &bv );

	a = attr_find( e->e_attrs, ad_olmTargetConnEstablishedTime );
	assert( a != NULL );
	bv.bv_val = buf;
	bv.bv_len = snprintf( buf, sizeof( buf ), "%lu", msc->msc_established_time );
	ber_bvreplace( &a->a_vals[ 0 ], &bv );

	a = attr_find( e->e_attrs, ad_olmTargetConnFlags );
	assert( a != NULL );
	bv.bv_val = buf;
	bv.bv_len = 0;
	ptr = bv.bv_val;

	if ( msc->msc_mscflags == 0 ) {
		bv.bv_len = snprintf( bv.bv_val, sizeof( buf ), "closed" );
	} else {
		for ( i = 0; s_flag[i].flag; i++ ) {
			int len = 0;
			if ( msc->msc_mscflags & s_flag[i].flag ) {
				if ( bv.bv_len == 0 )
					len = snprintf( ptr, sizeof( buf ), "%s", s_flag[i].name.bv_val );
				else
					len = snprintf( ptr, sizeof( buf )-bv.bv_len, ",%s", s_flag[i].name.bv_val );
				bv.bv_len += len;
				ptr += len;
			}
		}
	}
	ber_bvreplace( &a->a_vals[ 0 ], &bv );
	bv.bv_len = 0;

	if ( msc->msc_ld ) {
		a = attr_find( e->e_attrs, ad_olmTargetConnURI );
		ldap_get_option( msc->msc_ld, LDAP_OPT_URI, &bv.bv_val );
		ptr = strchr( bv.bv_val, ' ' );
		bv.bv_len = ptr ? ptr - bv.bv_val : strlen(bv.bv_val);
		ber_bvreplace( &a->a_vals[ 0 ], &bv );
		ch_free( bv.bv_val );

		asyncmeta_back_monitor_conn_peername( msc->msc_ld, &bv );
		a = attr_find( e->e_attrs, ad_olmTargetConnPeerAddress );
		ber_bvreplace( &a->a_vals[ 0 ], &bv );
		ch_free( bv.bv_val );
	} else {
		a = attr_find( e->e_attrs, ad_olmTargetConnURI );
		ber_bvreplace( &a->a_vals[ 0 ], &bv );
		a = attr_find( e->e_attrs, ad_olmTargetConnPeerAddress );
		ber_bvreplace( &a->a_vals[ 0 ], &bv );
	}

	return SLAP_CB_CONTINUE;
}

static int
asyncmeta_back_monitor_target_conn_free(
	Entry *e,
	void **priv)
{
	return asyncmeta_monitor_free( e, oc_olmAsyncmetaTargetConnection, priv );
}

static int
asyncmeta_back_monitor_target_conn_init(
	BackendDB		*be,
	monitor_subsys_t	*ms,
	Entry *parent,
	a_metaconn_t *mc )
{
	a_metainfo_t	*mi = (a_metainfo_t *) ms->mss_private;
	monitor_extra_t	*mbe;

	Entry		*e;
	int		rc = 0;
	int i;

	assert( be != NULL );
	mbe = (monitor_extra_t *) be->bd_info->bi_extra;

	for ( i = 0; i < mi->mi_ntargets; i++ )
	{
		monitor_callback_t *cb;
		char			    buf[ BACKMONITOR_BUFSIZE ];
		struct berval       conn_rdn;
		Attribute 		*a, *next;
		struct berval bv = BER_BVC( "0" );

		snprintf( buf, sizeof( buf ),
				  "cn=Target Connection %d", i+1 );
		ber_str2bv( buf, 0, 0, &conn_rdn );

		e = mbe->entry_stub( &parent->e_name, &parent->e_nname,
			&conn_rdn,
			oc_olmAsyncmetaTargetConnection, NULL, NULL );
		if ( e == NULL ) {
			Debug( LDAP_DEBUG_ANY,
				"asyncmeta_back_monitor_target_conn_init: "
				"unable to create entry \"%s,%s\"\n",
				conn_rdn.bv_val,
				parent->e_nname.bv_val );
			return( -1 );
		}

		cb = ch_calloc( sizeof( monitor_callback_t ), 1 );
		cb->mc_update = asyncmeta_back_monitor_target_conn_update;
		cb->mc_free = asyncmeta_back_monitor_target_conn_free;
		cb->mc_private = (void *)&mc->mc_conns[i];

		a = attrs_alloc( 1 + 8 );

		a->a_desc = slap_schema.si_ad_objectClass;
		attr_valadd( a, &oc_olmAsyncmetaTargetConnection->soc_cname, NULL, 1 );
		next = a->a_next;

		next->a_desc = ad_olmTargetConnLastUseTime;
		attr_valadd( next, &bv, NULL, 1 );
		next = next->a_next;

		next->a_desc = ad_olmTargetConnBoundTime;
		attr_valadd( next, &bv, NULL, 1 );
		next = next->a_next;

		next->a_desc = ad_olmTargetConnResultTime;
		attr_valadd( next, &bv, NULL, 1 );
		next = next->a_next;

		next->a_desc = ad_olmTargetConnFlags;
		attr_valadd( next, &bv, NULL, 1 );
		next = next->a_next;

		next->a_desc = ad_olmTargetConnURI;
		attr_valadd( next, &bv, NULL, 1 );
		next = next->a_next;

		next->a_desc = ad_olmTargetConnPeerAddress;
		attr_valadd( next, &bv, NULL, 1 );
		next = next->a_next;

		next->a_desc = ad_olmTargetConnResetTime;
		attr_valadd( next, &bv, NULL, 1 );
		next = next->a_next;

		next->a_desc = ad_olmTargetConnEstablishedTime;
		attr_valadd( next, &bv, NULL, 1 );

		rc = mbe->register_entry( e, NULL, ms, MONITOR_F_PERSISTENT_CH );
		if ( rc != LDAP_SUCCESS )
		{
			Debug( LDAP_DEBUG_ANY,
				"asyncmeta_back_monitor_target_conn_init: "
				"unable to register entry \"%s\" for monitoring\n",
				e->e_name.bv_val );
			ch_free( cb );
			attrs_free( a );
			entry_free( e );
			break;
		}

		rc = mbe->register_entry_attrs( &e->e_nname, a, cb,
											NULL, -1, NULL );
		if ( rc != LDAP_SUCCESS )
		{
			Debug( LDAP_DEBUG_ANY,
				"asyncmeta_back_monitor_target_conn_init: "
				"unable to register entry attributes \"%s\" for monitoring\n",
				e->e_name.bv_val );
		}
		attrs_free( a );
		entry_free( e );
	}

	return rc;
}

static int
asyncmeta_back_monitor_conn_group_update(
	Operation	*op,
	SlapReply	*rs,
	Entry *e,
	void *priv)
{
	a_metaconn_t *mc = ( a_metaconn_t* )priv;
	Attribute *a;
	char buf[ BUFSIZ ];
	struct berval bv;

	a = attr_find( e->e_attrs, ad_olmCGPendingOps );
	assert( a != NULL );
	bv.bv_val = buf;
	bv.bv_len = snprintf( buf, sizeof( buf ), "%i", mc->pending_ops );
	ber_bvreplace( &a->a_vals[ 0 ], &bv );
/* FIXME!!! */
	a = attr_find( e->e_attrs, ad_olmCGID );
	assert( a != NULL );
	bv.bv_val = buf;
	bv.bv_len = snprintf( buf, sizeof( buf ), "%i", mc->pending_ops );
	ber_bvreplace( &a->a_vals[ 0 ], &bv );

	return SLAP_CB_CONTINUE;
}


static int
asyncmeta_back_monitor_conn_group_free(
	Entry *e,
	void **priv)
{
	return asyncmeta_monitor_free( e, oc_olmAsyncmetaConnectionGroup, priv );
}

static int
asyncmeta_back_monitor_conn_init(
	BackendDB		*be,
	monitor_subsys_t	*ms )
{
	a_metainfo_t	*mi = (a_metainfo_t *) ms->mss_private;
	monitor_extra_t	*mbe;

	Entry		*e, *parent;
	int		rc;
	int i;

	assert( be != NULL );
	mbe = (monitor_extra_t *) be->bd_info->bi_extra;

	ms->mss_dn = ms->mss_ndn = mi->mi_monitor_info.mi_ndn;
	ms->mss_destroy = asyncmeta_back_monitor_subsystem_destroy;

	parent = mbe->entry_stub( &ms->mss_dn, &ms->mss_ndn,
		&mi->mi_monitor_info.mi_conn_rdn, oc_monitorContainer, NULL, NULL );
	if ( parent == NULL ) {
		Debug( LDAP_DEBUG_ANY,
			"asyncmeta_back_monitor_conn_init: "
			"unable to create entry \"%s,%s\"\n",
			mi->mi_monitor_info.mi_conn_rdn.bv_val,
			ms->mss_ndn.bv_val );
		return( -1 );
	}

	ber_dupbv( &ms->mss_dn, &parent->e_name );
	ber_dupbv( &ms->mss_ndn, &parent->e_nname );
	ber_dupbv( &ms->mss_rdn, &mi->mi_monitor_info.mi_conn_rdn );

	rc = mbe->register_entry( parent, NULL, ms, MONITOR_F_PERSISTENT_CH );

	for ( i = 0; i < mi->mi_num_conns; i++ )
	{
		monitor_callback_t *cb;
		char			    buf[ BACKMONITOR_BUFSIZE ];
		struct berval       conn_group_rdn;
		Attribute		*a,  *next;
		struct berval bv = BER_BVC( "0" );

		snprintf( buf, sizeof( buf ),
				  "cn=Connection Group %d", i+1 );
		ber_str2bv( buf, 0, 0, &conn_group_rdn );

		e = mbe->entry_stub( &parent->e_name, &parent->e_nname,
			&conn_group_rdn,
			oc_olmAsyncmetaConnectionGroup, NULL, NULL );
		if ( e == NULL ) {
			Debug( LDAP_DEBUG_ANY,
				"asyncmeta_back_monitor_conn_init: "
				"unable to create entry \"%s,%s\"\n",
				conn_group_rdn.bv_val,
				parent->e_nname.bv_val );
			return( -1 );
		}

		cb = ch_calloc( sizeof( monitor_callback_t ), 1 );
		cb->mc_update = asyncmeta_back_monitor_conn_group_update;
		cb->mc_free = asyncmeta_back_monitor_conn_group_free;
		cb->mc_private = (void *)&mi->mi_conns[i];
		cb->mc_next = NULL;

		a = attrs_alloc( 1 + 2 );

		a->a_desc = slap_schema.si_ad_objectClass;
		attr_valadd( a, &oc_olmAsyncmetaConnectionGroup->soc_cname, NULL, 1 );
		next = a->a_next;

		next->a_desc = ad_olmCGID;
		attr_valadd( next, &bv, NULL, 1 );
		next = next->a_next;

		next->a_desc = ad_olmCGPendingOps;
		attr_valadd( next, &bv, NULL, 1 );

		rc = mbe->register_entry( e, NULL, ms, MONITOR_F_PERSISTENT_CH );
		if ( rc != LDAP_SUCCESS )
		{
			Debug( LDAP_DEBUG_ANY,
				"asyncmeta_back_monitor_conn_init: "
				"unable to register entry \"%s\" for monitoring\n",
				e->e_name.bv_val );
			ch_free( cb );
			attrs_free( a );
			entry_free( e );
			break;
		}

		rc = mbe->register_entry_attrs( &e->e_nname, a, cb,
											NULL, -1, NULL );
		if ( rc != LDAP_SUCCESS )
		{
			Debug( LDAP_DEBUG_ANY,
				"asyncmeta_back_monitor_conn_init: "
				"unable to register entry attributes \"%s\" for monitoring\n",
				e->e_name.bv_val );
		}

		rc = asyncmeta_back_monitor_target_conn_init( be, ms, e, &mi->mi_conns[i] );
		if ( rc != LDAP_SUCCESS )
		{
			ch_free( cb );
			attrs_free( a );
			entry_free( e );
			break;
		}
		attrs_free( a );
		entry_free( e );
	}

	entry_free( parent );

	return rc;
}

/*
 * Targets monitoring subsystem:
 * Is target quarantined, last time a connection to it was reset, etc
 */

static int
asyncmeta_back_monitor_targets_free(
	Entry *e,
	void **priv)
{
	return asyncmeta_monitor_free( e, oc_olmAsyncmetaTarget, priv );
}

static int
asyncmeta_back_monitor_targets_update(
	Operation	*op,
	SlapReply	*rs,
	Entry		*e,
	void		*priv )
{
	a_metatarget_t *mt = ( a_metatarget_t* )priv;
	Attribute *a;
	char buf[ BUFSIZ ];
	struct berval bv;

	a = attr_find( e->e_attrs, ad_olmTgtURIList );
	assert( a != NULL );
	bv.bv_val = buf;
	/* todo mutex*/
	bv.bv_len = snprintf( buf, sizeof( buf ), "%s", mt->mt_uri );
	ber_bvreplace( &a->a_vals[ 0 ], &bv );

	a = attr_find( e->e_attrs, ad_olmTgtQuarantined );
	assert( a != NULL );
	bv.bv_val = buf;
	if ( mt->mt_isquarantined > 0 ) {
		bv.bv_len = snprintf( buf, sizeof( buf ), "%s", "TRUE" );
	} else {
		bv.bv_len = snprintf( buf, sizeof( buf ), "%s", "FALSE" );
	}
	ber_bvreplace( &a->a_vals[ 0 ], &bv );

	a = attr_find( e->e_attrs, ad_olmTgtTimeoutOps );
	assert( a != NULL );
	bv.bv_val = buf;
	bv.bv_len = snprintf( buf, sizeof( buf ), "%i", mt->mt_timeout_ops );
	ber_bvreplace( &a->a_vals[ 0 ], &bv );

	a = attr_find( e->e_attrs, ad_olmTgtConnLastReset );
	assert( a != NULL );
	bv.bv_val = buf;
	bv.bv_len = snprintf( buf, sizeof( buf ), "%lu", mt->msc_reset_time );
	ber_bvreplace( &a->a_vals[ 0 ], &bv );

	return SLAP_CB_CONTINUE;
}

static int
asyncmeta_back_monitor_targets_init(
	BackendDB		*be,
	monitor_subsys_t	*ms )
{
	a_metainfo_t	*mi = (a_metainfo_t *) ms->mss_private;
	monitor_extra_t	*mbe;
	Entry		*e, *parent;
	int		rc;
	int i;

	assert( be != NULL );

	mbe = (monitor_extra_t *) be->bd_info->bi_extra;

	ms->mss_dn = ms->mss_ndn = mi->mi_monitor_info.mi_ndn;
	ms->mss_destroy = asyncmeta_back_monitor_subsystem_destroy;

	parent = mbe->entry_stub( &ms->mss_dn, &ms->mss_ndn,
		&mi->mi_monitor_info.mi_targets_rdn, oc_monitorContainer, NULL, NULL );
	if ( parent == NULL ) {
		Debug( LDAP_DEBUG_ANY,
			"asyncmeta_back_monitor_targets_init: "
			"unable to create entry \"%s,%s\"\n",
			mi->mi_monitor_info.mi_targets_rdn.bv_val,
			ms->mss_ndn.bv_val );
		return( -1 );
	}

	ber_dupbv( &ms->mss_dn, &parent->e_name );
	ber_dupbv( &ms->mss_ndn, &parent->e_nname );
	ber_dupbv( &ms->mss_rdn, &mi->mi_monitor_info.mi_conn_rdn );
	
	rc = mbe->register_entry( parent, NULL, ms, MONITOR_F_PERSISTENT_CH );
	if ( rc != LDAP_SUCCESS )
	{
		Debug( LDAP_DEBUG_ANY,
			"asyncmeta_back_monitor_target_init: "
			"unable to register entry \"%s\" for monitoring\n",
			parent->e_name.bv_val );
		goto done;
	}

	for ( i = 0; i < mi->mi_ntargets; i++ )
	{
		monitor_callback_t *cb;
		char			    buf[ BACKMONITOR_BUFSIZE ];
		struct berval       target_rdn;
		Attribute		*a, *next;
		struct berval bv = BER_BVC( "0" );

		snprintf( buf, sizeof( buf ),
				  "cn=Target %d", i+1 );
		ber_str2bv( buf, 0, 0, &target_rdn );

		e = mbe->entry_stub( &parent->e_name, &parent->e_nname,
			&target_rdn,
			oc_olmAsyncmetaTarget, NULL, NULL );
		if ( e == NULL ) {
			Debug( LDAP_DEBUG_ANY,
				"asyncmeta_back_monitor_targets_init: "
				"unable to create entry \"%s,%s\"\n",
				target_rdn.bv_val,
				parent->e_nname.bv_val );
			return( -1 );
		}

		cb = ch_calloc( sizeof( monitor_callback_t ), 1 );
		cb->mc_update = asyncmeta_back_monitor_targets_update;
		cb->mc_free = asyncmeta_back_monitor_targets_free;
		cb->mc_private = (void *)&mi->mi_targets[i];

		a = attrs_alloc( 1 + 4 );

		a->a_desc = slap_schema.si_ad_objectClass;
		attr_valadd( a, &oc_olmAsyncmetaTarget->soc_cname, NULL, 1 );
		next = a->a_next;

		next->a_desc = ad_olmTgtURIList;
		attr_valadd( next, &bv, NULL, 1 );
		next = next->a_next;

		next->a_desc = ad_olmTgtQuarantined;
		attr_valadd( next, &bv, NULL, 1 );
		next = next->a_next;

		next->a_desc = ad_olmTgtConnLastReset;
		attr_valadd( next, &bv, NULL, 1 );
		next = next->a_next;

		next->a_desc = ad_olmTgtTimeoutOps;
		attr_valadd( next, &bv, NULL, 1 );

		rc = mbe->register_entry( e, NULL, ms, MONITOR_F_PERSISTENT_CH );
		if ( rc != LDAP_SUCCESS )
		{
			Debug( LDAP_DEBUG_ANY,
				"asyncmeta_back_monitor_targets_init: "
				"unable to register entry \"%s\" for monitoring\n",
				e->e_name.bv_val );
			ch_free( cb );
			attrs_free( a );
			entry_free( e );
			break;
		}

		rc = mbe->register_entry_attrs( &e->e_nname, a, cb,
											NULL, -1, NULL );
		if ( rc != LDAP_SUCCESS )
		{
			Debug( LDAP_DEBUG_ANY,
				"asyncmeta_back_monitor_targets_init: "
				"unable to register entry attributes \"%s\" for monitoring\n",
				e->e_name.bv_val );
		}
		attrs_free( a );
		entry_free( e );
	}

done:
	entry_free( parent );

	return rc;
}

/*
 * call from within asyncmeta_back_initialize()
 */
static int
asyncmeta_back_monitor_initialize( void )
{
	int		i, code;
	ConfigArgs c;
	char	*argv[ 3 ];

	static int	asyncmeta_back_monitor_initialized = 0;

	/* set to 0 when successfully initialized; otherwise, remember failure */
	static int	asyncmeta_back_monitor_initialized_failure = 1;

	/* register schema here */

	if ( asyncmeta_back_monitor_initialized++ ) {
		return asyncmeta_back_monitor_initialized_failure;
	}

	if ( backend_info( "monitor" ) == NULL ) {
		return -1;
	}

	argv[ 0 ] = "back-asyncmeta monitor";
	c.argv = argv;
	c.argc = 3;
	c.fname = argv[0];
	for ( i = 0; s_oid[ i ].name; i++ ) {

		argv[ 1 ] = s_oid[ i ].name;
		argv[ 2 ] = s_oid[ i ].oid;

		if ( parse_oidm( &c, 0, NULL ) != 0 ) {
			Debug( LDAP_DEBUG_ANY,
				"asyncmeta_back_monitor_initialize: unable to add "
				"objectIdentifier \"%s=%s\"\n",
				s_oid[ i ].name, s_oid[ i ].oid );
			return 2;
		}
	}

	for ( i = 0; s_at[ i ].desc != NULL; i++ ) {
		code = register_at( s_at[ i ].desc, s_at[ i ].ad, 1 );
		if ( code != LDAP_SUCCESS ) {
			Debug( LDAP_DEBUG_ANY,
				"asyncmeta_back_monitor_initialize: register_at failed for attributeType (%s)\n",
				s_at[ i ].desc );
			return 3;

		} else {
			(*s_at[ i ].ad)->ad_type->sat_flags |= SLAP_AT_HIDE;
		}
	}

	for ( i = 0; s_oc[ i ].desc != NULL; i++ ) {
		code = register_oc( s_oc[ i ].desc, s_oc[ i ].oc, 1 );
		if ( code != LDAP_SUCCESS ) {
			Debug( LDAP_DEBUG_ANY,
				"asyncmeta_back_monitor_initialize: register_oc failed for objectClass (%s)\n",
				s_oc[ i ].desc );
			return 4;

		} else {
			(*s_oc[ i ].oc)->soc_flags |= SLAP_OC_HIDE;
		}
	}

	for ( i = 0; s_moc[ i ].name != NULL; i++ ) {
		*s_moc[i].oc = oc_find( s_moc[ i ].name );
		if ( ! *s_moc[i].oc ) {
			Debug( LDAP_DEBUG_ANY,
				"asyncmeta_back_monitor_initialize: failed to find objectClass (%s)\n",
				s_moc[ i ].name );
			return 5;

		}
	}

	return ( asyncmeta_back_monitor_initialized_failure = LDAP_SUCCESS );
}

/*
 * call from within asyncmeta_back_db_init()
 */
int
asyncmeta_back_monitor_db_init( BackendDB *be )
{
	int	rc;

	rc = asyncmeta_back_monitor_initialize();
	if ( rc != LDAP_SUCCESS ) {
		return rc;
	}

	return 0;
}

/* adapted from mdb_monitor_update */
static int
asyncmeta_monitor_db_update(
	Operation	*op,
	SlapReply	*rs,
	Entry		*e,
	void		*priv )
{
	struct a_metainfo_t		*mi = (struct a_metainfo_t *) priv;
	Attribute *a;
	char buf[ BUFSIZ ];
	struct berval bv;

	a = attr_find( e->e_attrs, ad_olmDbNextConnectionGroup );
	assert( a != NULL );
	bv.bv_val = buf;
	bv.bv_len = snprintf( buf, sizeof( buf ), "%i", mi->mi_next_conn+1 );
	ber_bvreplace( &a->a_vals[ 0 ], &bv );

	return SLAP_CB_CONTINUE;
}

static int
asyncmeta_monitor_db_free
(
	Entry		*e,
	void		**priv )
{
	return asyncmeta_monitor_free( e, oc_olmAsyncmetaDatabase, priv );
}

/*
 * call from within asyncmeta_back_db_open()
 */
int
asyncmeta_back_monitor_db_open( BackendDB *be )
{
	a_metainfo_t		*mi = (a_metainfo_t *) be->be_private;
	monitor_subsys_t	*mss;
	int			rc = 0;
	BackendInfo		*bi;
	monitor_extra_t		*mbe;
	Attribute *a, *next;
	monitor_callback_t *cb;

	struct berval bv = BER_BVC( "0" );

	if ( !SLAP_DBMONITORING( be ) ) {
		return 0;
	}

	/* check if monitor is configured and usable */
	bi = backend_info( "monitor" );
	if ( !bi || !bi->bi_extra ) {
		SLAP_DBFLAGS( be ) ^= SLAP_DBFLAG_MONITORING;
		return 0;
	}
	mbe = bi->bi_extra;

	/* don't bother if monitor is not configured */
	if ( !mbe->is_configured() ) {
		static int warning = 0;

		if ( warning++ == 0 ) {
			Debug( LDAP_DEBUG_CONFIG, "back_asyncmeta_monitor_db_open: "
				"monitoring disabled; "
				"configure monitor database to enable\n" );
		}

		return 0;
	}

	if ( BER_BVISNULL( &mi->mi_monitor_info.mi_ndn ) ) {
		rc = mbe->register_database( be, &mi->mi_monitor_info.mi_ndn );
		if ( rc != 0 ) {
			Debug( LDAP_DEBUG_ANY, "back_asyncmeta_monitor_db_open: "
				"failed to register the database with back-monitor\n" );
		}
	}
	a = attrs_alloc( 2 );
	if ( a == NULL ) {
		return -1;
	}

	a->a_desc = slap_schema.si_ad_objectClass;
	attr_valadd( a, &oc_olmAsyncmetaDatabase->soc_cname, NULL, 1 );
	next = a->a_next;

	next->a_desc = ad_olmDbNextConnectionGroup;
	attr_valadd( next, &bv, NULL, 1 );

	cb = ch_calloc( sizeof( monitor_callback_t ), 1 );
	cb->mc_update = asyncmeta_monitor_db_update;
	cb->mc_free = asyncmeta_monitor_db_free;
	cb->mc_private = (void *)mi;

	rc = mbe->register_entry_attrs( &mi->mi_monitor_info.mi_ndn, a, cb,
			NULL, -1, NULL );
	attrs_free( a );
	if ( rc != 0 ) {
			Debug( LDAP_DEBUG_ANY, "back_asyncmeta_monitor_db_open: "
				   "failed to register entry %s with back-monitor\n",
				   mi->mi_monitor_info.mi_ndn.bv_val );
			return rc;
	}
	if ( BER_BVISNULL( &mi->mi_monitor_info.mi_conn_rdn ) ) {
		ber_str2bv( "cn=Connections", 0, 1,
			&mi->mi_monitor_info.mi_conn_rdn );
	}
	if ( BER_BVISNULL( &mi->mi_monitor_info.mi_targets_rdn ) ) {
		ber_str2bv( "cn=Targets", 0, 1,
			&mi->mi_monitor_info.mi_targets_rdn );
	}

	/* set up the subsystems used to create the targets and
	 * connection entries */
	/* unlike back-ldap, these entries are persistent,
	 * since asyncmeta maintains the data structures regardless of
	 * the ldap connection state */

	/* this will leak at monitor_db_destroy, but it can't be helped */
	mi->mi_monitor_info.mi_conn_mss = (monitor_subsys_t *)ch_calloc( 1, sizeof( monitor_subsys_t ) );
	/* just for clarity */
	mss = mi->mi_monitor_info.mi_conn_mss;
	mss->mss_name = "back-asyncmeta connections";
	mss->mss_flags = MONITOR_F_PERSISTENT_CH;
	mss->mss_open = asyncmeta_back_monitor_conn_init;
	mss->mss_private = mi;

	if ( mbe->register_subsys_late( mss ) )
	{
		Debug( LDAP_DEBUG_ANY,
			"back_asyncmeta_monitor_db_open: "
			"failed to register connections subsystem" );
		return -1;
	}

	mi->mi_monitor_info.mi_targets_mss = (monitor_subsys_t *)ch_calloc( 1, sizeof( monitor_subsys_t ) );
	mss = mi->mi_monitor_info.mi_targets_mss;
	mss->mss_name = "back-asyncmeta targets";
	mss->mss_flags = MONITOR_F_PERSISTENT_CH;
	mss->mss_open = asyncmeta_back_monitor_targets_init;
	mss->mss_private = mi;

	if ( mbe->register_subsys_late( mss ) )
	{
		Debug( LDAP_DEBUG_ANY,
			"ldap_back_monitor_db_open: "
			"failed to register operation subsystem" );
		return -1;
	}

	return rc;
}

/*
 * call from within asyncmeta_back_db_close()
 */
int
asyncmeta_back_monitor_db_close( BackendDB *be )
{
	a_metainfo_t		*mi = (a_metainfo_t *) be->be_private;
	int rc = 0;
	if ( mi && !BER_BVISNULL( &mi->mi_monitor_info.mi_ndn ) ) {
		BackendInfo		*bi;
		monitor_extra_t		*mbe;

		/* check if monitor is configured and usable */
		bi = backend_info( "monitor" );
		if ( bi && bi->bi_extra ) {
	   		mbe = bi->bi_extra;
			rc = mbe->unregister_entry( &mi->mi_monitor_info.mi_ndn );
		}
	}
	return rc;
}

/*
 * call from within asyncmeta_back_db_destroy()
 */
int
asyncmeta_back_monitor_db_destroy( BackendDB *be )
{
	a_metainfo_t		*mi = (a_metainfo_t *) be->be_private;
	if ( mi ) {
		if ( mi->mi_monitor_info.mi_targets_rdn.bv_len > 0 ) {
			ch_free( mi->mi_monitor_info.mi_targets_rdn.bv_val );
		}
		if ( mi->mi_monitor_info.mi_conn_rdn.bv_len > 0 ) {
			ch_free( mi->mi_monitor_info.mi_conn_rdn.bv_val );
		}
	}
	return 0;
}
