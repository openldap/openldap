/* init.c - initialize test harness backend */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2007-2022 The OpenLDAP Foundation.
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
 * This work was initially developed by Ondřej Kuzník for inclusion
 * in OpenLDAP Software.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/errno.h>
#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "mod-harness.h"

struct harness_conf_info harness_info;

static void *
harness_ready( void *ctx, void *arg )
{
    BackendInfo *bi = arg;
    struct harness_conf_info *hi = bi->bi_private;

    ldap_pvt_thread_mutex_lock( &slapd_init_mutex );
    while ( !slapd_ready && !slapd_shutdown ) {
        ldap_pvt_thread_cond_wait( &slapd_init_cond, &slapd_init_mutex );
    }
    ldap_pvt_thread_mutex_unlock( &slapd_init_mutex );

    if ( !slapd_shutdown ) {
        dprintf( hi->h_conn->c_sd, "SLAPD READY\n" );
    }
    return NULL;
}

static int
harness_resolve_addresses(
    const char *host,
    unsigned short port,
    struct sockaddr ***sal )
{
    struct sockaddr **sap;

#ifdef LDAP_PF_LOCAL
    if ( port == 0 ) {
        *sal = ch_malloc(2 * sizeof(void *));

        sap = *sal;
        *sap = ch_malloc(sizeof(struct sockaddr_un));
        sap[1] = NULL;

        if ( strlen(host) >
                (sizeof(((struct sockaddr_un *)*sap)->sun_path) - 1) )
        {
            Debug( LDAP_DEBUG_ANY, "harness_resolve_addresses: "
                    "domain socket path (%s) too long in URL\n",
                    host );
            goto errexit;
        }

        (void)memset( (void *)*sap, '\0', sizeof(struct sockaddr_un) );
        (*sap)->sa_family = AF_LOCAL;
        strcpy( ((struct sockaddr_un *)*sap)->sun_path, host );
    } else
#endif /* LDAP_PF_LOCAL */
    {
#ifdef HAVE_GETADDRINFO
        struct addrinfo hints, *res, *sai;
        int n, err;
        char serv[7];

        memset( &hints, '\0', sizeof(hints) );
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_family = slap_inet4or6;
        snprintf(serv, sizeof serv, "%d", port);

        if ( (err = getaddrinfo(host, serv, &hints, &res)) ) {
            Debug( LDAP_DEBUG_ANY, "harness_resolve_addresses: "
                    "getaddrinfo() failed: %s\n",
                    AC_GAI_STRERROR(err) );
            return -1;
        }

        sai = res;
        for (n=2; (sai = sai->ai_next) != NULL; n++) {
            /* EMPTY */ ;
        }
        *sal = ch_calloc(n, sizeof(void *));
        if (*sal == NULL) return -1;

        sap = *sal;
        *sap = NULL;

        for ( sai=res; sai; sai=sai->ai_next ) {
            if( sai->ai_addr == NULL ) {
                Debug( LDAP_DEBUG_ANY, "harness_resolve_addresses: "
                        "getaddrinfo ai_addr is NULL?\n" );
                freeaddrinfo(res);
                goto errexit;
            }

            switch ( sai->ai_family ) {
#  ifdef LDAP_PF_INET6
                case AF_INET6:
                    *sap = ch_malloc(sizeof(struct sockaddr_in6));
                    *(struct sockaddr_in6 *)*sap =
                        *((struct sockaddr_in6 *)sai->ai_addr);
                    break;
#  endif /* LDAP_PF_INET6 */
                case AF_INET:
                    *sap = ch_malloc(sizeof(struct sockaddr_in));
                    *(struct sockaddr_in *)*sap =
                        *((struct sockaddr_in *)sai->ai_addr);
                    break;
                default:
                    *sap = NULL;
                    break;
            }

            if (*sap != NULL) {
                (*sap)->sa_family = sai->ai_family;
                sap++;
                *sap = NULL;
            }
        }

        freeaddrinfo(res);

#else /* ! HAVE_GETADDRINFO */
        int i, n = 1;
        struct in_addr in;
        struct hostent *he = NULL;

        if ( !inet_aton( host, &in ) ) {
            he = gethostbyname( host );
            if( he == NULL ) {
                Debug( LDAP_DEBUG_ANY, "harness_resolve_addresses: "
                        "invalid host %s\n", host );
                return -1;
            }
            for (n = 0; he->h_addr_list[n]; n++) /* empty */;
        }

        *sal = ch_malloc((n+1) * sizeof(void *));

        sap = *sal;
        for ( i = 0; i<n; i++ ) {
            sap[i] = ch_malloc(sizeof(struct sockaddr_in));

            (void)memset( (void *)sap[i], '\0', sizeof(struct sockaddr_in) );
            sap[i]->sa_family = he->h_addrtype;
            switch ( he->h_addrtype ) {
                case AF_INET:
                    ((struct sockaddr_in *)sap[i])->sin_port = htons(port);
                    break;
#  ifdef LDAP_PF_INET6
                case AF_INET6:
                    ((struct sockaddr_in6 *)sap[i])->sin6_port = htons(port);
                    break;
#  endif /* LDAP_PF_INET6 */
                default:
                    Debug( LDAP_DEBUG_ANY, "harness_resolve_addresses: "
                            "unknown protocol family from gethostbyname\n" );
                    goto errexit;
            }

            AC_MEMCPY( &((struct sockaddr_in *)sap[i])->sin_addr,
                    he ? (struct in_addr *)he->h_addr_list[i] : &in,
                    sizeof(struct in_addr) );
        }
        sap[i] = NULL;
#endif /* ! HAVE_GETADDRINFO */
    }

    return 0;

errexit:
    for (sap = *sal; *sap != NULL; sap++) ch_free(*sap);
    ch_free(*sal);
    return -1;
}

static int
harness_connect( BackendInfo *bi )
{
    struct harness_conf_info *hi = bi->bi_private;
    struct sockaddr **res, **sal;
    int rc = -1;

    if ( !hi->h_host || !hi->h_port ) {
        Debug( LDAP_DEBUG_ANY, "harness_connect: "
                "configuration incomplete, host or port missing\n" );
        return rc;
    }

    if ( harness_resolve_addresses( hi->h_host, hi->h_port, &res ) ) {
        return rc;
    }

    for ( sal=res; *sal; sal++ ) {
        char ebuf[128];
        Connection *c;
        char *af;
        ber_socket_t s;
        socklen_t addrlen;

        switch ( (*sal)->sa_family ) {
        case AF_INET:
            af = "IPv4";
            addrlen = sizeof(struct sockaddr_in);
            break;
#ifdef LDAP_PF_INET6
        case AF_INET6:
            af = "IPv6";
            addrlen = sizeof(struct sockaddr_in6);
            break;
#endif /* LDAP_PF_INET6 */
#ifdef LDAP_PF_LOCAL
        case AF_LOCAL:
            af = "Local";
            addrlen = sizeof(struct sockaddr_un);
            break;
#endif /* LDAP_PF_LOCAL */
        default:
            sal++;
            continue;
        }

        s = socket( (*sal)->sa_family, SOCK_STREAM, 0 );
        if ( s == AC_SOCKET_INVALID ) {
            int err = sock_errno();
            Debug( LDAP_DEBUG_ANY, "harness_connect: "
                    "%s socket() failed errno=%d (%s)\n",
                    af, err, sock_errstr( err, ebuf, sizeof(ebuf) ) );
            continue;
        }

        if ( connect( s, (struct sockaddr *)*sal, addrlen ) == AC_SOCKET_ERROR ) {
            int err = sock_errno();
            Debug( LDAP_DEBUG_ANY, "harness_connect: "
                    "connect() failed errno=%d (%s)\n",
                    err, sock_errstr( err, ebuf, sizeof(ebuf) ) );
            close( s );
            continue;
        }

        c = connection_client_setup( s, harness_callback, hi );
        if ( c == NULL ) {
            Debug( LDAP_DEBUG_ANY, "harness_connect: "
                    "could not allocate connection\n" );
            close( s );
        }

        hi->h_conn = c;
        dprintf( c->c_sd, "PID %d %s\n", getpid(), hi->h_identifier );
        rc = 0;
        break;
    }

    ch_free( res );
    return rc;
}

static int
harness_back_open( BackendInfo *bi )
{
    struct harness_conf_info *hi = bi->bi_private;
    Listener **l;

    if ( slapMode & SLAP_TOOL_MODE ) {
        return 0;
    }

    if ( harness_connect( bi ) ) {
        Debug( LDAP_DEBUG_ANY, "harness_back_open: "
                "failed to contact test harness\n" );
        return -1;
    }

    if ( ( l = slapd_get_listeners() ) == NULL ) {
        Debug( LDAP_DEBUG_ANY, "harness_back_open: "
                "unable to get listeners\n" );
        return -1;
    }

    /* FIXME: A temporary text protocol for human consumption */
    dprintf( hi->h_conn->c_sd, "LISTENERS\n" );
    for ( ; *l; l++ ) {
        dprintf( hi->h_conn->c_sd, "URI=%s %s\n",
                (*l)->sl_url.bv_val, (*l)->sl_name.bv_val );
    }
    dprintf( hi->h_conn->c_sd, "LISTENERS END\n" );

    /* Contact harness as soon as startup finishes and slapd is running */
    return ldap_pvt_thread_pool_submit( &connection_pool, harness_ready, bi );
}

static int
harness_back_close( BackendInfo *bi )
{
    struct harness_conf_info *hi = bi->bi_private;

    if ( slapMode & SLAP_TOOL_MODE ) {
        return 0;
    }

    if ( slapd_shutdown ) {
        dprintf( hi->h_conn->c_sd, "SLAPD SHUTDOWN\n" );
    } else {
        dprintf( hi->h_conn->c_sd, "MODULE STOPPED\n" );
    }

    return 0;
}

static int
harness_global_init( void )
{
    return 0;
}

static int
harness_global_destroy( BackendInfo *bi )
{
    return 0;
}

int
harness_back_initialize( BackendInfo *bi )
{
    Debug( LDAP_DEBUG_TRACE, "harness_back_initialize: "
            "module loaded\n" );

    bi->bi_flags = SLAP_BFLAG_STANDALONE;
    bi->bi_open = harness_back_open;
    bi->bi_config = 0;
    bi->bi_pause = 0;
    bi->bi_unpause = 0;
    bi->bi_close = harness_back_close;
    bi->bi_destroy = harness_global_destroy;

    bi->bi_db_init = 0;
    bi->bi_db_config = 0;
    bi->bi_db_open = 0;
    bi->bi_db_close = 0;
    bi->bi_db_destroy = 0;

    bi->bi_op_bind = 0;
    bi->bi_op_unbind = 0;
    bi->bi_op_search = 0;
    bi->bi_op_compare = 0;
    bi->bi_op_modify = 0;
    bi->bi_op_modrdn = 0;
    bi->bi_op_add = 0;
    bi->bi_op_delete = 0;
    bi->bi_op_abandon = 0;

    bi->bi_extended = 0;

    bi->bi_chk_referrals = 0;

    bi->bi_connection_init = 0;
    bi->bi_connection_destroy = 0;

    if ( harness_global_init() ) {
        return -1;
    }

    bi->bi_private = &harness_info;
    return harness_back_init_cf( bi );
}

SLAP_BACKEND_INIT_MODULE( harness )
