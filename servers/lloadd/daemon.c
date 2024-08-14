/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2024 The OpenLDAP Foundation.
 * Portions Copyright 2007 by Howard Chu, Symas Corporation.
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

#include <ac/ctype.h>
#include <ac/errno.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>
#include <ac/unistd.h>

#include <event2/event.h>
#include <event2/dns.h>
#include <event2/listener.h>

#include "lload.h"
#include "ldap_pvt_thread.h"
#include "lutil.h"

#include "ldap_rq.h"

#ifdef HAVE_SYSTEMD
#include "sd-notify.h"
#endif

#ifdef LDAP_PF_LOCAL
#include <sys/stat.h>
/* this should go in <ldap.h> as soon as it is accepted */
#define LDAPI_MOD_URLEXT "x-mod"
#endif /* LDAP_PF_LOCAL */

#ifndef BALANCER_MODULE
#ifdef LDAP_PF_INET6
int slap_inet4or6 = AF_UNSPEC;
#else /* ! INETv6 */
int slap_inet4or6 = AF_INET;
#endif /* ! INETv6 */

/* globals */
time_t starttime;

#ifdef LDAP_TCP_BUFFER
int slapd_tcp_rmem;
int slapd_tcp_wmem;
#endif /* LDAP_TCP_BUFFER */

volatile sig_atomic_t slapd_shutdown = 0;
volatile sig_atomic_t slapd_gentle_shutdown = 0;
volatile sig_atomic_t slapd_abrupt_shutdown = 0;
#endif /* !BALANCER_MODULE */

static int emfile;

ldap_pvt_thread_mutex_t lload_wait_mutex;
ldap_pvt_thread_cond_t lload_wait_cond;
ldap_pvt_thread_cond_t lload_pause_cond;

#ifndef SLAPD_MAX_DAEMON_THREADS
#define SLAPD_MAX_DAEMON_THREADS 16
#endif
int lload_daemon_threads = 1;
int lload_daemon_mask;

/*
 * We might be a module, so concerns about listeners are different from slapd,
 * instead they are set up in three phases:
 * 1. parse urls to set up (LloadListener *) in configuration/main()
 * 2. resolve socket names and bind() just before going online
 *    Unlike slapd or standalone, module lloadd cannot see configuration
 *    (acquire sockets) prior to privileges being dropped. Admins should use
 *    CAP_NET_BIND_SERVICE on Linux, or similar elsewhere
 * 3. as we go online, allocate them to the listener base
 */
struct event_base *listener_base = NULL;
LloadListener **lload_listeners = NULL;
static ldap_pvt_thread_t listener_tid, *daemon_tid;

#ifndef RESOLV_CONF_PATH
#define RESOLV_CONF_PATH "/etc/resolv.conf"
#endif
char *lload_resolvconf_path = RESOLV_CONF_PATH;

struct event_base *daemon_base = NULL;
struct evdns_base *dnsbase;

struct event *lload_timeout_event;
struct event *lload_stats_event;

/*
 * global lload statistics. Not mutex protected to preserve performance -
 * increment is atomic, at most we risk a bit of inconsistency
 */
lload_global_stats_t lload_stats = {};

#ifndef SLAPD_LISTEN_BACKLOG
#define SLAPD_LISTEN_BACKLOG 1024
#endif /* ! SLAPD_LISTEN_BACKLOG */

#define DAEMON_ID(fd) ( fd & lload_daemon_mask )

#ifdef HAVE_WINSOCK
ldap_pvt_thread_mutex_t slapd_ws_mutex;
SOCKET *slapd_ws_sockets;
#define SD_READ 1
#define SD_WRITE 2
#define SD_ACTIVE 4
#define SD_LISTENER 8
#endif

#ifdef HAVE_TCPD
static ldap_pvt_thread_mutex_t sd_tcpd_mutex;
#endif /* TCP Wrappers */

typedef struct listener_item {
    struct evconnlistener *listener;
    ber_socket_t fd;
} listener_item;

typedef struct lload_daemon_st {
    ldap_pvt_thread_mutex_t sd_mutex;

    struct event_base *base;
    struct event *wakeup_event;
} lload_daemon_st;

static lload_daemon_st lload_daemon[SLAPD_MAX_DAEMON_THREADS];

static void daemon_wakeup_cb( evutil_socket_t sig, short what, void *arg );

static void
lloadd_close( ber_socket_t s )
{
    Debug( LDAP_DEBUG_CONNS, "lloadd_close: "
            "closing fd=%ld\n",
            (long)s );
    tcp_close( s );
}

#if defined(LDAP_PF_LOCAL) || defined(SLAP_X_LISTENER_MOD)
static int
get_url_perms( char **exts, mode_t *perms )
{
    int i;

    assert( exts != NULL );
    assert( perms != NULL );

    for ( i = 0; exts[i]; i++ ) {
        char *type = exts[i];

        if ( type[0] == '!' ) {
            type++;
        }

        if ( strncasecmp( type, LDAPI_MOD_URLEXT "=",
                     sizeof(LDAPI_MOD_URLEXT "=") - 1 ) == 0 ) {
            char *value = type + ( sizeof(LDAPI_MOD_URLEXT "=") - 1 );
            mode_t p = 0;
            int j;

            switch ( strlen( value ) ) {
                case 4:
                    /* skip leading '0' */
                    if ( value[0] != '0' ) return LDAP_OTHER;
                    value++;

                case 3:
                    for ( j = 0; j < 3; j++ ) {
                        int v;

                        v = value[j] - '0';

                        if ( v < 0 || v > 7 ) return LDAP_OTHER;

                        p |= v << 3 * ( 2 - j );
                    }
                    break;

                case 10:
                    for ( j = 1; j < 10; j++ ) {
                        static mode_t m[] = { 0, S_IRUSR, S_IWUSR, S_IXUSR,
                                S_IRGRP, S_IWGRP, S_IXGRP, S_IROTH, S_IWOTH,
                                S_IXOTH };
                        static const char c[] = "-rwxrwxrwx";

                        if ( value[j] == c[j] ) {
                            p |= m[j];

                        } else if ( value[j] != '-' ) {
                            return LDAP_OTHER;
                        }
                    }
                    break;

                default:
                    return LDAP_OTHER;
            }

            *perms = p;

            return LDAP_SUCCESS;
        }
    }

    return LDAP_OTHER;
}
#endif /* LDAP_PF_LOCAL || SLAP_X_LISTENER_MOD */

void
lload_listener_free( LloadListener *l )
{
    LloadListenerSocket *next, *ls = l->sl_sockets;

    for ( ; ls; ls = next ) {
        next = ls->ls_next;

        if ( ls->listener ) {
            evconnlistener_free( ls->listener );
        }

#ifdef LDAP_PF_LOCAL
        if ( ls->ls_sa.sa_addr.sa_family == AF_LOCAL ) {
            unlink( ls->ls_sa.sa_un_addr.sun_path );
        }
#endif /* LDAP_PF_LOCAL */
        lloadd_close( ls->ls_sd );

        if ( ls->ls_name.bv_val ) {
            ber_memfree( ls->ls_name.bv_val );
        }
        ch_free( ls );
    }

    if ( l->sl_url.bv_val ) {
        ber_memfree( l->sl_url.bv_val );
    }
    ch_free( l );
}

static int
lload_get_listener_addresses(
        LloadListener *l,
        LDAPURLDesc *lud,
        LloadListenerSocket **lsp )
{
    LloadListenerSocket **lsp_orig = lsp, *ls = NULL;
    Sockaddr *sa;
    char ebuf[LDAP_IPADDRLEN];
    struct berval namebv = BER_BVC(ebuf);
    char *host = lud->lud_host;
    int proto = ldap_pvt_url_scheme2proto( lud->lud_scheme );

    if ( proto == LDAP_PROTO_IPC ) {
        struct sockaddr_un sun;
#ifdef LDAP_PF_LOCAL
        if ( !host || !*host ) {
            host = LDAPI_SOCK;
        }

        if ( strlen( host ) > ( sizeof(sun.sun_path) - 1 ) ) {
            Debug( LDAP_DEBUG_ANY, "lload_get_listener_addresses: "
                    "domain socket path (%s) too long in URL\n",
                    host );
            return -1;
        }

        *lsp = ls = ch_calloc( 1, sizeof(LloadListenerSocket) );
        ls->ls_lr = l;
        ls->ls_sd = AC_SOCKET_INVALID;

        sa = &ls->ls_sa;
        ((struct sockaddr *)sa)->sa_family = AF_LOCAL;
        strcpy( ((struct sockaddr_un *)sa)->sun_path, host );
        ldap_pvt_sockaddrstr( sa, &namebv );
        ber_dupbv( &ls->ls_name, &namebv );

        return 0;
#else /* ! LDAP_PF_LOCAL */

        Debug( LDAP_DEBUG_ANY, "lload_get_listener_addresses: "
                "URL scheme not supported: %s\n",
                l->sl_url.bv_val );
        return -1;
#endif /* ! LDAP_PF_LOCAL */
    }

    if ( !host || !*host || strcmp( host, "*" ) == 0 ) {
        host = NULL;
    }

    {
#ifdef HAVE_GETADDRINFO
        struct addrinfo hints, *res, *sai;
        int err;
        char serv[7];

        memset( &hints, '\0', sizeof(hints) );
        hints.ai_flags = AI_PASSIVE;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_family = slap_inet4or6;
        snprintf( serv, sizeof(serv), "%d", lud->lud_port );

        if ( (err = getaddrinfo( host, serv, &hints, &res )) ) {
            Debug( LDAP_DEBUG_ANY, "lload_get_listener_addresses: "
                    "getaddrinfo() failed: %s\n",
                    AC_GAI_STRERROR(err) );
            return -1;
        }

        for ( sai = res; sai; sai = sai->ai_next ) {
            if ( sai->ai_addr == NULL ) {
                Debug( LDAP_DEBUG_ANY, "lload_get_listener_addresses: "
                        "getaddrinfo ai_addr is NULL?\n" );
                freeaddrinfo( res );
                return -1;
            }

            ls = ch_calloc( 1, sizeof(LloadListenerSocket) );
            ls->ls_lr = l;
            ls->ls_sd = AC_SOCKET_INVALID;
            sa = &ls->ls_sa;

            switch ( sai->ai_family ) {
#ifdef LDAP_PF_INET6
                case AF_INET6:
                    *(struct sockaddr_in6 *)sa =
                        *((struct sockaddr_in6 *)sai->ai_addr);
                    break;
#endif /* LDAP_PF_INET6 */
                case AF_INET:
                    *(struct sockaddr_in *)sa =
                        *((struct sockaddr_in *)sai->ai_addr);
                    break;
                default:
                    /* We don't know how to use this one, skip */
                    goto skip;
            }
            ((struct sockaddr *)sa)->sa_family = sai->ai_family;
            ldap_pvt_sockaddrstr( sa, &namebv );
            ber_dupbv( &ls->ls_name, &namebv );

            *lsp = ls;
            lsp = &ls->ls_next;
        }

        freeaddrinfo( res );

#else /* ! HAVE_GETADDRINFO */
        int i = 0;
        struct in_addr in;
        struct hostent *he = NULL;
        struct sockaddr_in *sin;

        if ( host == NULL ) {
            in.s_addr = htonl( INADDR_ANY );

        } else if ( !inet_aton( host, &in ) ) {
            he = gethostbyname( host );
            if ( he == NULL ) {
                Debug( LDAP_DEBUG_ANY, "lload_get_listener_addresses: "
                        "invalid host %s\n",
                        host );
                return -1;
            }
        }

        do {
            *lsp = ls = ch_calloc( 1, sizeof(LloadListenerSocket) );
            ls->ls_lr = l;

            sin = (struct sockaddr_in *)&ls->ls_sa;
            sin->sa_family = AF_INET;
            sin->sin_port = htons( lud->lud_port );

            AC_MEMCPY( &sin->sin_addr,
                    he ? (struct in_addr *)he->h_addr_list[i] : &in,
                    sizeof(struct in_addr) );

            ldap_pvt_sockaddrstr( (Sockaddr *)sin, &namebv );
            ber_dupbv( &ls->ls_name, &namebv );
            i++;
        } while ( he && he->h_addr_list[i] );
#endif /* ! HAVE_GETADDRINFO */
    }

    return !ls;

skip:
    ls = *lsp_orig;
    while ( ls ) {
        LloadListenerSocket *next = ls->ls_next;
        ch_free( ls );
        ls = next;
    }
    return -1;
}

LloadListener *
lload_configure_listener(
        const char *url,
        LDAPURLDesc *lud )
{
    LloadListener *l;
    LloadListenerSocket *ls, *next, **prev;
    char ebuf[LDAP_IPADDRLEN];
    struct berval namebv = BER_BVC(ebuf);
    int socktype = SOCK_STREAM; /* default to COTS */
    int addrlen = 0;
    int tmp, rc;

    assert( url );
    assert( lud );

    l = ch_calloc( 1, sizeof(LloadListener) );

    if ( !lud->lud_port ) lud->lud_port = LDAP_PORT;

#ifndef HAVE_TLS
    if ( ldap_pvt_url_scheme2tls( lud->lud_scheme ) ) {
        Debug( LDAP_DEBUG_ANY, "lload_configure_listener: "
                "TLS not supported (%s)\n",
                url );
        ldap_free_urldesc( lud );
        return NULL;
    }

#else /* HAVE_TLS */
    l->sl_is_tls = ldap_pvt_url_scheme2tls( lud->lud_scheme );
#endif /* HAVE_TLS */

#if defined(LDAP_PF_LOCAL) || defined(SLAP_X_LISTENER_MOD)
    if ( lud->lud_exts ) {
        if ( get_url_perms( lud->lud_exts, &l->sl_perms ) ) {
            ldap_free_urldesc( lud );
            return NULL;
        }
    } else {
        l->sl_perms = S_IRWXU | S_IRWXO;
    }
#endif /* LDAP_PF_LOCAL || SLAP_X_LISTENER_MOD */

    l->sl_is_proxied = ldap_pvt_url_scheme2proxied( lud->lud_scheme );

    if ( lload_get_listener_addresses( l, lud, &l->sl_sockets ) ) {
        ldap_free_urldesc( lud );
        return NULL;
    }
    ldap_free_urldesc( lud );

    for ( ls = l->sl_sockets, prev = &l->sl_sockets; ls; ls = next ) {
        struct sockaddr *sa = (struct sockaddr *)&ls->ls_sa;
        ber_socket_t s;
        char *af;

        next = ls->ls_next;
        switch ( sa->sa_family ) {
            case AF_INET:
                af = "IPv4";
                break;
#ifdef LDAP_PF_INET6
            case AF_INET6:
                af = "IPv6";
                break;
#endif /* LDAP_PF_INET6 */
#ifdef LDAP_PF_LOCAL
            case AF_LOCAL:
                af = "Local";
                break;
#endif /* LDAP_PF_LOCAL */
            default:
                Debug( LDAP_DEBUG_ANY, "lload_configure_listener: "
                        "unsupported address family (%d)\n",
                        (int)sa->sa_family );
                goto skip;
        }

#ifdef BALANCER_MODULE
        if ( !(slapMode & SLAP_SERVER_MODE) ) {
            /* This is as much validation as we can (safely) do short of proper
             * startup */
            continue;
        }
#endif

        s = socket( sa->sa_family, socktype, 0 );
        if ( s == AC_SOCKET_INVALID ) {
            int err = sock_errno();
            Debug( LDAP_DEBUG_ANY, "lload_configure_listener: "
                    "%s socket() failed errno=%d (%s)\n",
                    af, err, sock_errstr( err, ebuf, sizeof(ebuf) ) );
            goto skip;
        }
        ber_pvt_socket_set_nonblock( s, 1 );
        ls->ls_sd = s;

#ifdef LDAP_PF_LOCAL
        if ( sa->sa_family == AF_LOCAL ) {
            unlink( ((struct sockaddr_un *)sa)->sun_path );
        } else
#endif /* LDAP_PF_LOCAL */
        {
#ifdef SO_REUSEADDR
            /* enable address reuse */
            tmp = 1;
            rc = setsockopt(
                    s, SOL_SOCKET, SO_REUSEADDR, (char *)&tmp, sizeof(tmp) );
            if ( rc == AC_SOCKET_ERROR ) {
                int err = sock_errno();
                Debug( LDAP_DEBUG_ANY, "lload_configure_listener(%ld): "
                        "setsockopt(SO_REUSEADDR) failed errno=%d (%s)\n",
                        (long)s, err, sock_errstr( err, ebuf, sizeof(ebuf) ) );
            }
#endif /* SO_REUSEADDR */
        }

        switch ( sa->sa_family ) {
            case AF_INET:
                addrlen = sizeof(struct sockaddr_in);
                break;
#ifdef LDAP_PF_INET6
            case AF_INET6:
#ifdef IPV6_V6ONLY
                /* Try to use IPv6 sockets for IPv6 only */
                tmp = 1;
                rc = setsockopt( s, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&tmp,
                        sizeof(tmp) );
                if ( rc == AC_SOCKET_ERROR ) {
                    int err = sock_errno();
                    Debug( LDAP_DEBUG_ANY, "lload_configure_listener(%ld): "
                            "setsockopt(IPV6_V6ONLY) failed errno=%d (%s)\n",
                            (long)s, err,
                            sock_errstr( err, ebuf, sizeof(ebuf) ) );
                }
#endif /* IPV6_V6ONLY */
                addrlen = sizeof(struct sockaddr_in6);
                break;
#endif /* LDAP_PF_INET6 */

#ifdef LDAP_PF_LOCAL
            case AF_LOCAL:
#ifdef LOCAL_CREDS
            {
                int one = 1;
                setsockopt( s, 0, LOCAL_CREDS, &one, sizeof(one) );
            }
#endif /* LOCAL_CREDS */

                addrlen = sizeof(struct sockaddr_un);
                break;
#endif /* LDAP_PF_LOCAL */
        }

#ifdef LDAP_PF_LOCAL
        /* create socket with all permissions set for those systems
         * that honor permissions on sockets (e.g. Linux); typically,
         * only write is required.  To exploit filesystem permissions,
         * place the socket in a directory and use directory's
         * permissions.  Need write perms to the directory to
         * create/unlink the socket; likely need exec perms to access
         * the socket (ITS#4709) */
        {
            mode_t old_umask = 0;

            if ( sa->sa_family == AF_LOCAL ) {
                old_umask = umask( 0 );
            }
#endif /* LDAP_PF_LOCAL */
            rc = bind( s, sa, addrlen );
#ifdef LDAP_PF_LOCAL
            if ( old_umask != 0 ) {
                umask( old_umask );
            }
        }
#endif /* LDAP_PF_LOCAL */
        if ( rc ) {
            int err = sock_errno();
            Debug( LDAP_DEBUG_ANY, "lload_configure_listener: "
                    "bind(%ld) failed errno=%d (%s)\n",
                    (long)s, err, sock_errstr( err, ebuf, sizeof(ebuf) ) );
            tcp_close( s );
            ls->ls_sd = AC_SOCKET_INVALID;
            goto skip;
        }

        prev = &ls->ls_next;
        continue;
skip:
        ber_memfree( ls->ls_name.bv_val );
        ch_free( ls );
        *prev = next;
    }

    if ( !l->sl_sockets ) {
        Debug( LDAP_DEBUG_ANY, "lload_configure_listener: "
                "failed on %s\n",
                url );
        return NULL;
    }
    ber_str2bv( url, 0, 1, &l->sl_url );

    Debug( LDAP_DEBUG_TRACE, "lload_configure_listener: "
            "listener initialized %s\n",
            l->sl_url.bv_val );

    return l;
}

int lloadd_inited = 0;

static void
listener_error_cb( struct evconnlistener *lev, void *arg )
{
    LloadListenerSocket *ls = arg;
    int err = EVUTIL_SOCKET_ERROR();

    assert( ls->listener == lev );
    if (
#ifdef EMFILE
            err == EMFILE ||
#endif /* EMFILE */
#ifdef ENFILE
            err == ENFILE ||
#endif /* ENFILE */
            0 ) {
        ldap_pvt_thread_mutex_lock( &lload_daemon[0].sd_mutex );
        emfile++;
        /* Stop listening until an existing session closes */
        ls->ls_mute = 1;
        evconnlistener_disable( lev );
        ldap_pvt_thread_mutex_unlock( &lload_daemon[0].sd_mutex );
        Debug( LDAP_DEBUG_ANY, "listener_error_cb: "
                "too many open files, cannot accept new connections on "
                "url=%s\n",
                ls->ls_lr->sl_url.bv_val );
    } else {
        char ebuf[128];
        Debug( LDAP_DEBUG_ANY, "listener_error_cb: "
                "received an error on a listener, shutting down: '%s'\n",
                sock_errstr( err, ebuf, sizeof(ebuf) ) );
        event_base_loopexit( ls->base, NULL );
    }
}

int
lloadd_daemon_destroy( void )
{
    epoch_shutdown();
    if ( lloadd_inited ) {
        int i;

        for ( i = 0; i < lload_daemon_threads; i++ ) {
            ldap_pvt_thread_mutex_destroy( &lload_daemon[i].sd_mutex );
            if ( lload_daemon[i].wakeup_event ) {
                event_free( lload_daemon[i].wakeup_event );
            }
            if ( lload_daemon[i].base ) {
                event_base_free( lload_daemon[i].base );
            }
        }

        event_free( lload_stats_event );
        event_free( lload_timeout_event );

        event_base_free( daemon_base );
        daemon_base = NULL;

        lloadd_inited = 0;
#ifdef HAVE_TCPD
        ldap_pvt_thread_mutex_destroy( &sd_tcpd_mutex );
#endif /* TCP Wrappers */
    }

    return 0;
}

static void
destroy_listeners( void )
{
    LloadListener *l, **ll = lload_listeners;

    if ( ll == NULL ) return;

    ldap_pvt_thread_join( listener_tid, (void *)NULL );

    while ( (l = *ll++) != NULL ) {
        lload_listener_free( l );
    }

    ch_free( lload_listeners );
    lload_listeners = NULL;

    if ( listener_base ) {
        event_base_free( listener_base );
    }
}

static void
lload_listener(
        struct evconnlistener *listener,
        ber_socket_t s,
        struct sockaddr *a,
        int len,
        void *arg )
{
    LloadListenerSocket *ls = arg;
    LloadListener *l = ls->ls_lr;
    LloadConnection *c;
    Sockaddr *from = (Sockaddr *)a;
    char peername[LDAP_IPADDRLEN];
    struct berval peerbv = BER_BVC(peername);
    int cflag;
    int tid = DAEMON_ID(s);
    char ebuf[128];

    peername[0] = '\0';

    Debug( LDAP_DEBUG_TRACE, ">>> lload_listener(%s)\n", l->sl_url.bv_val );
    Debug( LDAP_DEBUG_CONNS, "lload_listener: "
            "listen=%ld, new connection fd=%ld\n",
            (long)ls->ls_sd, (long)s );

#if defined(SO_KEEPALIVE) || defined(TCP_NODELAY)
#ifdef LDAP_PF_LOCAL
    /* for IPv4 and IPv6 sockets only */
    if ( from->sa_addr.sa_family != AF_LOCAL )
#endif /* LDAP_PF_LOCAL */
    {
        int rc;
        int tmp;
#ifdef SO_KEEPALIVE
        /* enable keep alives */
        tmp = 1;
        rc = setsockopt(
                s, SOL_SOCKET, SO_KEEPALIVE, (char *)&tmp, sizeof(tmp) );
        if ( rc == AC_SOCKET_ERROR ) {
            int err = sock_errno();
            Debug( LDAP_DEBUG_ANY, "lload_listener(%ld): "
                    "setsockopt(SO_KEEPALIVE) failed errno=%d (%s)\n",
                    (long)s, err, sock_errstr( err, ebuf, sizeof(ebuf) ) );
        }
#endif /* SO_KEEPALIVE */
#ifdef TCP_NODELAY
        /* enable no delay */
        tmp = 1;
        rc = setsockopt(
                s, IPPROTO_TCP, TCP_NODELAY, (char *)&tmp, sizeof(tmp) );
        if ( rc == AC_SOCKET_ERROR ) {
            int err = sock_errno();
            Debug( LDAP_DEBUG_ANY, "lload_listener(%ld): "
                    "setsockopt(TCP_NODELAY) failed errno=%d (%s)\n",
                    (long)s, err, sock_errstr( err, ebuf, sizeof(ebuf) ) );
        }
#endif /* TCP_NODELAY */
    }
#endif /* SO_KEEPALIVE || TCP_NODELAY */

    if ( l->sl_is_proxied ) {
        if ( !proxyp( s, from ) ) {
            Debug( LDAP_DEBUG_ANY, "lload_listener: "
                    "proxyp(%ld) failed\n",
                    (long)s );
            lloadd_close( s );
            return;
        }
    }

    cflag = 0;
    switch ( from->sa_addr.sa_family ) {
#ifdef LDAP_PF_LOCAL
        case AF_LOCAL:
            cflag |= CONN_IS_IPC;

            /* apparently accept doesn't fill the sun_path member, use
             * listener name */
            peerbv = ls->ls_name;
            break;
#endif /* LDAP_PF_LOCAL */

#ifdef LDAP_PF_INET6
        case AF_INET6:
#endif /* LDAP_PF_INET6 */
        case AF_INET:
            ldap_pvt_sockaddrstr( from, &peerbv );
            break;

        default:
            lloadd_close( s );
            return;
    }

#ifdef HAVE_TLS
    if ( l->sl_is_tls ) cflag |= CONN_IS_TLS;
#endif
    c = client_init( s, ls, &peerbv, lload_daemon[tid].base, cflag );

    if ( !c ) {
        Debug( LDAP_DEBUG_ANY, "lload_listener: "
                "client_init(%ld, %s, %s) failed\n",
                (long)s, peername, ls->ls_name.bv_val );
        lloadd_close( s );
    }

    return;
}

static int
lload_sockets_activate( LloadListener *l )
{
    LloadListenerSocket *ls;
    char ebuf[128];
    struct evconnlistener *listener;
    int rc;

    for ( ls = l->sl_sockets; ls; ls = ls->ls_next ) {
#ifdef LDAP_TCP_BUFFER
        /* FIXME: TCP-only! */
        int origsize, size, realsize;
        socklen_t optlen;

        size = 0;
        if ( l->sl_tcp_rmem > 0 ) {
            size = l->sl_tcp_rmem;
        } else if ( slapd_tcp_rmem > 0 ) {
            size = slapd_tcp_rmem;
        }

        if ( size > 0 ) {
            optlen = sizeof(origsize);
            rc = getsockopt( ls->ls_sd, SOL_SOCKET,
                    SO_RCVBUF, (void *)&origsize, &optlen );

            if ( rc ) {
                int err = sock_errno();
                Debug( LDAP_DEBUG_ANY, "lload_sockets_activate: "
                        "getsockopt(SO_RCVBUF) failed errno=%d (%s)\n",
                        err, AC_STRERROR_R( err, ebuf, sizeof(ebuf) ) );
            }

            optlen = sizeof(size);
            rc = setsockopt( ls->ls_sd, SOL_SOCKET,
                    SO_RCVBUF, (const void *)&size, optlen );

            if ( rc ) {
                int err = sock_errno();
                Debug( LDAP_DEBUG_ANY, "lload_sockets_activate: "
                        "setsockopt(SO_RCVBUF) failed errno=%d (%s)\n",
                        err, sock_errstr( err, ebuf, sizeof(ebuf) ) );
            }

            optlen = sizeof(realsize);
            rc = getsockopt( ls->ls_sd, SOL_SOCKET,
                    SO_RCVBUF, (void *)&realsize, &optlen );

            if ( rc ) {
                int err = sock_errno();
                Debug( LDAP_DEBUG_ANY, "lload_sockets_activate: "
                        "getsockopt(SO_RCVBUF) failed errno=%d (%s)\n",
                        err, sock_errstr( err, ebuf, sizeof(ebuf) ) );
            }

            Debug( LDAP_DEBUG_ANY, "lload_sockets_activate: "
                    "url=%s RCVBUF original size=%d requested "
                    "size=%d real size=%d\n",
                    l->sl_url.bv_val, origsize, size, realsize );
        }

        size = 0;
        if ( l->sl_tcp_wmem > 0 ) {
            size = l->sl_tcp_wmem;
        } else if ( slapd_tcp_wmem > 0 ) {
            size = slapd_tcp_wmem;
        }

        if ( size > 0 ) {
            optlen = sizeof(origsize);
            rc = getsockopt( ls->ls_sd, SOL_SOCKET,
                    SO_SNDBUF, (void *)&origsize, &optlen );

            if ( rc ) {
                int err = sock_errno();
                Debug( LDAP_DEBUG_ANY, "lload_sockets_activate: "
                        "getsockopt(SO_SNDBUF) failed errno=%d (%s)\n",
                        err, sock_errstr( err, ebuf, sizeof(ebuf) ) );
            }

            optlen = sizeof(size);
            rc = setsockopt( ls->ls_sd, SOL_SOCKET,
                    SO_SNDBUF, (const void *)&size, optlen );

            if ( rc ) {
                int err = sock_errno();
                Debug( LDAP_DEBUG_ANY, "lload_sockets_activate: "
                        "setsockopt(SO_SNDBUF) failed errno=%d (%s)\n",
                        err, sock_errstr( err, ebuf, sizeof(ebuf) ) );
            }

            optlen = sizeof(realsize);
            rc = getsockopt( ls->ls_sd, SOL_SOCKET,
                    SO_SNDBUF, (void *)&realsize, &optlen );

            if ( rc ) {
                int err = sock_errno();
                Debug( LDAP_DEBUG_ANY, "lload_sockets_activate: "
                        "getsockopt(SO_SNDBUF) failed errno=%d (%s)\n",
                        err, sock_errstr( err, ebuf, sizeof(ebuf) ) );
            }

            Debug( LDAP_DEBUG_ANY, "lload_sockets_activate: "
                    "url=%s SNDBUF original size=%d requested "
                    "size=%d real size=%d\n",
                    l->sl_url.bv_val, origsize, size, realsize );
        }
#endif /* LDAP_TCP_BUFFER */

        listener = evconnlistener_new( listener_base, lload_listener, ls,
                LEV_OPT_THREADSAFE|LEV_OPT_DEFERRED_ACCEPT,
                SLAPD_LISTEN_BACKLOG, ls->ls_sd );
        if ( !listener ) {
            int err = sock_errno();

#ifdef LDAP_PF_INET6
            /*
             * If error is EADDRINUSE, we are trying to listen to INADDR_ANY and
             * we are already listening to in6addr_any, then we want to ignore
             * this and continue.
             */
            if ( err == EADDRINUSE ) {
                LloadListenerSocket *ls2 = l->sl_sockets;
                struct sockaddr_in sa = ls->ls_sa.sa_in_addr;
                struct sockaddr_in6 sa6;

                if ( sa.sin_family == AF_INET &&
                        sa.sin_addr.s_addr == htonl( INADDR_ANY ) ) {
                    for ( ; ls2 != ls; ls2 = ls2->ls_next ) {
                        sa6 = ls2->ls_sa.sa_in6_addr;
                        if ( sa6.sin6_family == AF_INET6 &&
                                !memcmp( &sa6.sin6_addr, &in6addr_any,
                                    sizeof(struct in6_addr) ) ) {
                            break;
                        }
                    }

                    if ( ls2 != ls ) {
                        /* We are already listening to in6addr_any */
                        Debug( LDAP_DEBUG_CONNS, "lload_sockets_activate: "
                                "Attempt to listen to 0.0.0.0 failed, "
                                "already listening on ::, assuming IPv4 "
                                "included\n" );

                        for ( ; ls2->ls_next != ls; ls2 = ls2->ls_next )
                            /* scroll to ls's prev */;

                        ls2->ls_next = ls->ls_next;
                        lloadd_close( ls->ls_sd );
                        ber_memfree( ls->ls_name.bv_val );
                        ch_free( ls );
                        continue;
                    }
                }
            }
#endif /* LDAP_PF_INET6 */
            Debug( LDAP_DEBUG_ANY, "lload_sockets_activate: "
                    "listen(%s, " LDAP_XSTRING(SLAPD_LISTEN_BACKLOG)
                    ") failed errno=%d (%s)\n",
                    l->sl_url.bv_val, err,
                    sock_errstr( err, ebuf, sizeof(ebuf) ) );
            return -1;
        }

        evconnlistener_set_error_cb( listener, listener_error_cb );
        ls->base = listener_base;
        ls->listener = listener;
    }

    return 0;
}

int
lload_open_new_listener( LloadListener *l )
{
    int rc, i;

    /* If we started up already, also activate it */
    if ( lloadd_inited && (rc = lload_sockets_activate( l )) ) {
        return rc;
    }

    for ( i = 0; lload_listeners && lload_listeners[i] != NULL;
            i++ ) /* count */
        ;

    lload_listeners = ch_realloc(
            lload_listeners, ( i + 2 ) * sizeof(LloadListener *) );
    lload_listeners[i] = l;
    lload_listeners[i+1] = NULL;

    return 0;
}

int
lloadd_listeners_init( const char *urls )
{
    int i;
    char **u;

    Debug( LDAP_DEBUG_ARGS, "lloadd_listeners_init: %s\n",
            urls ? urls : "<null>" );

#ifdef HAVE_TCPD
    ldap_pvt_thread_mutex_init( &sd_tcpd_mutex );
#endif /* TCP Wrappers */

    if ( urls == NULL ) urls = "ldap:///";

    u = ldap_str2charray( urls, " " );

    if ( u == NULL || u[0] == NULL ) {
        Debug( LDAP_DEBUG_ANY, "lloadd_listeners_init: "
                "no urls (%s) provided\n",
                urls );
        if ( u ) ldap_charray_free( u );
        return -1;
    }

    for ( i = 0; u[i] != NULL; i++ ) {
        Debug( LDAP_DEBUG_TRACE, "lloadd_listeners_init: "
                "listen on %s\n",
                u[i] );
    }

    Debug( LDAP_DEBUG_TRACE, "lloadd_listeners_init: "
            "%d listeners to open...\n",
            i );
    lload_listeners = ch_malloc( ( i + 1 ) * sizeof(LloadListener *) );

    for ( i = 0; u[i]; i++ ) {
        LDAPURLDesc *lud;

        if ( ldap_url_parse_ext( u[i], &lud, LDAP_PVT_URL_PARSE_DEF_PORT ) ) {
            Debug( LDAP_DEBUG_ANY, "lloadd_listeners_init: "
                    "could not parse url %s\n",
                    u[i] );
            goto fail;
        }

        if ( !(lload_listeners[i] = lload_configure_listener( u[i], lud )) ) {
            goto fail;
        }
    }
    lload_listeners[i] = NULL;

    ldap_charray_free( u );
    return 0;

fail:
    ldap_charray_free( u );

    for ( ; i >= 0; i-- ) {
        if ( lload_listeners[i] ) {
            lload_listener_free( lload_listeners[i] );
        }
    }
    ch_free( lload_listeners );
    lload_listeners = NULL;
    return -1;
}

static void *
lload_listener_thread( void *ctx )
{
    /* ITS#9984 Survive the listeners being paused if we run out of fds */
    int rc = event_base_loop( listener_base, EVLOOP_NO_EXIT_ON_EMPTY );
    Debug( LDAP_DEBUG_ANY, "lload_listener_thread: "
            "event loop finished: rc=%d\n",
            rc );

    return (void *)NULL;
}

static int
lload_listener_activate( void )
{
    int i, rc;

    listener_base = event_base_new();
    if ( !listener_base ) return -1;

    for ( i = 0; lload_listeners[i] != NULL; i++ ) {
        LloadListener *l = lload_listeners[i];

        if ( (rc = lload_sockets_activate( l )) ) {
            return rc;
        }
    }

    rc = ldap_pvt_thread_create(
            &listener_tid, 0, lload_listener_thread, NULL );

    if ( rc != 0 ) {
        Debug( LDAP_DEBUG_ANY, "lload_listener_activate(): "
                "could not start listener thread (%d)\n",
                rc );
    }
    return rc;
}

void
listeners_reactivate( void )
{
    int i;

    ldap_pvt_thread_mutex_lock( &lload_daemon[0].sd_mutex );
    for ( i = 0; emfile && lload_listeners[i] != NULL; i++ ) {
        LloadListener *l = lload_listeners[i];
        LloadListenerSocket *ls = l->sl_sockets;

        for ( ; emfile && ls; ls = ls->ls_next ) {
            if ( ls->ls_mute ) {
                emfile--;
                evconnlistener_enable( ls->listener );
                ls->ls_mute = 0;
                Debug( LDAP_DEBUG_CONNS, "listeners_reactivate: "
                        "reactivated listener url=%s\n",
                        l->sl_url.bv_val );
            }
        }
    }
    if ( emfile && lload_listeners[i] == NULL ) {
        /* Walked the entire list without enabling anything; emfile
         * counter is stale. Reset it. */
        emfile = 0;
    }
    ldap_pvt_thread_mutex_unlock( &lload_daemon[0].sd_mutex );
}

static void *
lloadd_io_task( void *ptr )
{
    int rc;
    int tid = (ldap_pvt_thread_t *)ptr - daemon_tid;
    struct event_base *base = lload_daemon[tid].base;
    struct event *event;

    event = event_new( base, -1, EV_WRITE, daemon_wakeup_cb, ptr );
    if ( !event ) {
        Debug( LDAP_DEBUG_ANY, "lloadd_io_task: "
                "failed to set up the wakeup event\n" );
        return (void *)-1;
    }
    event_add( event, NULL );
    lload_daemon[tid].wakeup_event = event;

    /* run */
    rc = event_base_dispatch( base );
    Debug( LDAP_DEBUG_ANY, "lloadd_io_task: "
            "Daemon %d, event loop finished: rc=%d\n",
            tid, rc );

    if ( !slapd_gentle_shutdown ) {
        slapd_abrupt_shutdown = 1;
    }

    return NULL;
}

int
lloadd_daemon( struct event_base *daemon_base )
{
    int i, rc;
    LloadTier *tier;
    struct event_base *base;
    struct event *event;
    struct timeval second = { 1, 0 };

    assert( daemon_base != NULL );

    dnsbase = evdns_base_new( daemon_base, 0 );
    if ( !dnsbase ) {
        Debug( LDAP_DEBUG_ANY, "lloadd startup: "
                "failed to set up for async name resolution\n" );
        return -1;
    }

    /*
     * ITS#10070: Allow both operation without working DNS (test environments)
     * and e.g. containers that don't have a /etc/resolv.conf but do have a
     * server listening on 127.0.0.1 which is the default.
     */
    (void)evdns_base_resolv_conf_parse( dnsbase,
            DNS_OPTION_NAMESERVERS|DNS_OPTION_HOSTSFILE,
            lload_resolvconf_path );

    if ( lload_daemon_threads > SLAPD_MAX_DAEMON_THREADS )
        lload_daemon_threads = SLAPD_MAX_DAEMON_THREADS;

    daemon_tid =
            ch_malloc( lload_daemon_threads * sizeof(ldap_pvt_thread_t) );

    for ( i = 0; i < lload_daemon_threads; i++ ) {
        base = event_base_new();
        if ( !base ) {
            Debug( LDAP_DEBUG_ANY, "lloadd startup: "
                    "failed to acquire event base for an I/O thread\n" );
            return -1;
        }
        lload_daemon[i].base = base;

        ldap_pvt_thread_mutex_init( &lload_daemon[i].sd_mutex );
        /* threads that handle client and upstream sockets */
        rc = ldap_pvt_thread_create(
                &daemon_tid[i], 0, lloadd_io_task, &daemon_tid[i] );

        if ( rc != 0 ) {
            Debug( LDAP_DEBUG_ANY, "lloadd startup: "
                    "listener ldap_pvt_thread_create failed (%d)\n",
                    rc );
            return rc;
        }
    }

    if ( (rc = lload_listener_activate()) != 0 ) {
        return rc;
    }

    LDAP_STAILQ_FOREACH ( tier, &tiers, t_next ) {
        if ( tier->t_type.tier_startup( tier ) ) {
            return -1;
        }
    }

    event = event_new( daemon_base, -1, EV_TIMEOUT|EV_PERSIST,
            lload_tiers_update, NULL );
    if ( !event ) {
        Debug( LDAP_DEBUG_ANY, "lloadd: "
                "failed to allocate stats update event\n" );
        return -1;
    }
    lload_stats_event = event;
    event_add( event, &second );

    event = evtimer_new( daemon_base, operations_timeout, event_self_cbarg() );
    if ( !event ) {
        Debug( LDAP_DEBUG_ANY, "lloadd: "
                "failed to allocate timeout event\n" );
        return -1;
    }
    lload_timeout_event = event;

    /* TODO: should we just add it with any timeout and re-add when the timeout
     * changes? */
    if ( lload_timeout_api ) {
        event_add( event, lload_timeout_api );
    }

    checked_lock( &lload_wait_mutex );
    lloadd_inited = 1;
    ldap_pvt_thread_cond_signal( &lload_wait_cond );
    checked_unlock( &lload_wait_mutex );
#if !defined(BALANCER_MODULE) && defined(HAVE_SYSTEMD)
    rc = sd_notify( 1, "READY=1" );
    if ( rc < 0 ) {
        Debug( LDAP_DEBUG_ANY, "lloadd startup: "
            "systemd sd_notify failed (%d)\n", rc );
    }
#endif /* !BALANCER_MODULE && HAVE_SYSTEMD */

    rc = event_base_dispatch( daemon_base );
    Debug( LDAP_DEBUG_ANY, "lloadd shutdown: "
            "Main event loop finished: rc=%d\n",
            rc );

    /* shutdown */
    event_base_loopexit( listener_base, 0 );

    /* wait for the listener threads to complete */
    destroy_listeners();

    /* Mark upstream connections closing and prevent from opening new ones */
    lload_tiers_shutdown();

    /* Do the same for clients */
    clients_destroy( 1 );

    for ( i = 0; i < lload_daemon_threads; i++ ) {
        /*
         * https://github.com/libevent/libevent/issues/623
         * deleting the event doesn't notify the base, just activate it and
         * let it delete itself
         */
        event_active( lload_daemon[i].wakeup_event, EV_READ, 0 );
    }

    for ( i = 0; i < lload_daemon_threads; i++ ) {
        ldap_pvt_thread_join( daemon_tid[i], (void *)NULL );
    }

#ifndef BALANCER_MODULE
    if ( LogTest( LDAP_DEBUG_ANY ) ) {
        int t = ldap_pvt_thread_pool_backload( &connection_pool );
        Debug( LDAP_DEBUG_ANY, "lloadd shutdown: "
                "waiting for %d operations/tasks to finish\n",
                t );
    }
    ldap_pvt_thread_pool_close( &connection_pool, 1 );
#endif

    lload_tiers_destroy();
    clients_destroy( 0 );
    lload_bindconf_free( &bindconf );
    evdns_base_free( dnsbase, 0 );

    ch_free( daemon_tid );
    daemon_tid = NULL;

    lloadd_daemon_destroy();

    /* If we're a slapd module, let the thread that initiated the shut down
     * know we've finished */
    checked_lock( &lload_wait_mutex );
    ldap_pvt_thread_cond_signal( &lload_wait_cond );
    checked_unlock( &lload_wait_mutex );

    return 0;
}

static void
daemon_wakeup_cb( evutil_socket_t sig, short what, void *arg )
{
    int tid = (ldap_pvt_thread_t *)arg - daemon_tid;

    Debug( LDAP_DEBUG_TRACE, "daemon_wakeup_cb: "
            "Daemon thread %d woken up\n",
            tid );
    event_del( lload_daemon[tid].wakeup_event );
}

LloadChange lload_change = { .type = LLOAD_CHANGE_UNDEFINED };

#ifdef BALANCER_MODULE
int
backend_conn_cb( ldap_pvt_thread_start_t *start, void *startarg, void *arg )
{
    LloadConnection *c = startarg;
    LloadBackend *b = arg;

    if ( b == NULL || c->c_backend == b ) {
        CONNECTION_LOCK_DESTROY(c);
        return 1;
    }
    return 0;
}

#ifdef HAVE_TLS
int
client_tls_cb( ldap_pvt_thread_start_t *start, void *startarg, void *arg )
{
    LloadConnection *c = startarg;

    if ( c->c_destroy == client_destroy &&
            c->c_is_tls == LLOAD_TLS_ESTABLISHED ) {
        CONNECTION_LOCK_DESTROY(c);
        return 1;
    }
    return 0;
}
#endif /* HAVE_TLS */

static int
detach_linked_backend_cb( LloadConnection *client, LloadBackend *b )
{
    int rc = LDAP_SUCCESS;

    if ( client->c_backend != b ) {
        return rc;
    }

    Debug( LDAP_DEBUG_CONNS, "detach_linked_backend_cb: "
            "detaching backend '%s' from connid=%lu%s\n",
            b->b_name.bv_val, client->c_connid,
            client->c_restricted == LLOAD_OP_RESTRICTED_BACKEND ?
                " and closing the connection" :
                "" );

    /* We were approached from the connection list */
    assert( IS_ALIVE( client, c_refcnt ) );

    assert( client->c_restricted == LLOAD_OP_RESTRICTED_WRITE ||
            client->c_restricted == LLOAD_OP_RESTRICTED_BACKEND );
    if ( client->c_restricted == LLOAD_OP_RESTRICTED_BACKEND ) {
        int gentle = 1;
        CONNECTION_LOCK(client);
        rc = lload_connection_close( client, &gentle );
        CONNECTION_UNLOCK(client);
    }

    client->c_restricted = LLOAD_OP_NOT_RESTRICTED;
    client->c_restricted_at = 0;
    client->c_restricted_inflight = 0;

    return rc;
}

void
lload_handle_backend_invalidation( LloadChange *change )
{
    LloadBackend *b = change->target;
    LloadTier *tier = b->b_tier;

    assert( change->object == LLOAD_BACKEND );

    if ( change->type == LLOAD_CHANGE_ADD ) {
        BackendInfo *mi = backend_info( "monitor" );

        if ( mi ) {
            monitor_extra_t *mbe = mi->bi_extra;
            if ( mbe->is_configured() ) {
                lload_monitor_backend_init( mi, tier->t_monitor, b );
            }
        }

        if ( tier->t_type.tier_change ) {
            tier->t_type.tier_change( tier, change );
        }

        checked_lock( &b->b_mutex );
        backend_retry( b );
        checked_unlock( &b->b_mutex );
        return;
    } else if ( change->type == LLOAD_CHANGE_DEL ) {
        ldap_pvt_thread_pool_walk(
                &connection_pool, handle_pdus, backend_conn_cb, b );
        ldap_pvt_thread_pool_walk(
                &connection_pool, upstream_bind, backend_conn_cb, b );

        checked_lock( &clients_mutex );
        connections_walk(
                &clients_mutex, &clients,
                (CONNCB)detach_linked_backend_cb, b );
        checked_unlock( &clients_mutex );

        if ( tier->t_type.tier_change ) {
            tier->t_type.tier_change( tier, change );
        }
        lload_backend_destroy( b );
        return;
    }
    assert( change->type == LLOAD_CHANGE_MODIFY );

    /*
     * A change that can't be handled gracefully, terminate all connections and
     * start over.
     */
    if ( change->flags.backend & LLOAD_BACKEND_MOD_OTHER ) {
        ldap_pvt_thread_pool_walk(
                &connection_pool, handle_pdus, backend_conn_cb, b );
        ldap_pvt_thread_pool_walk(
                &connection_pool, upstream_bind, backend_conn_cb, b );
        checked_lock( &b->b_mutex );
        backend_reset( b, 0 );
        backend_retry( b );
        checked_unlock( &b->b_mutex );
        return;
    }

    /*
     * Handle changes to number of connections:
     * - a change might get the connection limit above the pool size:
     *   - consider closing (in order of priority?):
     *     - connections awaiting connect() completion
     *     - connections currently preparing
     *     - bind connections over limit (which is 0 if 'feature vc' is on
     *     - regular connections over limit
     * - below pool size
     *   - call backend_retry if there are no opening connections
     * - one pool size above and one below the configured size
     *   - still close the ones above limit, it should sort itself out
     *     the only issue is if a closing connection isn't guaranteed to do
     *     that at some point
     */
    if ( change->flags.backend & LLOAD_BACKEND_MOD_CONNS ) {
        int bind_requested = 0, need_close = 0, need_open = 0;
        LloadConnection *c;

        bind_requested =
#ifdef LDAP_API_FEATURE_VERIFY_CREDENTIALS
                (lload_features & LLOAD_FEATURE_VC) ? 0 :
#endif /* LDAP_API_FEATURE_VERIFY_CREDENTIALS */
                b->b_numbindconns;

        if ( b->b_bindavail > bind_requested ) {
            need_close += b->b_bindavail - bind_requested;
        } else if ( b->b_bindavail < bind_requested ) {
            need_open = 1;
        }

        if ( b->b_active > b->b_numconns ) {
            need_close += b->b_active - b->b_numconns;
        } else if ( b->b_active < b->b_numconns ) {
            need_open = 1;
        }

        if ( !need_open ) {
            need_close += b->b_opening;

            while ( !LDAP_LIST_EMPTY( &b->b_connecting ) ) {
                LloadPendingConnection *p = LDAP_LIST_FIRST( &b->b_connecting );

                LDAP_LIST_REMOVE( p, next );
                event_free( p->event );
                evutil_closesocket( p->fd );
                ch_free( p );
                b->b_opening--;
                need_close--;
            }
        }

        if ( need_close || !need_open ) {
            /* It might be too late to repurpose a preparing connection, just
             * close them all */
            while ( !LDAP_CIRCLEQ_EMPTY( &b->b_preparing ) ) {
                c = LDAP_CIRCLEQ_FIRST( &b->b_preparing );

                event_del( c->c_read_event );
                CONNECTION_LOCK_DESTROY(c);
                assert( c == NULL );
                b->b_opening--;
                need_close--;
            }
            if ( event_pending( b->b_retry_event, EV_TIMEOUT, NULL ) ) {
                event_del( b->b_retry_event );
                b->b_opening--;
            }
            assert( b->b_opening == 0 );
        }

        if ( b->b_bindavail > bind_requested ) {
            int diff = b->b_bindavail - bind_requested;

            assert( need_close >= diff );

            LDAP_CIRCLEQ_FOREACH ( c, &b->b_bindconns, c_next ) {
                int gentle = 1;

                lload_connection_close( c, &gentle );
                need_close--;
                diff--;
                if ( !diff ) {
                    break;
                }
            }
            assert( diff == 0 );
        }

        if ( b->b_active > b->b_numconns ) {
            int diff = b->b_active - b->b_numconns;

            assert( need_close >= diff );

            LDAP_CIRCLEQ_FOREACH ( c, &b->b_conns, c_next ) {
                int gentle = 1;

                lload_connection_close( c, &gentle );
                need_close--;
                diff--;
                if ( !diff ) {
                    break;
                }
            }
            assert( diff == 0 );
        }
        assert( need_close == 0 );

        if ( need_open ) {
            checked_lock( &b->b_mutex );
            backend_retry( b );
            checked_unlock( &b->b_mutex );
        }
    }
}

void
lload_handle_tier_invalidation( LloadChange *change )
{
    LloadTier *tier;

    assert( change->object == LLOAD_TIER );
    tier = change->target;

    if ( change->type == LLOAD_CHANGE_ADD ) {
        BackendInfo *mi = backend_info( "monitor" );

        if ( mi ) {
            monitor_extra_t *mbe = mi->bi_extra;
            if ( mbe->is_configured() ) {
                lload_monitor_tier_init( mi, tier );
            }
        }

        tier->t_type.tier_startup( tier );
        if ( LDAP_STAILQ_EMPTY( &tiers ) ) {
            LDAP_STAILQ_INSERT_HEAD( &tiers, tier, t_next );
        } else {
            LDAP_STAILQ_INSERT_TAIL( &tiers, tier, t_next );
        }
        return;
    } else if ( change->type == LLOAD_CHANGE_DEL ) {
        LDAP_STAILQ_REMOVE( &tiers, tier, LloadTier, t_next );
        tier->t_type.tier_reset( tier, 1 );
        tier->t_type.tier_destroy( tier );
        return;
    }
    assert( change->type == LLOAD_CHANGE_MODIFY );

    if ( tier->t_type.tier_change ) {
        tier->t_type.tier_change( tier, change );
    }
}

void
lload_handle_global_invalidation( LloadChange *change )
{
    assert( change->type == LLOAD_CHANGE_MODIFY );
    assert( change->object == LLOAD_DAEMON );

    if ( change->flags.daemon & LLOAD_DAEMON_MOD_THREADS ) {
        /* walk the task queue to remove any tasks belonging to us. */
        /* TODO: initiate a full module restart, everything will fall into
         * place at that point */
        ldap_pvt_thread_pool_walk(
                &connection_pool, handle_pdus, backend_conn_cb, NULL );
        ldap_pvt_thread_pool_walk(
                &connection_pool, upstream_bind, backend_conn_cb, NULL );
        assert(0);
        return;
    }

    if ( change->flags.daemon & LLOAD_DAEMON_MOD_FEATURES ) {
        lload_features_t feature_diff =
                lload_features ^ ( ~(uintptr_t)change->target );
        /* Feature change handling:
         * - VC (TODO):
         *   - on: terminate all bind connections
         *   - off: cancel all bind operations in progress, reopen bind connections
         * - ProxyAuthz:
         *   - on: nothing needed
         *   - off: clear c_auth/privileged on each client
         * - read pause (WIP):
         *   - nothing needed?
         */

        assert( change->target );
        if ( feature_diff & LLOAD_FEATURE_VC ) {
            assert(0);
            feature_diff &= ~LLOAD_FEATURE_VC;
        }
        if ( feature_diff & LLOAD_FEATURE_PAUSE ) {
            feature_diff &= ~LLOAD_FEATURE_PAUSE;
        }
        if ( feature_diff & LLOAD_FEATURE_PROXYAUTHZ ) {
            if ( !(lload_features & LLOAD_FEATURE_PROXYAUTHZ) ) {
                LloadConnection *c;
                /* We switched proxyauthz off */
                LDAP_CIRCLEQ_FOREACH ( c, &clients, c_next ) {
                    if ( !BER_BVISNULL( &c->c_auth ) ) {
                        ber_memfree( c->c_auth.bv_val );
                        BER_BVZERO( &c->c_auth );
                    }
                    if ( c->c_type == LLOAD_C_PRIVILEGED ) {
                        c->c_type = LLOAD_C_OPEN;
                    }
                }
            }
            feature_diff &= ~LLOAD_FEATURE_PROXYAUTHZ;
        }
        assert( !feature_diff );
    }

#ifdef HAVE_TLS
    if ( change->flags.daemon & LLOAD_DAEMON_MOD_TLS ) {
        /* terminate all clients with TLS set up */
        ldap_pvt_thread_pool_walk(
                &connection_pool, handle_pdus, client_tls_cb, NULL );
        if ( !LDAP_CIRCLEQ_EMPTY( &clients ) ) {
            LloadConnection *c = LDAP_CIRCLEQ_FIRST( &clients );
            unsigned long first_connid = c->c_connid;

            while ( c ) {
                LloadConnection *next =
                        LDAP_CIRCLEQ_LOOP_NEXT( &clients, c, c_next );
                if ( c->c_is_tls ) {
                    CONNECTION_LOCK_DESTROY(c);
                    assert( c == NULL );
                }
                c = next;
                if ( c->c_connid <= first_connid ) {
                    c = NULL;
                }
            }
        }
    }
#endif /* HAVE_TLS */

    if ( change->flags.daemon & LLOAD_DAEMON_MOD_BINDCONF ) {
        LloadConnection *c;

        /*
         * Only timeout changes can be handled gracefully, terminate all
         * connections and start over.
         */
        ldap_pvt_thread_pool_walk(
                &connection_pool, handle_pdus, backend_conn_cb, NULL );
        ldap_pvt_thread_pool_walk(
                &connection_pool, upstream_bind, backend_conn_cb, NULL );

        lload_tiers_reset( 0 );

        /* Reconsider the PRIVILEGED flag on all clients */
        LDAP_CIRCLEQ_FOREACH ( c, &clients, c_next ) {
            int privileged = ber_bvstrcasecmp( &c->c_auth, &lloadd_identity );

            /* We have just terminated all pending operations (even pins), there
             * should be no connections still binding/closing */
            assert( c->c_state == LLOAD_C_READY );

            c->c_type = privileged ? LLOAD_C_PRIVILEGED : LLOAD_C_OPEN;
        }
    }

    if ( change->flags.daemon & LLOAD_DAEMON_MOD_LISTENER ) {
        LloadListener **lp, *l;
        int i;

        /* Mark clients linked to the disappearing listeners closing */
        if ( !LDAP_CIRCLEQ_EMPTY( &clients ) ) {
            LloadConnection *c = LDAP_CIRCLEQ_FIRST( &clients );
            unsigned long first_connid = c->c_connid;

            while ( c ) {
                LloadConnection *next =
                    LDAP_CIRCLEQ_LOOP_NEXT( &clients, c, c_next );
                if ( c->c_listener && c->c_listener->ls_lr->sl_removed ) {
                    int gentle = 1;
                    c->c_listener = NULL;
                    lload_connection_close( c, &gentle );
                }
                c = next;
                if ( c->c_connid <= first_connid ) {
                    c = NULL;
                }
            }
        }

        /* Go through listeners that have been removed and dispose of them */
        assert( lload_listeners );
        lp = lload_listeners;

        for ( i = 0; lload_listeners[i]; i++ ) {
            l = lload_listeners[i];

            if ( l->sl_removed ) {
                lload_listener_free( l );
                continue;
            }
            *(lp++) = l;
        }
        *lp = NULL;
    }
}

int
lload_handle_invalidation( LloadChange *change )
{
    if ( (change->type == LLOAD_CHANGE_MODIFY) &&
            change->flags.generic == 0 ) {
        Debug( LDAP_DEBUG_ANY, "lload_handle_invalidation: "
                "a modify where apparently nothing changed\n" );
    }

    switch ( change->object ) {
        case LLOAD_BACKEND:
            lload_handle_backend_invalidation( change );
            break;
        case LLOAD_TIER:
            lload_handle_tier_invalidation( change );
            break;
        case LLOAD_DAEMON:
            lload_handle_global_invalidation( change );
            break;
        default:
            Debug( LDAP_DEBUG_ANY, "lload_handle_invalidation: "
                    "unrecognised change\n" );
            assert(0);
    }

    return LDAP_SUCCESS;
}

static void
lload_pause_event_cb( evutil_socket_t s, short what, void *arg )
{
    /*
     * We are pausing, signal the pausing thread we've finished and
     * wait until the thread pool resumes operation.
     *
     * Do this in lockstep with the pausing thread.
     */
    checked_lock( &lload_wait_mutex );
    ldap_pvt_thread_cond_signal( &lload_wait_cond );

    /* Now wait until we unpause, then we can resume operation */
    ldap_pvt_thread_cond_wait( &lload_pause_cond, &lload_wait_mutex );
    checked_unlock( &lload_wait_mutex );
}

/*
 * Signal the event base to terminate processing as soon as it can and wait for
 * lload_pause_event_cb to notify us this has happened.
 */
static int
lload_pause_base( struct event_base *base )
{
    int rc;

    checked_lock( &lload_wait_mutex );
    event_base_once( base, -1, EV_TIMEOUT, lload_pause_event_cb, base, NULL );
    rc = ldap_pvt_thread_cond_wait( &lload_wait_cond, &lload_wait_mutex );
    checked_unlock( &lload_wait_mutex );

    return rc;
}

void
lload_pause_server( void )
{
    LloadChange ch = { .type = LLOAD_CHANGE_UNDEFINED };
    int i;

    lload_pause_base( listener_base );
    lload_pause_base( daemon_base );

    for ( i = 0; i < lload_daemon_threads; i++ ) {
        lload_pause_base( lload_daemon[i].base );
    }

    lload_change = ch;
}

void
lload_unpause_server( void )
{
    if ( lload_change.type != LLOAD_CHANGE_UNDEFINED ) {
        lload_handle_invalidation( &lload_change );
    }

    /*
     * Make sure lloadd is completely ready to unpause by now:
     *
     * After the broadcast, we handle I/O and begin filling the thread pool, in
     * high load conditions, we might hit the pool limits and start processing
     * operations in the I/O threads (one PDU per socket at a time for fairness
     * sake) even before a pause has finished from slapd's point of view!
     *
     * When (max_pdus_per_cycle == 0) we don't use the pool for these at all and
     * most lload processing starts immediately making this even more prominent.
     */
    ldap_pvt_thread_cond_broadcast( &lload_pause_cond );
}
#endif /* BALANCER_MODULE */

void
lload_sig_shutdown( evutil_socket_t sig, short what, void *arg )
{
    struct event_base *daemon_base = arg;
    int save_errno = errno;
    int i;

    /*
     * If the NT Service Manager is controlling the server, we don't
     * want SIGBREAK to kill the server. For some strange reason,
     * SIGBREAK is generated when a user logs out.
     */

#if defined(HAVE_NT_SERVICE_MANAGER) && defined(SIGBREAK)
    if ( is_NT_Service && sig == SIGBREAK ) {
        /* empty */;
    } else
#endif /* HAVE_NT_SERVICE_MANAGER && SIGBREAK */
#ifdef SIGHUP
    if ( sig == SIGHUP && global_gentlehup && slapd_gentle_shutdown == 0 ) {
        slapd_gentle_shutdown = 1;
    } else
#endif /* SIGHUP */
    {
        slapd_shutdown = 1;
    }

    for ( i = 0; i < lload_daemon_threads; i++ ) {
        event_base_loopexit( lload_daemon[i].base, NULL );
    }
    event_base_loopexit( daemon_base, NULL );

    errno = save_errno;
}

struct event_base *
lload_get_base( ber_socket_t s )
{
    int tid = DAEMON_ID(s);
    return lload_daemon[tid].base;
}

LloadListener **
lloadd_get_listeners( void )
{
    return lload_listeners;
}

/* Reject all incoming requests */
void
lload_suspend_listeners( void )
{
    int i;
    for ( i = 0; lload_listeners[i]; i++ ) {
        LloadListenerSocket *ls = lload_listeners[i]->sl_sockets;

        for ( ; ls; ls = ls->ls_next ) {
            ls->ls_mute = 1;
            evconnlistener_disable( ls->listener );
            listen( ls->ls_sd, 0 );
        }
    }
}

/* Resume after a suspend */
void
lload_resume_listeners( void )
{
    int i;
    for ( i = 0; lload_listeners[i]; i++ ) {
        LloadListenerSocket *ls = lload_listeners[i]->sl_sockets;

        for ( ; ls; ls = ls->ls_next ) {
            ls->ls_mute = 0;
            listen( ls->ls_sd, SLAPD_LISTEN_BACKLOG );
            evconnlistener_enable( ls->listener );
        }
    }
}
