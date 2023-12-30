/* tls_mt.c - Handle tls/ssl using MbedTLS */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2010-2023 Belledonne Communications SARL.
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
 */

#include "portable.h"

#ifdef HAVE_MBEDTLS

#include "ldap_config.h"

#include <stdio.h>

#include <ac/stdlib.h>
#include <ac/errno.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/ctype.h>

#include "ldap-int.h"
#include "ldap-tls.h"

#include <mbedtls/ssl.h>
#include <mbedtls/oid.h>
#include <mbedtls/x509.h>
#include <mbedtls/version.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>

typedef struct tlsmt_ctx {
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ssl_config ssl_config;
	mbedtls_x509_crt own_cert;
	mbedtls_pk_context own_cert_key;
	mbedtls_x509_crt ca_chain;
	unsigned long verify_depth;
	int refcount;
#ifdef LDAP_R_COMPILE
	ldap_pvt_thread_mutex_t ref_mutex;
#endif
} tlsmt_ctx;

typedef struct tlsmt_session {
	mbedtls_ssl_context ssl_ctx;
	tlsmt_ctx *config;
} tlsmt_session;

#ifdef LDAP_R_COMPILE
static void tlsmt_thr_init( void )
{
}
#endif /* LDAP_R_COMPILE */

/*
 * Initialize TLS subsystem. Should be called only once.
 */
static int
tlsmt_init( void )
{
	return 0;
}

/*
 * Tear down the TLS subsystem. Should only be called once.
 */
static void
tlsmt_destroy( void )
{

}

static tls_ctx *
tlsmt_ctx_new( struct ldapoptions *lo )
{
	tlsmt_ctx *ctx;

	ctx = ber_memcalloc ( 1, sizeof (*ctx) );
	if ( ctx ) {
		int ret = 0;
		ctx->refcount = 1;
		mbedtls_entropy_init( &ctx->entropy );
		mbedtls_ctr_drbg_init( &ctx->ctr_drbg );
		if( ( ret = mbedtls_ctr_drbg_seed( &ctx->ctr_drbg, mbedtls_entropy_func, &ctx->entropy, NULL, 0 ) )   != 0 )
		{
			mbedtls_ctr_drbg_free( &ctx->ctr_drbg );
			mbedtls_entropy_free( &ctx->entropy );
			ber_memfree ( ctx );
			Debug1(LDAP_DEBUG_ANY, "Mbedtls can't init ctr_drbg: [-0x%x]. Unable to create tls context", -ret);
			return NULL;
		}
		mbedtls_ssl_config_init( &ctx->ssl_config );
		mbedtls_ssl_conf_rng( &ctx->ssl_config, mbedtls_ctr_drbg_random, &ctx->ctr_drbg);
		mbedtls_x509_crt_init( &ctx->own_cert );
		mbedtls_pk_init( &ctx->own_cert_key );
		mbedtls_x509_crt_init( &ctx->ca_chain );

#ifdef LDAP_R_COMPILE
		ldap_pvt_thread_mutex_init( &ctx->ref_mutex );
#endif
	}

	return (tls_ctx *)ctx;
}

static void
tlsmt_ctx_ref( tls_ctx *ctx )
{

	tlsmt_ctx *c = (tlsmt_ctx *)ctx;
	LDAP_MUTEX_LOCK( &c->ref_mutex );
	c->refcount++;
	LDAP_MUTEX_UNLOCK( &c->ref_mutex );
}

static void
tlsmt_ctx_free ( tls_ctx *ctx )
{

	tlsmt_ctx *c = (tlsmt_ctx *)ctx;
	int refcount;

	if ( !c ) return;

	LDAP_MUTEX_LOCK( &c->ref_mutex );
	refcount = --c->refcount;
	LDAP_MUTEX_UNLOCK( &c->ref_mutex );
	if ( refcount )
		return;

	mbedtls_ssl_config_free( &c->ssl_config );
	mbedtls_ctr_drbg_free( &c->ctr_drbg );
	mbedtls_entropy_free( &c->entropy );
	mbedtls_x509_crt_free( &c->own_cert );
	mbedtls_pk_free( &c->own_cert_key );
	mbedtls_x509_crt_free( &c->ca_chain );
	ber_memfree ( c );
}

/*
 * initialize a new TLS context
 */
static int
tlsmt_ctx_init( struct ldapoptions *lo, struct ldaptls *lt, int is_server, char *errmsg )
{
	tlsmt_ctx *ctx = (tlsmt_ctx *)lo->ldo_tls_ctx;
	mbedtls_ssl_config *ssl_config = &ctx->ssl_config;

	// Set all options for the connection
	int ret = mbedtls_ssl_config_defaults(ssl_config, is_server?MBEDTLS_SSL_IS_SERVER:MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);

// MBedtls v3 deprecated SSLv3, TLS1.0, TLS1.1
#if MBEDTLS_VERSION_NUMBER < 0x03000000
	if ( lo->ldo_tls_protocol_min ) {
		int minor = MBEDTLS_SSL_MINOR_VERSION_0; // SSLv3.0 shall be avoided
		switch (lo->ldo_tls_protocol_min) {
			case LDAP_OPT_X_TLS_PROTOCOL_SSL2: // SSL2 not supported, set min to SSLv3
			case LDAP_OPT_X_TLS_PROTOCOL_SSL3:
				minor = MBEDTLS_SSL_MINOR_VERSION_0;
				break;
			case LDAP_OPT_X_TLS_PROTOCOL_TLS1_0:
				minor = MBEDTLS_SSL_MINOR_VERSION_1;
				break;
			case LDAP_OPT_X_TLS_PROTOCOL_TLS1_1:
				minor = MBEDTLS_SSL_MINOR_VERSION_2;
				break;
			case LDAP_OPT_X_TLS_PROTOCOL_TLS1_2:
			default:
				minor = MBEDTLS_SSL_MINOR_VERSION_3;
				break;
			case LDAP_OPT_X_TLS_PROTOCOL_TLS1_3:
				Debug0 ( LDAP_DEBUG_ANY, "MbedTLSv2 backend does not support TLSv1.3, keep minimum version to 1.2" );
				minor = MBEDTLS_SSL_MINOR_VERSION_3;
				break;
		}
		mbedtls_ssl_conf_min_version ( ssl_config, MBEDTLS_SSL_MAJOR_VERSION_3, minor );
	}

	if ( lo->ldo_tls_protocol_max ) {
		int minor = MBEDTLS_SSL_MINOR_VERSION_3;
		switch (lo->ldo_tls_protocol_max) {
			case LDAP_OPT_X_TLS_PROTOCOL_SSL2: // SSL2 not supported, set min to SSLv3
			case LDAP_OPT_X_TLS_PROTOCOL_SSL3:
				minor = MBEDTLS_SSL_MINOR_VERSION_0;
				break;
			case LDAP_OPT_X_TLS_PROTOCOL_TLS1_0:
				minor = MBEDTLS_SSL_MINOR_VERSION_1;
				break;
			case LDAP_OPT_X_TLS_PROTOCOL_TLS1_1:
				minor = MBEDTLS_SSL_MINOR_VERSION_2;
				break;
			case LDAP_OPT_X_TLS_PROTOCOL_TLS1_2:
			default:
				minor = MBEDTLS_SSL_MINOR_VERSION_3;
				break;
			case LDAP_OPT_X_TLS_PROTOCOL_TLS1_3:
				Debug0 ( LDAP_DEBUG_ANY, "MbedTLSv2 backend does not support TLSv1.3, keep maximum version to 1.2" );
				minor = MBEDTLS_SSL_MINOR_VERSION_3;
				break;
		}
		mbedtls_ssl_conf_max_version ( ssl_config, MBEDTLS_SSL_MAJOR_VERSION_3, minor );
	}
#else /* MBEDTLS_VERSION_NUMBER < 0x03000000 : MBEDTLS version 3 and above: No SSLv3, TLSv1.0, TLSv1.1 */
	if ( lo->ldo_tls_protocol_min ) {
	 	mbedtls_ssl_protocol_version version = MBEDTLS_SSL_VERSION_TLS1_2; // TLSv1.2 is the lowest version available
		switch (lo->ldo_tls_protocol_max) {
			case LDAP_OPT_X_TLS_PROTOCOL_SSL2:
			case LDAP_OPT_X_TLS_PROTOCOL_SSL3:
			case LDAP_OPT_X_TLS_PROTOCOL_TLS1_0:
			case LDAP_OPT_X_TLS_PROTOCOL_TLS1_1:
				/* for all non supported version request, force TLSv1.2 */
				Debug0 ( LDAP_DEBUG_ANY, "MbedTLSv3 backend does not support TLS version under 1.2, switch the minimum version requested to it" );
			case LDAP_OPT_X_TLS_PROTOCOL_TLS1_2:
			default:
				version = MBEDTLS_SSL_VERSION_TLS1_2;
				break;
			case LDAP_OPT_X_TLS_PROTOCOL_TLS1_3:
				version = MBEDTLS_SSL_VERSION_TLS1_3;
				break;
		}
		mbedtls_ssl_conf_min_tls_version ( ssl_config, version );
	}

	if ( lo->ldo_tls_protocol_max ) {
	 	mbedtls_ssl_protocol_version version = MBEDTLS_SSL_VERSION_TLS1_3;
		switch (lo->ldo_tls_protocol_min) {
			case LDAP_OPT_X_TLS_PROTOCOL_SSL2:
			case LDAP_OPT_X_TLS_PROTOCOL_SSL3:
			case LDAP_OPT_X_TLS_PROTOCOL_TLS1_0:
			case LDAP_OPT_X_TLS_PROTOCOL_TLS1_1:
				/* for all non supported version request, force TLSv1.2 */
				Debug0 ( LDAP_DEBUG_ANY, "MbedTLSv3 backend does not support TLS version under 1.2, switch the maximum version requested to it" );
			case LDAP_OPT_X_TLS_PROTOCOL_TLS1_2:
			default:
				version = MBEDTLS_SSL_VERSION_TLS1_2;
				break;
			case LDAP_OPT_X_TLS_PROTOCOL_TLS1_3:
				version = MBEDTLS_SSL_VERSION_TLS1_3;
				break;
		}
		mbedtls_ssl_conf_max_tls_version ( ssl_config, version );
	}

#endif /* MBEDTLS_VERSION_NUMBER < 0x03000000 */

	if ( lo->ldo_tls_ciphersuite ) {
		Debug1 (LDAP_DEBUG_ANY, "tlsmt_ctx_init Cipher suite selection is not supported by MbedTLS backend, ignore setting %s\n", lt->lt_ciphersuite);
	}

	if (lo->ldo_tls_cacertdir != NULL) {
		char **dirs = ldap_str2charray( lt->lt_cacertdir, CERTPATHSEP );
		int i;
		for ( i=0; dirs[i]; i++ ) {
			int ret = mbedtls_x509_crt_parse_path( &ctx->ca_chain, dirs[i] );
			if ( ret < 0 ) {
				Debug1( LDAP_DEBUG_ANY,
					"TLS: warning: no certificate found in CA certificate directory `%s'.\n",
					dirs[i] );
				/* only warn, no return */
				mbedtls_strerror( ret, errmsg, ERRBUFSIZE );
			}
		}
		ldap_charray_free( dirs );
	}

	if (lo->ldo_tls_cacertfile != NULL) {
		int ret = mbedtls_x509_crt_parse_file( &ctx->ca_chain, lt->lt_cacertfile );
		if ( ret < 0 ) {
			char errParseFile[ERRBUFSIZE];
			mbedtls_strerror( ret, errParseFile, ERRBUFSIZE );
			Debug3( LDAP_DEBUG_ANY,
				"TLS: could not use CA certificate file `%s': %s (%d)\n",
				lo->ldo_tls_cacertfile,
				errParseFile,
				ret );
			return -1;
		}
	}
	mbedtls_ssl_conf_ca_chain(ssl_config, &ctx->ca_chain, NULL); // CRL not supported

	if (( lo->ldo_tls_certfile && lo->ldo_tls_keyfile ) ||
		( lo->ldo_tls_cert.bv_val && lo->ldo_tls_key.bv_val )) {

#if MBEDTLS_VERSION_NUMBER < 0x03000000
		if ( lo->ldo_tls_key.bv_val ) {
			ret = mbedtls_pk_parse_key(&ctx->own_cert_key, (unsigned char *)lo->ldo_tls_key.bv_val, lo->ldo_tls_key.bv_len, NULL, 0);
		} else {
			ret = mbedtls_pk_parse_keyfile(&ctx->own_cert_key, lt->lt_keyfile, NULL);
		}
#else /* MBEDTLS_VERSION_NUMBER < 0x03000000 */
		if ( lo->ldo_tls_key.bv_val ) {
			ret = mbedtls_pk_parse_key(&ctx->own_cert_key, (unsigned char *)lo->ldo_tls_key.bv_val, lo->ldo_tls_key.bv_len, NULL, 0, mbedtls_ctr_drbg_random, &ctx->ctr_drbg);
		} else {
			ret = mbedtls_pk_parse_keyfile(&ctx->own_cert_key, lt->lt_keyfile, NULL, mbedtls_ctr_drbg_random, &ctx->ctr_drbg);
		}
#endif /* MBEDTLS_VERSION_NUMBER < 0x03000000 */

		if (ret != 0) {
			return -1;
		}

		if ( lo->ldo_tls_cert.bv_val ) {
			ret = mbedtls_x509_crt_parse( &ctx->own_cert, (unsigned char *)lo->ldo_tls_cert.bv_val, lo->ldo_tls_cert.bv_len);
		} else {
			ret = mbedtls_x509_crt_parse_file( &ctx->own_cert, lt->lt_certfile);
		}

		if (ret != 0) {
			return -1;
		}

		if ( (ret = mbedtls_ssl_conf_own_cert(ssl_config, &ctx->own_cert, &ctx->own_cert_key ) ) != 0) {
			return -1;
		}
	}

	switch ( lo->ldo_tls_require_cert ) {
		case LDAP_OPT_X_TLS_NEVER :
			mbedtls_ssl_conf_authmode( ssl_config, MBEDTLS_SSL_VERIFY_NONE );
			break;
		case LDAP_OPT_X_TLS_HARD:
		case LDAP_OPT_X_TLS_DEMAND:
		default:
			mbedtls_ssl_conf_authmode( ssl_config, MBEDTLS_SSL_VERIFY_REQUIRED );
			break;
		case LDAP_OPT_X_TLS_ALLOW:
		case LDAP_OPT_X_TLS_TRY:
			mbedtls_ssl_conf_authmode( ssl_config, MBEDTLS_SSL_VERIFY_OPTIONAL );
			break;
	}

	if ( is_server && lo->ldo_tls_dhfile ) {
		Debug1 (LDAP_DEBUG_ANY, "tlsmt_ctx_init DH params from file is not supported by MbedTLS backend, ignore setting %s\n", lo->ldo_tls_dhfile);
	}

	if ( lo->ldo_tls_uris )
	{
		Debug0( LDAP_DEBUG_ANY,
			"TLS: uris are not supported.\n" );
		strncpy( errmsg, "TLS uris are not supported", ERRBUFSIZE );
		return -1;
	}

	if ( lo->ldo_tls_cacerturis )
	{
		Debug0( LDAP_DEBUG_ANY,
			"TLS: cacerturis are not supported.\n" );
		strncpy( errmsg, "TLS cacerturis are not supported", ERRBUFSIZE );
		return -1;
	}

	return 0;
}

static tls_session *
tlsmt_session_new( tls_ctx *ctx, int is_server )
{
	tlsmt_ctx *c = (tlsmt_ctx *)ctx;
	tlsmt_session *session;

	session = ber_memcalloc ( 1, sizeof (*session) );
	if ( !session )
		return NULL;

	session->config = c;

	mbedtls_ssl_init(&(session->ssl_ctx));
	mbedtls_ssl_setup(&(session->ssl_ctx), &session->config->ssl_config);

	return (tls_session *)session;
}

static int
tlsmt_session_accept( tls_session *sess )
{
	tlsmt_session *s = (tlsmt_session *)sess;

	int ret;
	do {
		ret = mbedtls_ssl_handshake( &(s->ssl_ctx) );
	} while (ret!=0 && (ret== MBEDTLS_ERR_SSL_WANT_READ || ret==MBEDTLS_ERR_SSL_WANT_WRITE));

	return ret;
}

static int
tlsmt_session_connect( LDAP *ld, tls_session *sess, const char *name_in )
{
	tlsmt_session *s = (tlsmt_session *)sess;
	if (name_in) {
		int ret = mbedtls_ssl_set_hostname( &(s->ssl_ctx), name_in );
		if ( ret != 0 ) {
			return ret;
		}
	}

	return tlsmt_session_accept(sess);
}

static int
tlsmt_session_upflags( Sockbuf *sb, tls_session *sess, int rc )
{
	if (rc == MBEDTLS_ERR_SSL_WANT_READ) {
		sb->sb_trans_needs_read  = 1;
		return 1;

	} else if (rc == MBEDTLS_ERR_SSL_WANT_WRITE) {
		sb->sb_trans_needs_write = 1;
		return 1;
	}
	return 0;
}

static char *
tlsmt_session_errmsg( tls_session *sess, int rc, char *buf, size_t len )
{
	if ( rc ) {
		mbedtls_strerror(rc, buf, len);
		return buf;
	}
	return NULL;
}

static int
tlsmt_session_my_dn( tls_session *sess, struct berval *der_dn )
{
	// Session cannot give us our own certificate but it is stored in the config context
	tlsmt_session *s = (tlsmt_session *)sess;

	der_dn->bv_len = s->config->own_cert.subject_raw.len;
	der_dn->bv_val = s->config->own_cert.subject_raw.p;

	return 0;
}

static int
tlsmt_session_peer_dn( tls_session *sess, struct berval *der_dn )
{
	tlsmt_session *s = (tlsmt_session *)sess;
	const mbedtls_x509_crt* peer_cert = mbedtls_ssl_get_peer_cert( &s->ssl_ctx );

	if ( peer_cert == NULL ) {

		return LDAP_INVALID_CREDENTIALS;
	}

	der_dn->bv_len = peer_cert->subject_raw.len;
	der_dn->bv_val = peer_cert->subject_raw.p;

	return 0;
}

/* what kind of hostname were we given? */
#define	IS_DNS	0
#define	IS_IP4	1
#define	IS_IP6	2

static int
tlsmt_session_chkhost( LDAP *ld, tls_session *sess, const char *name_in )
{
	tlsmt_session *s = (tlsmt_session *)sess;
	int i, ret = LDAP_LOCAL_ERROR;
	int chkSAN = ld->ld_options.ldo_tls_require_san, gotSAN = 0;
	const char *name;
	char *ptr;
	char *domain = NULL;
	int len1 = 0, len2 = 0;
	int ntype = IS_DNS, nlen;
#ifdef LDAP_PF_INET6
	struct in6_addr addr;
#else
	struct in_addr addr;
#endif

	if( ldap_int_hostname &&
		( !name_in || !strcasecmp( name_in, "localhost" ) ) )
	{
		name = ldap_int_hostname;
	} else {
		name = name_in;
	}
	nlen = strlen(name);

	const mbedtls_x509_crt* x = mbedtls_ssl_get_peer_cert( &s->ssl_ctx );
	if (!x) {
		Debug0( LDAP_DEBUG_ANY,
			"TLS: unable to get peer certificate.\n" );
		/* If this was a fatal condition, things would have
		 * aborted long before now.
		 */
		return LDAP_SUCCESS;
	}

#ifdef LDAP_PF_INET6
	if (inet_pton(AF_INET6, name, &addr)) {
		ntype = IS_IP6;
	} else
#endif
	if ((ptr = strrchr(name, '.')) && isdigit((unsigned char)ptr[1])) {
		if (inet_aton(name, (struct in_addr *)&addr)) ntype = IS_IP4;
	}

	if (ntype == IS_DNS) {
		len1 = strlen(name);
		domain = strchr(name, '.');
		if (domain) {
			len2 = len1 - (domain-name);
		}
	}

#if MBEDTLS_VERSION_NUMBER < 0x03000000
	if ( chkSAN && ( ret != LDAP_SUCCESS ) && ( x->ext_types & MBEDTLS_X509_EXT_SUBJECT_ALT_NAME ) ) {
#else
	if ( chkSAN && ( ret != LDAP_SUCCESS ) && ( mbedtls_x509_crt_has_ext_type(x, MBEDTLS_X509_EXT_SUBJECT_ALT_NAME ) != 0 ) ) {
#endif
		mbedtls_x509_sequence *SANs = (mbedtls_x509_sequence *)&x->subject_alt_names;
		while ( SANs != NULL && ret != LDAP_SUCCESS ) {
			gotSAN = 1;
			const mbedtls_x509_buf *san_buf = &SANs->buf;
			/* mbedtls does not support SAN ip address type, so parse it here instead of using x509_crt_check_san */
			switch ( san_buf->tag & ( MBEDTLS_ASN1_TAG_CLASS_MASK | MBEDTLS_ASN1_TAG_VALUE_MASK )) {
				/* DNS type */
				case (MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_X509_SAN_DNS_NAME ) :
				{
					/* Is this an exact match? */
					if ((len1 == san_buf->len) && !strncasecmp(name, san_buf->p, len1)) {
						ret = LDAP_SUCCESS;
					}

					/* Is this a wildcard match? */
					if (domain && (san_buf->p[0] == '*') && (san_buf->p[1] == '.') &&
						(len2 == san_buf->len-1) && !strncasecmp(domain, (san_buf->p)+1, len2))
					{
						ret = LDAP_SUCCESS;
					}
				}
				break;
				/* IPADDRESS type */
				case (MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_X509_SAN_IP_ADDRESS ) :
				{

					if (
						(ntype == IS_IP4 && san_buf->len == sizeof(struct in_addr))
#ifdef LDAP_PF_INET6
						|| (ntype == IS_IP6 && san_buf->len == sizeof(struct in6_addr))
#endif
					   ) {
						if (!memcmp(san_buf->p, &addr, san_buf->len)) {
							ret = LDAP_SUCCESS;
						}
					}
				}
				break;
				default:
					Debug0(LDAP_DEBUG_ANY, "Unsupported SAN type. Only DNS and IP ADDRESS are supported");
			}

			SANs = SANs->next;
		}
	}

	if (ret != LDAP_SUCCESS && chkSAN) {
		switch(chkSAN) {
		case LDAP_OPT_X_TLS_DEMAND:
		case LDAP_OPT_X_TLS_HARD:
			if (!gotSAN) {
				Debug0( LDAP_DEBUG_ANY,
					"TLS: unable to get subjectAltName from peer certificate.\n" );
				ret = LDAP_CONNECT_ERROR;
				if ( ld->ld_error ) {
					LDAP_FREE( ld->ld_error );
				}
				ld->ld_error = LDAP_STRDUP(
					_("TLS: unable to get subjectAltName from peer certificate"));
				goto done;
			}
			/* FALLTHRU */
		case LDAP_OPT_X_TLS_TRY:
			if (gotSAN) {
				Debug1( LDAP_DEBUG_ANY, "TLS: hostname (%s) does not match "
					"subjectAltName in certificate.\n",
					name );
				ret = LDAP_CONNECT_ERROR;
				if ( ld->ld_error ) {
					LDAP_FREE( ld->ld_error );
				}
				ld->ld_error = LDAP_STRDUP(
					_("TLS: hostname does not match subjectAltName in peer certificate"));
				goto done;
			}
			break;
		case LDAP_OPT_X_TLS_ALLOW:
			break;
		}
	}

	if (ret != LDAP_SUCCESS) {
		/* find the last CN */
		const mbedtls_x509_name *subject;
		for( subject = &x->subject; subject != NULL && ret != LDAP_SUCCESS; subject = subject->next ) {
			if( MBEDTLS_OID_CMP( MBEDTLS_OID_AT_CN, &subject->oid ) == 0 ) {
				const mbedtls_x509_buf *cn=&subject->val;
				/* Is this an exact match? */
				if ((len1 == cn->len) && !strncasecmp(name, cn->p, len1)) {
					ret = LDAP_SUCCESS;
				}

				/* Is this a wildcard match? */
				if (domain && (cn->p[0] == '*') && (cn->p[1] == '.') &&
					(len2 == cn->len-1) && !strncasecmp(domain, (cn->p)+1, len2))
				{
					ret = LDAP_SUCCESS;
				}
			}
		}
	}
done:
	return ret;
}

static int
tlsmt_session_strength( tls_session *sess )
{
	tlsmt_session *s = (tlsmt_session *)sess;
#if MBEDTLS_VERSION_NUMBER < 0x03000000
	const mbedtls_ssl_ciphersuite_t *currentCipherSuite = mbedtls_ssl_ciphersuite_from_string( mbedtls_ssl_get_ciphersuite( &s->ssl_ctx ) );
	if (currentCipherSuite == NULL) return 0;

	return ( ( mbedtls_cipher_info_from_type( currentCipherSuite->cipher )->key_bitlen ) );
#else /* MBEDTLS_VERSION_NUMBER < 0x03000000 */
	const mbedtls_ssl_ciphersuite_t *currentCipherSuite = mbedtls_ssl_ciphersuite_from_id( mbedtls_ssl_get_ciphersuite_id_from_ssl( &s->ssl_ctx ) );
	if (currentCipherSuite == NULL) return 0;

	return ( ( mbedtls_ssl_ciphersuite_get_cipher_key_bitlen( currentCipherSuite ) ) );
#endif /* MBEDTLS_VERSION_NUMBER < 0x03000000 */
}

static int
tlsmt_session_unique( tls_session *sess, struct berval *buf, int is_server)
{
	Debug0(LDAP_DEBUG_ANY, "tlsmt_session_unique channel binding using unique is not available with MbedTLS backend\n");

	return 0;
}

static int
tlsmt_session_endpoint( tls_session *sess, struct berval *buf, int is_server )
{
	tlsmt_session *s = (tlsmt_session *)sess;

	const mbedtls_x509_crt* cert = NULL;

	/* get server certificate */
	if ( is_server ) {
		cert = &s->config->own_cert;
	} else {
	       	cert = mbedtls_ssl_get_peer_cert( &s->ssl_ctx );
	}
#if MBEDTLS_VERSION_NUMBER < 0x03000000
	mbedtls_md_type_t mdt = cert->sig_md;
#else
	mbedtls_md_type_t mdt;
	mbedtls_pk_type_t pk;
	mbedtls_oid_get_sig_alg(&(cert->sig_oid), &mdt, &pk);
#endif

	/* RFC 5929 */
	switch (mdt) {
		case MBEDTLS_MD_NONE:
#if MBEDTLS_VERSION_NUMBER < 0x03000000
		case MBEDTLS_MD_MD2:
		case MBEDTLS_MD_MD4:
#endif
		case MBEDTLS_MD_MD5:
		case MBEDTLS_MD_SHA1:
			mdt = MBEDTLS_MD_SHA256;
	}

	const mbedtls_md_info_t *md = mbedtls_md_info_from_type(mdt);

	int md_len = mbedtls_md_get_size(md);
	if ( md_len > buf->bv_len) {
		return 0;
	}

	if ( mbedtls_md( md, cert->raw.p, cert->raw.len, buf->bv_val ) != 0 ) {
		return 0;
	}
	buf->bv_len = md_len;

	return md_len;
}

static const char *
tlsmt_session_version( tls_session *sess )
{
	tlsmt_session *s = (tlsmt_session *)sess;
	return mbedtls_ssl_get_version( &s->ssl_ctx );
}

static const char *
tlsmt_session_cipher( tls_session *sess )
{
	tlsmt_session *s = (tlsmt_session *)sess;
	return mbedtls_ssl_get_ciphersuite( &s->ssl_ctx );
}

static int
tlsmt_session_peercert( tls_session *sess, struct berval *der )
{
	tlsmt_session *s = (tlsmt_session *)sess;
	const mbedtls_x509_crt* peer_cert = mbedtls_ssl_get_peer_cert( &s->ssl_ctx );

	if ( peer_cert == NULL ) {
		return -1;
	}

	der->bv_len = peer_cert->raw.len;
	der->bv_val = LDAP_MALLOC( der->bv_len );
	if (!der->bv_val)
		return -1;
	memcpy(der->bv_val, peer_cert->raw.p, der->bv_len);
	return 0;
}

static int
tlsmt_session_pinning( LDAP *ld, tls_session *sess, char *hashalg, struct berval *hash )
{
	int ret;
	tlsmt_session *s = (tlsmt_session *)sess;
	const mbedtls_x509_crt* peer_cert = mbedtls_ssl_get_peer_cert(&s->ssl_ctx);

	if (peer_cert == NULL) {
		return -1;
	}
	const mbedtls_md_info_t *mbedtls_hash;
	if ( hashalg ) {
		// mbedtls hash algo parser requires all uppercase characters in algo name
		size_t hashalg_len = strlen(hashalg);
		char *hashalgUpper = ber_memcalloc ( 1, hashalg_len + 1 );
		for (int i=0; i<hashalg_len; i++) {
			hashalgUpper[i] = toupper(hashalg[i]);
		}
		mbedtls_hash = mbedtls_md_info_from_string( hashalgUpper );
		ber_memfree( hashalgUpper );

		if ( mbedtls_hash == NULL ) {
			Debug1( LDAP_DEBUG_ANY, "tlsmt_session_pinning: "
					"unknown hashing algorithm for MbedTLS: '%s'\n",
					hashalg );
			return -1;
		}
	}

	// Extract certificate pk in DER format
	const mbedtls_pk_context *pk = &peer_cert->pk;
	size_t pk_size = mbedtls_pk_get_len( pk );

	unsigned char *der_pk = ber_memcalloc ( 1, 2*pk_size );
#if MBEDTLS_VERSION_NUMBER < 0x03000000
	int der_pk_len = mbedtls_pk_write_pubkey_der( (mbedtls_pk_context *)pk, der_pk, pk_size*2 );
#else
	int der_pk_len = mbedtls_pk_write_pubkey_der( pk, der_pk, pk_size*2 );
#endif

	unsigned char *digest[MBEDTLS_MD_MAX_SIZE];
	struct berval keyhash;

	if ( hashalg ) {
		keyhash.bv_len = mbedtls_md_get_size(mbedtls_hash);
		keyhash.bv_val = (char *)digest;
		mbedtls_md(mbedtls_hash, der_pk+2*pk_size-der_pk_len, der_pk_len, keyhash.bv_val );
	} else {
		keyhash.bv_len = der_pk_len;
		keyhash.bv_val = der_pk+2*pk_size-der_pk_len;
	}
	ber_memfree(der_pk);

	if ( ber_bvcmp( hash, &keyhash ) ) {
		ret = LDAP_CONNECT_ERROR;
		Debug0( LDAP_DEBUG_ANY, "tlsmt_session_pinning: "
				"public key hash does not match provided pin.\n" );
		if ( ld->ld_error ) {
			LDAP_FREE( ld->ld_error );
		}
		ld->ld_error = LDAP_STRDUP(
			_("TLS: public key hash does not match provided pin"));
	} else {
		ret = LDAP_SUCCESS;
	}

	return ret;
}

/*
 * TLS support for LBER Sockbufs
 */

struct tls_data {
	tlsmt_session		*session;
	Sockbuf_IO_Desc		*sbiod;
};

static int
tlsmt_read ( void *ptr, unsigned char *buf, size_t len )
{
	struct tls_data	*p;

	if ( buf == NULL || len <= 0 ) return 0;

	p = (struct tls_data *)ptr;

	if ( p == NULL || p->sbiod == NULL ) {
		return 0;
	}

	int ret = LBER_SBIOD_READ_NEXT( p->sbiod, buf, len );

	if ( ret < 0 ) {
		int err = sock_errno();
		if ( err == EAGAIN || err == EWOULDBLOCK ) {
			return MBEDTLS_ERR_SSL_WANT_READ;
		}
	}

	return ret;
}

static int
tlsmt_write( void *ptr, const unsigned char *buf, size_t len )
{
	struct tls_data	*p;

	if ( buf == NULL || len <= 0 ) return 0;

	p = (struct tls_data *)ptr;

	if ( p == NULL || p->sbiod == NULL ) {
		return 0;
	}

	int ret =  LBER_SBIOD_WRITE_NEXT( p->sbiod, (char *)buf, len );

	if ( ret < 0 ) {
		int err = sock_errno();
		if ( err == EAGAIN || err == EWOULDBLOCK ) {

			return MBEDTLS_ERR_SSL_WANT_WRITE;
		}
	}

	return ret;
}

static int
tlsmt_sb_setup( Sockbuf_IO_Desc *sbiod, void *arg )
{
	struct tls_data	*p;
	tlsmt_session	*session = (tlsmt_session *) arg;

	assert( sbiod != NULL );

	p = LBER_MALLOC( sizeof( *p ) );
	if ( p == NULL ) {
		return -1;
	}
	mbedtls_ssl_set_bio(&(session->ssl_ctx), p, tlsmt_write, tlsmt_read, NULL);

	p->session = session;
	p->sbiod = sbiod;
	sbiod->sbiod_pvt = p;

	return 0;
}

static int
tlsmt_sb_remove( Sockbuf_IO_Desc *sbiod )
{
	struct tls_data		*p;
	assert( sbiod != NULL );
	assert( sbiod->sbiod_pvt != NULL );
	p = (struct tls_data *)sbiod->sbiod_pvt;

	mbedtls_ssl_free( &p->session->ssl_ctx );
	LBER_FREE( p->session );
	LBER_FREE( sbiod->sbiod_pvt );
	sbiod->sbiod_pvt = NULL;
	return 0;
}

static int
tlsmt_sb_close( Sockbuf_IO_Desc *sbiod )
{
	struct tls_data		*p;
	assert( sbiod != NULL );
	assert( sbiod->sbiod_pvt != NULL );
	p = (struct tls_data *)sbiod->sbiod_pvt;

	int ret = MBEDTLS_ERR_SSL_WANT_WRITE;
	do { ret = mbedtls_ssl_close_notify( &(p->session->ssl_ctx) ); }
	while (ret == MBEDTLS_ERR_SSL_WANT_WRITE);

	return 0;
}

static int
tlsmt_sb_ctrl( Sockbuf_IO_Desc *sbiod, int opt, void *arg )
{
	struct tls_data		*p;
	assert( sbiod != NULL );
	assert( sbiod->sbiod_pvt != NULL );
	p = (struct tls_data *)sbiod->sbiod_pvt;

	if ( opt == LBER_SB_OPT_GET_SSL ) {
		*((tlsmt_session **)arg) = p->session;
		return 1;

	} else if ( opt == LBER_SB_OPT_DATA_READY ) {
		return mbedtls_ssl_check_pending( &(p->session->ssl_ctx) );
	}

	return LBER_SBIOD_CTRL_NEXT( sbiod, opt, arg );
}

static ber_slen_t
tlsmt_sb_read( Sockbuf_IO_Desc *sbiod, void *buf, ber_len_t len)
{
	struct tls_data	*p;
	assert( sbiod != NULL );
	assert( sbiod->sbiod_pvt != NULL );
	p = (struct tls_data *)sbiod->sbiod_pvt;

	int ret = mbedtls_ssl_read( &(p->session->ssl_ctx), buf, len);

	if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE ) {
		sbiod->sbiod_sb->sb_trans_needs_read = 1;
		sock_errset(EWOULDBLOCK);
		return 0;
	}
	else {
		sbiod->sbiod_sb->sb_trans_needs_read = 0;
	}

	return ret;
}

static ber_slen_t
tlsmt_sb_write( Sockbuf_IO_Desc *sbiod, void *buf, ber_len_t len)
{
	struct tls_data	*p;
	assert( sbiod != NULL );
	assert( sbiod->sbiod_pvt != NULL );
	p = (struct tls_data *)sbiod->sbiod_pvt;

	int ret = mbedtls_ssl_write( &(p->session->ssl_ctx), buf, len);

	if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE ) {
		sbiod->sbiod_sb->sb_trans_needs_write = 1;
		sock_errset(EWOULDBLOCK);
		return 0;
	}
	else {
		sbiod->sbiod_sb->sb_trans_needs_write = 0;
	}
	return ret;
}

static Sockbuf_IO tlsmt_sbio =
{
	tlsmt_sb_setup,		/* sbi_setup */
	tlsmt_sb_remove,		/* sbi_remove */
	tlsmt_sb_ctrl,		/* sbi_ctrl */
	tlsmt_sb_read,		/* sbi_read */
	tlsmt_sb_write,		/* sbi_write */
	tlsmt_sb_close		/* sbi_close */
};

tls_impl ldap_int_tls_impl = {
	"MbedTLS",

	tlsmt_init,
	tlsmt_destroy,

	tlsmt_ctx_new,
	tlsmt_ctx_ref,
	tlsmt_ctx_free,
	tlsmt_ctx_init,

	tlsmt_session_new,
	tlsmt_session_connect,
	tlsmt_session_accept,
	tlsmt_session_upflags,
	tlsmt_session_errmsg,
	tlsmt_session_my_dn,
	tlsmt_session_peer_dn,
	tlsmt_session_chkhost,
	tlsmt_session_strength,
	tlsmt_session_unique,
	tlsmt_session_endpoint,
	tlsmt_session_version,
	tlsmt_session_cipher,
	tlsmt_session_peercert,
	tlsmt_session_pinning,

	&tlsmt_sbio,

#ifdef LDAP_R_COMPILE
	tlsmt_thr_init,
#else
	NULL,
#endif

	0
};

#endif /* HAVE_MBEDTLS */
