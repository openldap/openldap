/* modify.c - modify request handler for back-asyncmeta */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2016-2024 The OpenLDAP Foundation.
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
#include <ac/socket.h>
#include "slap.h"
#include "../../../libraries/liblber/lber-int.h"
#include "../../../libraries/libldap/ldap-int.h"
#include "../back-ldap/back-ldap.h"
#include "back-asyncmeta.h"

meta_search_candidate_t
asyncmeta_back_modify_start(Operation *op,
			    SlapReply *rs,
			    a_metaconn_t *mc,
			    bm_context_t *bc,
			    int candidate,
			    int do_lock)
{
	int		i, isupdate, rc = 0;
	a_dncookie	dc;
	a_metainfo_t	*mi = mc->mc_info;
	a_metatarget_t	*mt = mi->mi_targets[ candidate ];
	LDAPMod		**modv = NULL;
	LDAPMod		*mods = NULL;
	struct berval mdn;
	Modifications	*ml;
	meta_search_candidate_t retcode = META_SEARCH_CANDIDATE;
		BerElement *ber = NULL;
	a_metasingleconn_t	*msc = &mc->mc_conns[ candidate ];
	SlapReply		*candidates = bc->candidates;
	ber_int_t	msgid;
	LDAPControl		**ctrls = NULL;

	/*
	 * Rewrite the modify dn, if needed
	 */
	dc.op = op;
	dc.target = mt;
	dc.memctx = op->o_tmpmemctx;
	dc.to_from = MASSAGE_REQ;

	asyncmeta_dn_massage( &dc, &op->o_req_dn, &mdn );

	for ( i = 0, ml = op->orm_modlist; ml; i++ ,ml = ml->sml_next )
		;

	modv = op->o_tmpalloc( ( i + 1 )*sizeof( LDAPMod * ) + i*sizeof( LDAPMod ),
			op->o_tmpmemctx );
	if ( modv == NULL ) {
		rs->sr_err = LDAP_OTHER;
		retcode = META_SEARCH_ERR;
		goto doreturn;
	}
	mods = (LDAPMod *)&modv[ i + 1 ];

	isupdate = be_shadow_update( op );
	for ( i = 0, ml = op->orm_modlist; ml; ml = ml->sml_next ) {
		int	j;

		if ( !isupdate && !get_relax( op ) && ml->sml_desc->ad_type->sat_no_user_mod  )
		{
			continue;
		}

		modv[ i ] = &mods[ i ];
		mods[ i ].mod_op = ml->sml_op | LDAP_MOD_BVALUES;
		mods[ i ].mod_type = ml->sml_desc->ad_cname.bv_val;

		if ( ml->sml_values != NULL ) {
			j = ml->sml_numvals;
			mods[ i ].mod_bvalues =(struct berval **)op->o_tmpalloc( ( j + 1 ) *sizeof( struct berval * ), op->o_tmpmemctx );
			for ( j = 0; !BER_BVISNULL( &ml->sml_values[ j ] ); j++ ) {
				mods[ i ].mod_bvalues[ j ] = op->o_tmpalloc(sizeof( struct berval ), op->o_tmpmemctx );
				if ( ml->sml_desc->ad_type->sat_syntax == slap_schema.si_syn_distinguishedName )
					asyncmeta_dn_massage( &dc, &ml->sml_values[ j ], mods[ i ].mod_bvalues[ j ] );
				else
					*mods[ i ].mod_bvalues[ j ] = ml->sml_values[ j ];
			}
			mods[ i ].mod_bvalues[ j ] = NULL;

		} else {
			mods[ i ].mod_bvalues = NULL;
		}

		i++;
	}
	modv[ i ] = 0;

	asyncmeta_set_msc_time(msc);
	ctrls = op->o_ctrls;
	if ( asyncmeta_controls_add( op, rs, mc, candidate, bc->is_root, &ctrls) != LDAP_SUCCESS )
	{
		candidates[ candidate ].sr_msgid = META_MSGID_IGNORE;
		retcode = META_SEARCH_ERR;
		goto done;
	}

	/* someone reset the connection */
	if (!( LDAP_BACK_CONN_ISBOUND( msc )
	       || LDAP_BACK_CONN_ISANON( msc )) || msc->msc_ld == NULL ) {
		Debug( asyncmeta_debug , "msc %p not initialized at %s:%d\n", msc, __FILE__, __LINE__ );
		goto error_unavailable;
	}

	ber = ldap_build_modify_req( msc->msc_ld, mdn.bv_val, modv, ctrls, NULL, &msgid);

	if (!ber) {
		Debug( asyncmeta_debug, "%s asyncmeta_back_modify_start: Operation encoding failed with errno %d\n",
		       op->o_log_prefix, msc->msc_ld->ld_errno );
		rs->sr_err = LDAP_OPERATIONS_ERROR;
		rs->sr_text = "Failed to encode proxied request";
		retcode = META_SEARCH_ERR;
		goto done;
	}

	if (ber) {
		struct timeval tv = {0, mt->mt_network_timeout*1000};
		ber_socket_t s;
		if (!( LDAP_BACK_CONN_ISBOUND( msc )
		       || LDAP_BACK_CONN_ISANON( msc )) || msc->msc_ld == NULL ) {
			Debug( asyncmeta_debug, "msc %p not initialized at %s:%d\n", msc, __FILE__, __LINE__ );
			goto error_unavailable;
		}

		ldap_get_option( msc->msc_ld, LDAP_OPT_DESC, &s );
		if (s < 0) {
			Debug( asyncmeta_debug, "msc %p not initialized at %s:%d\n", msc, __FILE__, __LINE__ );
			goto error_unavailable;
		}

		rc = ldap_int_poll( msc->msc_ld, s, &tv, 1);
		if (rc < 0) {
			Debug( asyncmeta_debug, "msc %p not writable within network timeout %s:%d\n", msc, __FILE__, __LINE__ );
			if ((msc->msc_result_time + META_BACK_RESULT_INTERVAL) < slap_get_time()) {
				rc = LDAP_SERVER_DOWN;
			} else {
				goto error_unavailable;
			}
		} else {
			candidates[ candidate ].sr_msgid = msgid;
			rc = ldap_send_initial_request( msc->msc_ld, LDAP_REQ_MODIFY,
							mdn.bv_val, ber, msgid );
			if (rc == msgid)
				rc = LDAP_SUCCESS;
			else
				rc = LDAP_SERVER_DOWN;
			ber = NULL;
		}

		switch ( rc ) {
		case LDAP_SUCCESS:
			retcode = META_SEARCH_CANDIDATE;
			asyncmeta_set_msc_time(msc);
			goto done;

		case LDAP_SERVER_DOWN:
			/* do not lock if called from asyncmeta_handle_bind_result. Also do not reset the connection */
			if (do_lock > 0) {
				ldap_pvt_thread_mutex_lock( &mc->mc_om_mutex);
				asyncmeta_reset_msc(NULL, mc, candidate, 0, __FUNCTION__);
				ldap_pvt_thread_mutex_unlock( &mc->mc_om_mutex);
			}
			/* fall though*/
		default:
			Debug( asyncmeta_debug, "msc %p ldap_send_initial_request failed. %s:%d\n", msc, __FILE__, __LINE__ );
			goto error_unavailable;
		}
	}

error_unavailable:
	if (ber)
		ber_free(ber, 1);
	switch (bc->nretries[candidate]) {
	case -1: /* nretries = forever */
		ldap_pvt_thread_yield();
		retcode = META_SEARCH_NEED_BIND;
		break;
	case 0: /* no retries left */
		candidates[ candidate ].sr_msgid = META_MSGID_IGNORE;
		rs->sr_err = LDAP_UNAVAILABLE;
		rs->sr_text = "Unable to send modify request to target";
		retcode = META_SEARCH_ERR;
		break;
	default: /* more retries left - try to rebind and go again */
		retcode = META_SEARCH_NEED_BIND;
		bc->nretries[candidate]--;
		ldap_pvt_thread_yield();
		break;
	}
done:
	(void)mi->mi_ldap_extra->controls_free( op, rs, &ctrls );

	if ( mdn.bv_val != op->o_req_dn.bv_val ) {
		op->o_tmpfree( mdn.bv_val, op->o_tmpmemctx );
	}

	op->o_tmpfree( modv, op->o_tmpmemctx );

doreturn:;
	Debug( LDAP_DEBUG_TRACE, "%s <<< asyncmeta_back_modify_start[%p]=%d\n", op->o_log_prefix, msc, candidates[candidate].sr_msgid );
	return retcode;
}

int
asyncmeta_back_modify( Operation *op, SlapReply *rs )
{
	a_metainfo_t	*mi = ( a_metainfo_t * )op->o_bd->be_private;
	a_metatarget_t	*mt;
	a_metaconn_t	*mc;
	int		rc, candidate = -1;
	void *thrctx = op->o_threadctx;
	bm_context_t *bc;
	SlapReply *candidates;
	time_t current_time = slap_get_time();
	int max_pending_ops = (mi->mi_max_pending_ops == 0) ? META_BACK_CFG_MAX_PENDING_OPS : mi->mi_max_pending_ops;

	Debug(LDAP_DEBUG_ARGS, "==> asyncmeta_back_modify: %s\n",
	      op->o_req_dn.bv_val );

	if (current_time > op->o_time) {
		Debug(asyncmeta_debug, "==> asyncmeta_back_modify[%s]: o_time:[%ld], current time: [%ld]\n",
		      op->o_log_prefix, op->o_time, current_time );
	}

	if ( mi->mi_ntargets == 0 ) {
		rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
		rs->sr_text = "No targets are configured for this database";
		send_ldap_result(op, rs);
		return rs->sr_err;
	}

	asyncmeta_new_bm_context(op, rs, &bc, mi->mi_ntargets, mi );
	if (bc == NULL) {
		rs->sr_err = LDAP_OTHER;
		send_ldap_result(op, rs);
		return rs->sr_err;
	}

	candidates = bc->candidates;
	mc = asyncmeta_getconn( op, rs, candidates, &candidate, 0);
	if ( !mc || rs->sr_err != LDAP_SUCCESS) {
		send_ldap_result(op, rs);
		return rs->sr_err;
	}

	mt = mi->mi_targets[ candidate ];
	bc->timeout = mt->mt_timeout[ SLAP_OP_MODIFY ];
	bc->retrying = LDAP_BACK_RETRYING;
	bc->sendok = ( LDAP_BACK_SENDRESULT | bc->retrying );
	bc->stoptime = op->o_time + bc->timeout;
	bc->bc_active = 1;

	if (mc->pending_ops >= max_pending_ops) {
		rs->sr_err = LDAP_BUSY;
		rs->sr_text = "Maximum pending ops limit exceeded";
		send_ldap_result(op, rs);
		return rs->sr_err;
	}

	ldap_pvt_thread_mutex_lock( &mc->mc_om_mutex);
	rc = asyncmeta_add_message_queue(mc, bc);
	mc->mc_conns[candidate].msc_active++;
	ldap_pvt_thread_mutex_unlock( &mc->mc_om_mutex);

	if (rc != LDAP_SUCCESS) {
		rs->sr_err = LDAP_BUSY;
		rs->sr_text = "Maximum pending ops limit exceeded";
		send_ldap_result(op, rs);
		ldap_pvt_thread_mutex_lock(&mc->mc_om_mutex);
		mc->mc_conns[candidate].msc_active--;
		ldap_pvt_thread_mutex_unlock(&mc->mc_om_mutex);
		goto finish;
	}

retry:
	if (bc->timeout && bc->stoptime < slap_get_time()) {
		int		timeout_err;
		timeout_err = op->o_protocol >= LDAP_VERSION3 ?
			LDAP_ADMINLIMIT_EXCEEDED : LDAP_OTHER;
		rs->sr_err = timeout_err;
		rs->sr_text = "Operation timed out before it was sent to target";
		asyncmeta_error_cleanup(op, rs, bc, mc, candidate);
		goto finish;
	}

	rc = asyncmeta_dobind_init_with_retry(op, rs, bc, mc, candidate);
	switch (rc)
	{
	case META_SEARCH_CANDIDATE:
		/* target is already bound, just send the request */
		Debug( LDAP_DEBUG_TRACE, "%s asyncmeta_back_modify:  "
		       "cnd=\"%d\"\n", op->o_log_prefix, candidate );

		rc = asyncmeta_back_modify_start( op, rs, mc, bc, candidate, 1);
		if (rc == META_SEARCH_ERR) {
			asyncmeta_error_cleanup(op, rs, bc, mc, candidate);
			goto finish;

		} else if (rc == META_SEARCH_NEED_BIND) {
			goto retry;
		}
		break;
	case META_SEARCH_NOT_CANDIDATE:
		Debug( LDAP_DEBUG_TRACE, "%s asyncmeta_back_modify: NOT_CANDIDATE "
		       "cnd=\"%d\"\n", op->o_log_prefix, candidate );
		asyncmeta_error_cleanup(op, rs, bc, mc, candidate);
		goto finish;

	case META_SEARCH_NEED_BIND:
	case META_SEARCH_BINDING:
			Debug( LDAP_DEBUG_TRACE, "%s asyncmeta_back_modify: BINDING "
			       "cnd=\"%d\" %p\n", op->o_log_prefix, candidate , &mc->mc_conns[candidate]);
			/* Todo add the context to the message queue but do not send the request
			   the receiver must send this when we are done binding */
			break;

	case META_SEARCH_ERR:
			Debug( LDAP_DEBUG_TRACE, "%s asyncmeta_back_modify: ERR "
			       "cnd=\"%d\"\n", op->o_log_prefix, candidate );
			asyncmeta_error_cleanup(op, rs, bc, mc, candidate);
			goto finish;
		default:
			assert( 0 );
			break;
		}

	ldap_pvt_thread_mutex_lock( &mc->mc_om_mutex);
	mc->mc_conns[candidate].msc_active--;
	asyncmeta_start_one_listener(mc, candidates, bc, candidate);
	bc->bc_active--;
	ldap_pvt_thread_mutex_unlock( &mc->mc_om_mutex);
	rs->sr_err = SLAPD_ASYNCOP;

finish:
	return rs->sr_err;
}
