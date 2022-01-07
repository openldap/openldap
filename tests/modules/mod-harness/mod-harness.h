/* mod-harness.h - mod harness header file */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2019-2022 The OpenLDAP Foundation.
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

#ifndef SLAPD_HARNESS_H
#define SLAPD_HARNESS_H

LDAP_BEGIN_DECL

struct harness_conf_info {
    char *h_host;
    in_port_t h_port;

    char *h_identifier;

    Connection *h_conn;
};

ldap_pvt_thread_start_t harness_callback;

int harness_back_init_cf( BackendInfo *bi );

LDAP_END_DECL

#endif /* SLAPD_HARNESS_H */
