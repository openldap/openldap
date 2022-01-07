/* connection.c - communication with test harness */
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

#include "slap.h"
#include "mod-harness.h"

void *
harness_callback( void *ctx, void *arg )
{
    Debug( LDAP_DEBUG_ANY, "harness_callback: "
            "not expecting to receive anything yet on this connection!\n" );
    assert( slapd_shutdown );

    return NULL;
}
