/* config.c - configuration of the test harness backend */
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

#include "slap.h"
#include "slap-config.h"
#include "mod-harness.h"

static int config_generic(ConfigArgs *c);

enum {
	CFG_HOST = 1,
	CFG_PORT,
	CFG_IDENTIFIER,

	CFG_LAST
};

static ConfigTable harness_cf_table[] = {
	{ "host", "hostname", 2, 2, 0, ARG_OFFSET|ARG_STRING|CFG_HOST,
		(void *)offsetof(struct harness_conf_info, h_host),
		"( OLcfgDbAt:14.1 NAME 'olcBkHarnessHost' "
			"DESC 'Hostname to connect to' "
			"EQUALITY caseIgnoreMatch "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "port", "port", 2, 2, 0, ARG_MAGIC|ARG_UINT|CFG_PORT,
		&config_generic,
		"( OLcfgDbAt:14.2 NAME 'olcBkHarnessPort' "
			"DESC 'Port to connect to' "
			"EQUALITY integerMatch "
			"SYNTAX OMsInteger SINGLE-VALUE )", NULL, NULL },
	{ "identifier", "identifier", 2, 2, 0, ARG_OFFSET|ARG_STRING|CFG_IDENTIFIER,
		(void *)offsetof(struct harness_conf_info, h_identifier),
		"( OLcfgDbAt:14.3 NAME 'olcBkHarnessIdentifier' "
			"DESC 'A token identifying this server' "
			"EQUALITY caseIgnoreMatch "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ NULL, NULL, 0, 0, 0, ARG_IGNORED, NULL }
};

static ConfigOCs harness_ocs[] = {
	{ "( OLcfgBkOc:14.1 "
		"NAME 'olcBkHarnessConfig' "
		"DESC 'Harness module backend configuration' "
		"SUP olcBackendConfig "
		"MUST ( olcBkHarnessHost "
			"$ olcBkHarnessPort "
			"$ olcBkHarnessIdentifier "
		") )",
		Cft_Backend, harness_cf_table,
	},
	{ NULL, 0, NULL }
};

static int
config_generic(ConfigArgs *c)
{
	struct harness_conf_info *hi = c->bi->bi_private;
	int rc = LDAP_SUCCESS;

	if ( c->op == SLAP_CONFIG_EMIT ) {
		switch( c->type ) {
			case CFG_PORT:
				c->value_uint = hi->h_port;
				break;
			default:
				rc = 1;
				break;
		}
		return rc;

	} else if ( c->op == LDAP_MOD_DELETE ) {
		/* We don't allow removing/reconfiguration (yet) */
		Debug( LDAP_DEBUG_ANY,
				"%s: mod_harness doesn't support reconfiguration\n",
				c->log );
		return 1;
	}

	switch ( c->type ) {
		case CFG_PORT:
			if ( c->value_uint <= 0 || c->value_uint > 65535 ) {
				Debug( LDAP_DEBUG_ANY,
						"%s: port %d invalid\n",
						c->log, c->value_uint );
				rc = 1;
			}
			hi->h_port = c->value_uint;
			break;
		default:
			Debug( LDAP_DEBUG_ANY,
					"%s: unknown CFG_TYPE %d\n",
					c->log, c->type );
			return 1;
	}

	return rc;
}

int
harness_back_init_cf( BackendInfo *bi )
{
	bi->bi_cf_ocs = harness_ocs;

	/* Make sure we don't exceed the bits reserved for userland */
	config_check_userland( CFG_LAST );

	return config_register_schema( harness_cf_table, harness_ocs );
}
