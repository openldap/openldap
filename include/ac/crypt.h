/* Generic crypt.h */
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
 * A copy of this license is available in file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */

#ifndef _AC_CRYPT_H
#define _AC_CRYPT_H

#include <ac/unistd.h>

#if defined(HAVE_CRYPT_H) && (defined(HAVE_CRYPT_R) || !defined(HAVE_UNISTD_H))
/* crypt() is defined in <unistd.h> if that exists, otherwise <crypt.h>.
 * crypt_r() is only defined in <crypt.h> */
# include <crypt.h>
#else
 LDAP_LIBC_F(char *) (crypt) LDAP_P((const char *key, const char *salt));
#endif

#endif /* _AC_CRYPT_H */
