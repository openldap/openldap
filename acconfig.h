/* acconfig.h
   This file is in the public domain.

   Descriptive text for the C preprocessor macros that
   the distributed Autoconf macros can define.
   No software package will use all of them; autoheader copies the ones
   your configure.in uses into your configuration header file templates.

   The entries are in sort -df order: alphabetical, case insensitive,
   ignoring punctuation (such as underscores).  Although this order
   can split up related entries, it makes it easier to check whether
   a given entry is in the file.

   Leave the following blank line there!!  Autoheader needs it.  */


/* define this if sys_errlist is not defined in stdio.h or errno.h */
#undef DECL_SYS_ERRLIST

/* define this to use LDAP LDBM backends */
#undef LDAP_LDBM

/* define this to use LDAP PASSWD backends */
#undef LDAP_PASSWD

/* define this to use LDAP SHELL backends */
#undef LDAP_SHELL

/* define this to use DB BTREES */
#undef LDBM_USE_DBBTREE

/* define this to use DB HASH */
#undef LDBM_USE_DBHASH

/* define this to use GNU DBM */
#undef LDBM_USE_GDBM

/* define this to use NDBM */
#undef LDBM_USE_NDBM

/* define this you have crypt */
#undef HAVE_CRYPT


/* Leave that blank line there!!  Autoheader needs it.
   If you're adding to this file, keep in mind:
   The entries are in sort -df order: alphabetical, case insensitive,
   ignoring punctuation (such as underscores).  */
