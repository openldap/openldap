dnl Check for declaration of sys_errlist in one of stdio.h and errno.h.
dnl Declaration of sys_errlist on BSD4.4 interferes with our declaration.
dnl Reported by Keith Bostic.
dnl
AC_DEFUN([CF_SYS_ERRLIST],
[
AC_MSG_CHECKING([declaration of sys_errlist])
AC_CACHE_VAL(cf_cv_dcl_sys_errlist,[
	AC_TRY_COMPILE([
#include <stdio.h>
#include <sys/types.h>
#include <errno.h> ],
	[char *c = (char *) *sys_errlist],
	[cf_cv_dcl_sys_errlist=yes],
	[cf_cv_dcl_sys_errlist=no])])
AC_MSG_RESULT($cf_cv_dcl_sys_errlist)

# It's possible (for near-UNIX clones) that sys_errlist doesn't exist
if test $cf_cv_dcl_sys_errlist = no ; then
	AC_DEFINE(DECL_SYS_ERRLIST)
	AC_MSG_CHECKING([existence of sys_errlist])
	AC_CACHE_VAL(cf_cv_have_sys_errlist,[
		AC_TRY_LINK([#include <errno.h>],
			[char *c = (char *) *sys_errlist],
			[cf_cv_have_sys_errlist=yes],
			[cf_cv_have_sys_errlist=no])])
	AC_MSG_RESULT($cf_cv_have_sys_errlist)
fi
])dnl
