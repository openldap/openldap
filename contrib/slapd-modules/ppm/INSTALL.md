INSTALLATION
============

Build dependencies
------------------
OpenLDAP sources must be available. For an easier build, copy all ppm module
into contrib/slapd-modules OpenLDAP source directory.

Build
-----
Be sure to have copied ppm module into contrib/slapd-modules OpenLDAP source
directory.

Adapt the Makefile command to indicate:
OLDAP_SOURCES : should point to OpenLDAP source directory
CONFIG: where the ppm.conf example configuration file will finally stand
        note: ppm configuration now lies into pwdCheckModuleArg password policy attribute
              provided config file is only helpful as an example or for testing
LIBDIR: where the library will be installed
DEBUG: If defined, ppm logs its actions with syslog

If necessary, you can also adapt some OpenLDAP source directories (if changed):
LDAP_INC : OpenLDAP headers directory
LDAP_LIBS : OpenLDAP built libraries directory

then type:

```
make clean
make CONFIG=/etc/openldap/ppm.conf OLDAP_SOURCES=../../..
make test
make install CONFIG=/etc/openldap/ppm.conf LIBDIR=/usr/lib/openldap
```


For LTB build, use rather:

```
make clean
make "CONFIG=/usr/local/openldap/etc/openldap/ppm.conf" "OLDAP_SOURCES=.."
make test
make install CONFIG=/usr/local/openldap/etc/openldap/ppm.conf LIBDIR=/usr/local/openldap/lib64
```

