INSTALLATION
============

Dependencies
------------------
ppm is provided along with OpenLDAP sources. By default, it is available into contrib/slapd-modules.
 - make sure both OpenLDAP sources and ppm are available for building.
 - install cracklib development files if you want to test passwords against cracklib


Build
-----
Enter contrib/slapd-modules/ppm directory

You can optionally customize some variables if you don't want the default ones:
- prefix: prefix of the path where ppm is to be installed (default to /usr/local)
- libdir: where the ppm library is to be deployed (default to /lib under prefix)
- etcdir: where the ppm example policy is to be deployed (default to /etc/openldap under prefix)
- LDAP_SRC: path to OpenLDAP source directory
- Options in OPTS variable:
    CONFIG_FILE: (DEPRECATED) path to a ppm configuration file (see PPM_READ_FILE in ppm.h)
        note: ppm configuration now lies into pwdCheckModuleArg password policy attribute
              provided example file is only helpful as an example or for testing
    CRACKLIB: if defined, link against cracklib
    DEBUG: If defined, ppm logs its actions with syslog


To build ppm, simply run these commands:
(based upon the default prefix /usr/local of OpenLDAP)

```
make clean
make
make test
make install
```

Here is an illustrative example showing how to overload some options:

```
make clean
make LDAP_SRC=../../.. prefix=/usr/local libdir=/usr/local/lib 
make test LDAP_SRC=../../..
make install prefix=/usr/local libdir=/usr/local/lib
```

