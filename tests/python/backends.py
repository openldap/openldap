#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This work is part of OpenLDAP Software <http://www.openldap.org/>.
#
# Copyright 2021-2026 The OpenLDAP Foundation.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted only as authorized by the OpenLDAP
# Public License.
#
# A copy of this license is available in the file LICENSE in the
# top-level directory of the distribution or, alternatively, at
# <http://www.OpenLDAP.org/license.html>.
#
# ACKNOWLEDGEMENTS:
# This work was initially developed by Ondřej Kuzník
# for inclusion in OpenLDAP Software.
"""
OpenLDAP fixtures for backends
"""

import ldap
import logging
import os
import pathlib
import pytest
import secrets
import tempfile

from ldap.controls.readentry import PostReadControl

from .slapd import server


SOURCEROOT = pathlib.Path(os.environ.get('TOP_SRCDIR', "..")).absolute()
BUILDROOT = pathlib.Path(os.environ.get('TOP_BUILDDIR', SOURCEROOT)).absolute()

NOTSET = object()

logger = logging.getLogger(__name__)


class Database:
    have_directory = True

    def __init__(self, server, suffix, backend, *,
                 rootdn=NOTSET, module=NOTSET):
        if rootdn is NOTSET:
            rootdn = suffix
        if module is NOTSET:
            module = (BUILDROOT/"servers"/"slapd"/
                      f"back-{backend}"/f"back_{backend}")

        self.server = server
        self.suffix = suffix
        self.rootdn = rootdn
        self.secret = secrets.token_urlsafe()
        self.overlays = []

        if suffix in server.suffixes:
            raise RuntimeError(f"Suffix {suffix} already configured in server")

        if self.have_directory:
            self.directory = tempfile.TemporaryDirectory(dir=server.home, delete=False)

        if module:
            server.load_module(module)

        conn = server.connect()
        conn.simple_bind_s("cn=config", server.secret)

        # We're just after the generated DN, no other attributes at the moment
        control = PostReadControl(True, ["1.1"])

        _, _, _, ctrls = conn.add_ext_s(
            f"olcDatabase={backend},cn=config", list(self._entry().items()),
            serverctrls=[control])
        dn = ctrls[0].dn

        self.dn = dn
        server.suffixes[suffix] = self

    def _entry(self):
        entry = {
            "objectclass": [self.objectclass.encode()],
            "olcSuffix": [self.suffix.encode()],
        }
        if self.rootdn is not None:
            entry["olcRootDN"] = [self.rootdn.encode()]
            if self.rootdn.endswith(self.suffix):
                entry["olcRootPW"] = [self.secret.encode()]
        if self.have_directory:
            entry["olcDbDirectory"] = [self.directory.name.encode()]
        return entry


class MDB(Database):
    have_directory = True
    objectclass = "olcMdbConfig"

    _size = 10 * (1024 ** 3)

    def __init__(self, server, suffix):
        super().__init__(server, suffix, "mdb")

    def _entry(self):
        return super()._entry() | {
            "olcDbMaxSize": [str(self._size).encode()],
        }


class LDAP(Database):
    have_directory = False
    objectclass = "olcLDAPConfig"

    def __init__(self, server, suffix, uris):
        self.uris = uris
        super().__init__(server, suffix, "ldap")

    def _entry(self):
        return super()._entry() | {
            "olcDbURI": [" ".join(self.uris).encode()],
        }


class Monitor(Database):
    have_directory = False
    objectclass = "olcMonitorConfig"

    def __init__(self, server):
        super().__init__(server, "cn=monitor", "monitor",
                         rootdn="cn=config", module=None)


backend_types = {
    "mdb": MDB,
    "ldap": LDAP,
    "monitor": Monitor,
}


@pytest.fixture(scope="class")
def db(request, server):
    marker = request.node.get_closest_marker("db")
    database_type = marker.args[0] if marker else "mdb"
    klass = backend_types[database_type]

    conn = server.connect()
    conn.simple_bind_s("cn=config", server.secret)

    db = klass(server, "cn=test")
    yield db

    conn.delete_s(db.dn)


class TestDB:
    def test_db_setup(self, db):
        pass
