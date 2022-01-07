#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This work is part of OpenLDAP Software <http://www.openldap.org/>.
#
# Copyright 2021-2022 The OpenLDAP Foundation.
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

import ldap0
import logging
import os
import pathlib
import pytest
import secrets
import tempfile

from ldap0.controls.readentry import PostReadControl

from .slapd import server


SOURCEROOT = pathlib.Path(os.environ.get('TOP_SRCDIR', "..")).absolute()
BUILDROOT = pathlib.Path(os.environ.get('TOP_BUILDDIR', SOURCEROOT)).absolute()


logger = logging.getLogger(__name__)


class Database:
    have_directory = True

    def __init__(self, server, suffix, backend):
        self.server = server
        self.suffix = suffix
        self.rootdn = suffix
        self.secret = secrets.token_urlsafe()
        self.overlays = []

        if suffix in server.suffixes:
            raise RuntimeError(f"Suffix {suffix} already configured in server")

        if self.have_directory:
            self.directory = tempfile.TemporaryDirectory(dir=server.home)

        conn = server.connect()
        conn.simple_bind_s("cn=config", server.secret)

        # We're just after the generated DN, no other attributes at the moment
        control = PostReadControl(True, [])

        result = conn.add_s(
            f"olcDatabase={backend},cn=config", self._entry(),
            req_ctrls=[control])
        dn = result.ctrls[0].res.dn_s

        self.dn = dn
        server.suffixes[suffix] = self

    def _entry(self):
        entry = {
            "objectclass": [self.objectclass.encode()],
            "olcSuffix": [self.suffix.encode()],
            "olcRootDN": [self.suffix.encode()],
            "olcRootPW": [self.secret.encode()],
        }
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
        entry = {
            "olcDbMaxSize": [str(self._size).encode()],
        }
        return {**super()._entry(), **entry}


class LDAP(Database):
    have_directory = False
    objectclass = "olcLDAPConfig"

    def __init__(self, server, suffix, uris):
        self.uris = uris
        super().__init__(server, suffix, "ldap")

    def _entry(self):
        entry = {
            "olcDbURI": [" ".join(self.uris).encode()],
        }
        return {**super()._entry(), **entry}


backend_types = {
    "mdb": MDB,
    "ldap": LDAP,
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
