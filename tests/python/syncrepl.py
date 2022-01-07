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
OpenLDAP fixtures for overlays
"""

import ldap0
import logging
import os
import pathlib
import pytest
import subprocess


from .slapd import server
from .backends import db, backend_types
from .overlays import Overlay


SOURCEROOT = pathlib.Path(os.environ.get('TOP_SRCDIR', "..")).absolute()
BUILDROOT = pathlib.Path(os.environ.get('TOP_BUILDDIR', SOURCEROOT)).absolute()


logger = logging.getLogger(__name__)


class Syncprov(Overlay):
    objectclass = 'olcSyncprovConfig'

    def __init__(self, backend, *args, **kwargs):
        super().__init__(backend, 'syncprov', *args, **kwargs)


@pytest.fixture(scope="class")
def provider(request, db):
    conn = server.connect()
    conn.simple_bind_s("cn=config", server.secret)

    syncprov = Syncprov(db)
    yield db.server

    conn.delete_s(syncprov.dn)


@pytest.fixture(scope="class")
def replica(request, server_factory, provider):
    raise NotImplementedError


@pytest.fixture(scope="class")
def mmr(request, server_factory):
    mmr_marker = request.node.get_closest_marker("mmr")
    mmr_args = mmr_marker and mmr_marker.args or {}
    server_count = mmr_args.get("mmr", 4)
    serverids = mmr_args.get("serverids", range(1, server_count+1))
    server_connections = mmr_args.get("connections") or \
        {consumer: {provider for provider in serverids if provider != consumer}
            for consumer in serverids}

    database_marker = request.node.get_closest_marker("db")
    database_type = database_marker.args[0] if database_marker else "mdb"
    db_class = backend_types[database_type]

    servers = {}
    connections = {}
    for serverid in serverids:
        server = server_factory.new_server()
        server.start()
        conn = server.connect()
        conn.simple_bind_s("cn=config", server.secret)

        conn.modify_s("cn=config", [
                (ldap0.MOD_REPLACE, b"olcServerId", [str(serverid).encode()])])

        server.serverid = serverid
        servers[serverid] = server
        connections[serverid] = conn

        db = db_class(server, "dc=example,dc=com")
        syncprov = Syncprov(db)

    for serverid, server in servers.items():
        suffix = db.suffix

        syncrepl = []
        for providerid in server_connections[serverid]:
            provider = servers[providerid]
            db = provider.suffixes[suffix]
            syncrepl.append((
                f'rid={providerid} provider={provider.uri} '
                f'searchbase="{db.suffix}" '
                f'type=refreshAndPersist retry="1 +" '
                f'bindmethod=simple '
                f'binddn="{db.suffix}" credentials="{db.secret}"').encode())

        connections[serverid].modify_s(db.dn, [
            (ldap0.MOD_REPLACE, b"olcSyncrepl", syncrepl),
            (ldap0.MOD_REPLACE, b"olcMultiprovider", [b"TRUE"])])

    yield servers

    for serverid, server in servers.items():
        server.stop()
        server.path.cleanup()


# TODO: after we switch to asyncio, make use of the syncmonitor module
# directly.
# We should even wrap this in a class to allow finer grained control
# over the behaviour like waiting for partial syncs etc.
def wait_for_resync(searchbase, servers, timeout=30):
    subprocess.check_call(["synccheck", "-p", "--base", searchbase,
                           "--timeout", str(timeout),
                           *[str(server.uri) for server in servers],
                           ], timeout=timeout+5)


def test_mmr(mmr):
    suffix = "dc=example,dc=com"
    entries_added = set()

    connections = []
    for serverid, server in mmr.items():
        db = server.suffixes[suffix]
        conn = server.connect()
        conn.simple_bind_s(db.rootdn, db.secret)

        if not entries_added:
            conn.add_s(suffix, {
                "objectClass": [b"organization",
                                b"domainRelatedObject",
                                b"dcobject"],
                "o": [b"Example, Inc."],
                "associatedDomain": [b"example.com"]})
            entries_added.add(suffix)
            # Make sure all hosts have the suffix entry
            wait_for_resync(suffix, mmr.values())

        dn = f"cn=entry{serverid},{suffix}"
        conn.add_s(dn, {"objectClass": [b"device"],
                        "description": [(f"Entry created on serverid "
                                         f"{serverid}").encode()]})
        entries_added.add(dn)
        connections.append(conn)

    wait_for_resync(suffix, mmr.values())

    for conn in connections:
        result = conn.search_s(suffix, ldap0.SCOPE_SUBTREE, attrlist=['1.1'])
        dns = {entry.dn_s for entry in result}
        assert dns == entries_added, \
                f"Server {serverid} contents do not match expectations"
