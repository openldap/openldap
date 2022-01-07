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
OpenLDAP server fixtures
"""

import ldap0
import ldapurl
import logging
import os
import pathlib
import pytest
import re
import secrets
import signal
import socket
import subprocess
import tempfile
import textwrap

from ldap0.ldapobject import LDAPObject


SOURCEROOT = pathlib.Path(os.environ.get('TOP_SRCDIR', "..")).absolute()
BUILDROOT = pathlib.Path(os.environ.get('TOP_BUILDDIR', SOURCEROOT)).absolute()


logger = logging.getLogger(__name__)


class Server:
    def __init__(self, where, manager, cnconfig=True, schemas=None):
        self.path = where
        self.home = pathlib.Path(self.path.name)
        self.executable = BUILDROOT/'servers'/'slapd'/'slapd'

        self.manager = manager
        self.cnconfig = cnconfig

        self.token = secrets.token_urlsafe()
        self.secret = None
        self.level = "-1"
        self.port = 0
        self.pid = None

        if schemas is None:
            schemas = ["core", "cosine", "inetorgperson", "openldap", "nis"]

        if cnconfig and not (self.home/'slapd.d').is_dir():
            self.create_config(schemas)
        elif not cnconfig and not (self.home/'slapd.conf').is_file():
            self.create_config(schemas)

        self.process = None
        self.schema = []
        self.suffixes = {}

    def create_config(self, schemas):
        mod_harness = BUILDROOT/"tests"/"modules"/"mod-harness"/"mod_harness"
        schemadir = SOURCEROOT/"servers"/"slapd"/"schema"
        if not self.secret:
            self.secret = secrets.token_urlsafe()

        if self.cnconfig:
            confdir = self.home/'slapd.d'
            confdir.mkdir()
            includes = []

            config = """
                dn: cn=config
                objectClass: olcGlobal
                cn: config

                dn: cn=module{{0}},cn=config
                objectClass: olcModuleList
                olcModuleLoad: {mod_harness}

                dn: cn=schema,cn=config
                objectClass: olcSchemaConfig
                cn: schema

                dn: olcBackend={{0}}harness,cn=config
                objectClass: olcBkHarnessConfig
                olcBkHarnessHost: {self.manager.host}
                olcBkHarnessPort: {self.manager.port}
                olcBkHarnessIdentifier: {self.token}

                dn: olcDatabase={{0}}config,cn=config
                objectClass: olcDatabaseConfig
                olcRootPW: {self.secret}
            """.format(self=self, mod_harness=mod_harness)

            for schema in schemas:
                if not isinstance(schema, pathlib.Path):
                    schema = schemadir / (schema + ".ldif")
                includes.append(f"include: file://{schema}")

            config = "\n".join([textwrap.dedent(config), "\n", *includes])

            args = [self.executable, '-T', 'add', '-d', self.level,
                    '-n0', '-F', confdir]
            args = [str(arg) for arg in args]
            subprocess.run(args, capture_output=True, check=True,
                           cwd=self.home, text=True, input=config)
        else:
            with open(self.home/'slapd.conf', mode='w') as config:
                config.write(textwrap.dedent("""
                    moduleload {mod_harness}

                    backend harness
                    host {self.manager.host}
                    port {self.manager.port}
                    identifier {self.token}

                    database config
                    rootpw {self.secret}
                """.format(self=self, mod_harness=mod_harness)))

                includes = []
                for schema in schemas:
                    if not isinstance(schema, pathlib.Path):
                        schema = schemadir / (schema + ".schema")
                    includes.append(f"include {schema}\n")

                config.write("".join(includes))

    def test(self):
        args = [self.executable, '-T', 'test', '-d', self.level]
        if self.cnconfig:
            args += ['-F', self.home/'slapd.d']
        else:
            args += ['-f', self.home/'slapd.conf']

        args = [str(arg) for arg in args]
        return subprocess.run(args, capture_output=True, check=True,
                              cwd=self.home)

    def start(self, port=None):
        if self.process:
            raise RuntimeError("process %d still running" % self.process.pid)

        self.test()

        if port is not None:
            self.port = port

        listeners = [
            'ldapi://socket',
            'ldap://localhost:%d' % self.port,
        ]
        args = [self.executable, '-d', self.level]
        if self.cnconfig:
            args += ['-F', self.home/'slapd.d']
        else:
            args += ['-f', self.home/'slapd.conf']
        args += ['-h', ' '.join(listeners)]

        with open(self.home/'slapd.log', 'a+') as log:
            args = [str(arg) for arg in args]
            self.process = subprocess.Popen(args, stderr=log, cwd=self.home)
        self.log = open(self.home/'slapd.log', 'r+')

        self.connection, self.pid = self.manager.wait(self.token)

        line = self.connection.readline().strip()
        while line:
            if line == 'SLAPD READY':
                break
            elif line.startswith("URI="):
                uri, name = line[4:].split()
            line = self.connection.readline().strip()

    def stop(self):
        if self.process:
            os.kill(self.pid, signal.SIGHUP)
            self.process.terminate()
            self.process.wait()
        self.process = None

    def connect(self):
        return LDAPObject(str(self.uri))

    def load_module(self, module):
        if not self.cnconfig:
            raise NotImplementedError

        if not isinstance(module, pathlib.Path):
            raise NotImplementedError
        module_name = module.stem

        conn = self.connect()
        conn.simple_bind_s('cn=config', self.secret)

        moduleload_object = None
        for entry in conn.search_s('cn=config', ldap0.SCOPE_SUBTREE,
                                   'objectclass=olcModuleList',
                                   ['olcModuleLoad']):
            if not moduleload_object:
                moduleload_object = entry.dn_s
            for value in entry.entry_s.get('olcModuleLoad', []):
                if value[0] == '{':
                    value = value[value.find('}')+1:]
                if pathlib.Path(value).stem == module_name:
                    logger.warning("Module %s already loaded, ignoring",
                                   module_name)
                    return

        if moduleload_object:
            conn.modify_s(
                moduleload_object,
                [(ldap0.MOD_ADD, b'olcModuleLoad', [str(module).encode()])])
        else:
            conn.add_s('cn=module,cn=config',
                       {'objectClass': [b'olcModuleList'],
                        'olcModuleLoad': [str(module).encode()]})

    @property
    def uri(self):
        return ldapurl.LDAPUrl(urlscheme="ldapi",
                               hostport=str(self.home/'socket'))


class ServerManager:
    def __init__(self, tmp_path):
        self.tmpdir = tmp_path
        self.waiter = socket.create_server(('localhost', 0))
        self.address = self.waiter.getsockname()

    @property
    def host(self):
        return self.address[0]

    @property
    def port(self):
        return self.address[1]

    def new_server(self):
        path = tempfile.TemporaryDirectory(dir=self.tmpdir)
        return Server(path, self)

    def wait(self, token):
        s, _ = self.waiter.accept()
        f = s.makefile('r')
        response = f.readline().split()
        if response[0] != 'PID':
            response.close()
            raise RuntimeError("Unexpected response")
        if response[2] != token:
            raise NotImplementedError("Concurrent startup not implemented yet")
        return f, int(response[1])


@pytest.fixture(scope="module")
def temp(request, tmp_path_factory):
    # Stolen from pytest.tmpdir._mk_tmp
    name = request.node.name
    name = re.sub(r"[\W]", "_", name)
    MAXVAL = 30
    name = name[:MAXVAL]
    return tmp_path_factory.mktemp(name, numbered=True)


@pytest.fixture(scope="module")
def server_factory(temp):
    return ServerManager(temp)


@pytest.fixture(scope="class")
def server(server_factory):
    server = server_factory.new_server()
    server.start()
    yield server
    server.stop()
    server.path.cleanup()


def test_rootdse(server):
    conn = server.connect()
    conn.search_s("", scope=ldap0.SCOPE_BASE)
