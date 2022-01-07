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

import logging
import os
import pathlib

from ldap0.controls.readentry import PostReadControl


SOURCEROOT = pathlib.Path(os.environ.get('TOP_SRCDIR', "..")).absolute()
BUILDROOT = pathlib.Path(os.environ.get('TOP_BUILDDIR', SOURCEROOT)).absolute()


logger = logging.getLogger(__name__)


class Overlay:
    def __init__(self, database, overlay, order=-1):
        self.database = database
        server = database.server

        conn = server.connect()
        conn.simple_bind_s("cn=config", server.secret)

        if isinstance(overlay, pathlib.Path):
            overlay_name = overlay.stem
        else:
            overlay_name = overlay
            overlay = BUILDROOT/"servers"/"slapd"/"overlays"/overlay_name

        server.load_module(overlay)

        # We're just after the generated DN, no other attributes at the moment
        control = PostReadControl(True, [])

        result = conn.add_s(
            f"olcOverlay={overlay_name},{database.dn}", self._entry(),
            req_ctrls=[control])
        self.dn = result.ctrls[0].res.dn_s

        if order == -1:
            database.overlays.append(self)
        else:
            raise NotImplementedError
            database.overlays.insert(order, self)

    def _entry(self):
        entry = {
            "objectclass": [self.objectclass.encode()],
        }
        return entry
