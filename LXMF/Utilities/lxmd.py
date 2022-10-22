#!/usr/bin/env python3

# MIT License
#
# Copyright (c) 2016-2022 Mark Qvist / unsigned.io
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import RNS
import LXMF
import argparse
import time
import os

from LXMF._version import __version__

from RNS.vendor.configobj import ConfigObj
identity = None
lxmd_config = None
message_router = None
lxmf_destination = None
active_configuration = {}

def create_default_config(configpath):
    lxmd_config = ConfigObj(__default_lxmd_config__.splitlines())
    lxmd_config.filename = configpath
    lxmd_config.write()

def apply_config():
    # TODO: Apply configuration
    active_configuration["display_name"] = "Anonymous Peer"
    active_configuration["enable_propagation_node"] = True
    active_configuration["message_storage_limit"] = 2000
    active_configuration["prioritised_lxmf_destinations"] = []
    active_configuration["ignored_lxmf_destinations"] = []

def lxmf_delivery(lxm):
    # TODO: Implement delivery callback
    pass

def program_setup(configdir, rnsconfigdir, run_pn, verbosity = 0, quietness = 0, service = False):
    targetloglevel = 3+verbosity-quietness

    if service:
        targetlogdest  = RNS.LOG_FILE
        targetloglevel = None
    else:
        targetlogdest  = RNS.LOG_STDOUT

    # Get configuration
    if configdir == None:
        if os.path.isdir("/etc/lxmd") and os.path.isfile("/etc/lxmd/config"):
            configdir = "/etc/lxmd"
        elif os.path.isdir(RNS.Reticulum.userdir+"/.config/lxmd") and os.path.isfile(Reticulum.userdir+"/.config/lxmd/config"):
            configdir = RNS.Reticulum.userdir+"/.config/lxmd"
        else:
            configdir = RNS.Reticulum.userdir+"/.lxmd"

    configpath   = configdir+"/config"
    identitypath = configdir+"/identity"
    storagedir   = configdir+"/storage"

    if not os.path.isdir(storagedir):
        os.makedirs(storagedir)

    if os.path.isfile(configpath):
        try:
            lxmd_config = ConfigObj(configpath)
        except Exception as e:
            RNS.log("Could not parse the configuration at "+configpath, RNS.LOG_ERROR)
            RNS.log("Check your configuration file for errors!", RNS.LOG_ERROR)
            RNS.panic()
    else:
        RNS.log("Could not load config file, creating default configuration file...")
        create_default_config(configpath)
        RNS.log("Default config file created. Make any necessary changes in "+configpath+" and restart Reticulum if needed.")
        time.sleep(1.5)

    apply_config()
    RNS.log("Configuration loaded from "+configpath, RNS.LOG_VERBOSE)

    # Start Reticulum
    RNS.log("Substantiating Reticulum...")
    reticulum = RNS.Reticulum(configdir=rnsconfigdir, loglevel=targetloglevel, logdest=targetlogdest)

    # Generate or load primary identity
    if os.path.isfile(identitypath):
        try:
            identity = RNS.Identity.from_file(identitypath)
            if identity != None:
                RNS.log("Loaded Primary Identity %s" % (str(identity)))
            else:
                RNS.log("Could not load the Primary Identity from "+identitypath, RNS.LOG_ERROR)
                nomadnet.panic()
        except Exception as e:
            RNS.log("Could not load the Primary Identity from "+identitypath, RNS.LOG_ERROR)
            RNS.log("The contained exception was: %s" % (str(e)), RNS.LOG_ERROR)
            exit(1)
    else:
        try:
            RNS.log("No Primary Identity file found, creating new...")
            identity = RNS.Identity()
            identity.to_file(identitypath)
            RNS.log("Created new Primary Identity %s" % (str(identity)))
        except Exception as e:
            RNS.log("Could not create and save a new Primary Identity", RNS.LOG_ERROR)
            RNS.log("The contained exception was: %s" % (str(e)), RNS.LOG_ERROR)
            exit(2)

    # Start LXMF
    message_router = LXMF.LXMRouter(identity = identity, storagepath = storagedir, autopeer = True)
    message_router.register_delivery_callback(lxmf_delivery)

    for destination_hash in active_configuration["ignored_lxmf_destinations"]:
        message_router.ignore_destination(destination_hash)

    lxmf_destination = message_router.register_delivery_identity(identity, display_name=active_configuration["display_name"])

    RNS.Identity.remember(
        packet_hash=None,
        destination_hash=lxmf_destination.hash,
        public_key=identity.get_public_key(),
        app_data=None
    )

    RNS.log("LXMF Router ready to receive on "+RNS.prettyhexrep(lxmf_destination.hash))

    if active_configuration["enable_propagation_node"]:
        message_router.set_message_storage_limit(megabytes=active_configuration["message_storage_limit"])
        for dest_str in active_configuration["prioritised_lxmf_destinations"]:
            try:
                dest_hash = bytes.fromhex(dest_str)
                if len(dest_hash) == RNS.Reticulum.TRUNCATED_HASHLENGTH//8:
                    message_router.prioritise(dest_hash)

            except Exception as e:
                RNS.log("Cannot prioritise "+str(dest_str)+", it is not a valid destination hash", RNS.LOG_ERROR)

        message_router.enable_propagation()

        RNS.log("LXMF Propagation Node started on "+RNS.prettyhexrep(message_router.propagation_destination.hash))

    RNS.log("Started lxmd version {version}".format(version=__version__), RNS.LOG_NOTICE)

    while True:
        time.sleep(1)

def main():
    try:
        parser = argparse.ArgumentParser(description="Lightweight Extensible Messaging Daemon")
        parser.add_argument("--config", action="store", default=None, help="path to alternative lxmd config directory", type=str)
        parser.add_argument("--rnsconfig", action="store", default=None, help="path to alternative Reticulum config directory", type=str)
        parser.add_argument("-p", "--propagation-node", action="store_true", default=False, help="run an LXMF Propagation Node")
        parser.add_argument("-i", "--on-inbound", action="store", metavar="PATH", default=None, help="executable to run when a message is received", type=str)
        parser.add_argument("-v", "--verbose", action="count", default=0)
        parser.add_argument("-q", "--quiet", action="count", default=0)
        parser.add_argument("-s", "--service", action="store_true", default=False, help="lxmd is running as a service and should log to file")
        parser.add_argument("--exampleconfig", action="store_true", default=False, help="print verbose configuration example to stdout and exit")
        parser.add_argument("--version", action="version", version="lxmd {version}".format(version=__version__))
        
        args = parser.parse_args()

        if args.exampleconfig:
            print(__default_lxmd_config__)
            exit()

        program_setup(
            configdir = args.config,
            rnsconfigdir=args.rnsconfig,
            run_pn=args.propagation_node,
            verbosity=args.verbose,
            quietness=args.quiet,
            service=args.service
        )

    except KeyboardInterrupt:
        print("")
        exit()

__default_lxmd_config__ = """# This is an example LXM Daemon config file.
# You should probably edit it to suit your
# intended usage.

[propagation]

# Whether to enable propagation node
enable_node = no

# Automatic announce interval in minutes.
# 6 hours by default.
announce_interval = 360

# Whether to announce when the node starts.
announce_at_start = yes

# Wheter to automatically peer with other
# propagation nodes on the network.
autopeer = yes

# The maximum amount of storage to use for
# the LXMF Propagation Node message store,
# specified in megabytes. When this limit
# is reached, LXMF will periodically remove
# messages in its message store. By default,
# LXMF prioritises keeping messages that are
# new and small. Large and old messages will
# be removed first. This setting is optional
# and defaults to 2 gigabytes.
# message_storage_limit = 2000

# You can tell the LXMF message router to
# prioritise storage for one or more
# destinations. If the message store reaches
# the specified limit, LXMF will prioritise
# keeping messages for destinations specified
# with this option. This setting is optional,
# and generally you do not need to use it.
# prioritise_destinations = 41d20c727598a3fbbdf9106133a3a0ed, d924b81822ca24e68e2effea99bcb8cf


[lxmf]

# The LXM Daemon will create an LXMF destination
# that it can receive messages on. This option sets
# the announced display name for this destination.
display_name = Anonymous Peer

# It is possible to announce the internal LXMF
# destination when the LXM Daemon starts up.
announce_at_start = no


[logging]
# Valid log levels are 0 through 7:
#   0: Log only critical information
#   1: Log errors and lower log levels
#   2: Log warnings and lower log levels
#   3: Log notices and lower log levels
#   4: Log info and lower (this is the default)
#   5: Verbose logging
#   6: Debug logging
#   7: Extreme logging
loglevel = 4

"""

if __name__ == "__main__":
    main()
