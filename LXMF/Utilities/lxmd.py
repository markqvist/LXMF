#!/usr/bin/env python3

# Reticulum License
#
# Copyright (c) 2020-2025 Mark Qvist
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# - The Software shall not be used in any kind of system which includes amongst
#   its functions the ability to purposefully do harm to human beings.
#
# - The Software shall not be used, directly or indirectly, in the creation of
#   an artificial intelligence, machine learning or language model training
#   dataset, including but not limited to any use that contributes to the
#   training or development of such a model or algorithm.
#
# - The above copyright notice and this permission notice shall be included in
#   all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

DEFFERED_JOBS_DELAY = 10
JOBS_INTERVAL = 5

import RNS
import LXMF
import argparse
import threading
import subprocess
import shlex
import time
import os

from LXMF._version import __version__
from LXMF import APP_NAME

from RNS.vendor.configobj import ConfigObj

configpath     = None
ignoredpath    = None
identitypath   = None
storagedir     = None
lxmdir         = None
targetloglevel = None

identity = None
lxmd_config = None
message_router = None
lxmf_destination = None
active_configuration = {}

last_peer_announce = None
last_node_announce = None

def create_default_config(configpath):
    lxmd_config = ConfigObj(__default_lxmd_config__.splitlines())
    lxmd_config.filename = configpath
    lxmd_config.write()

def apply_config():
    global active_configuration, targetloglevel
    try:
        # Load peer settings
        if "lxmf" in lxmd_config and "display_name" in lxmd_config["lxmf"]:
            active_configuration["display_name"] = lxmd_config["lxmf"]["display_name"]
        else:
            active_configuration["display_name"] = "Anonymous Peer"

        if "lxmf" in lxmd_config and "announce_at_start" in lxmd_config["lxmf"]:
            active_configuration["peer_announce_at_start"] = lxmd_config["lxmf"].as_bool("announce_at_start")
        else:
            active_configuration["peer_announce_at_start"] = False

        if "lxmf" in lxmd_config and "announce_interval" in lxmd_config["lxmf"]:
            active_configuration["peer_announce_interval"] = lxmd_config["lxmf"].as_int("announce_interval")*60
        else:
            active_configuration["peer_announce_interval"] = None
        
        if "lxmf" in lxmd_config and "delivery_transfer_max_accepted_size" in lxmd_config["lxmf"]:
            active_configuration["delivery_transfer_max_accepted_size"] = lxmd_config["lxmf"].as_float("delivery_transfer_max_accepted_size")
            if active_configuration["delivery_transfer_max_accepted_size"] < 0.38:
                active_configuration["delivery_transfer_max_accepted_size"] = 0.38
        else:
            active_configuration["delivery_transfer_max_accepted_size"] = 1000

        if "lxmf" in lxmd_config and "on_inbound" in lxmd_config["lxmf"]:
            active_configuration["on_inbound"] = lxmd_config["lxmf"]["on_inbound"]
        else:
            active_configuration["on_inbound"] = None

        # Load propagation node settings
        if "propagation" in lxmd_config and "enable_node" in lxmd_config["propagation"]:
            active_configuration["enable_propagation_node"] = lxmd_config["propagation"].as_bool("enable_node")
        else:
            active_configuration["enable_propagation_node"] = False

        if "propagation" in lxmd_config and "node_name" in lxmd_config["propagation"]:
            active_configuration["node_name"] = lxmd_config["propagation"].get("node_name")
        else:
            active_configuration["node_name"] = None

        if "propagation" in lxmd_config and "auth_required" in lxmd_config["propagation"]:
            active_configuration["auth_required"] = lxmd_config["propagation"].as_bool("auth_required")
        else:
            active_configuration["auth_required"] = False

        if "propagation" in lxmd_config and "announce_at_start" in lxmd_config["propagation"]:
            active_configuration["node_announce_at_start"] = lxmd_config["propagation"].as_bool("announce_at_start")
        else:
            active_configuration["node_announce_at_start"] = False

        if "propagation" in lxmd_config and "autopeer" in lxmd_config["propagation"]:
            active_configuration["autopeer"] = lxmd_config["propagation"].as_bool("autopeer")
        else:
            active_configuration["autopeer"] = True

        if "propagation" in lxmd_config and "autopeer_maxdepth" in lxmd_config["propagation"]:
            active_configuration["autopeer_maxdepth"] = lxmd_config["propagation"].as_int("autopeer_maxdepth")
        else:
            active_configuration["autopeer_maxdepth"] = None

        if "propagation" in lxmd_config and "announce_interval" in lxmd_config["propagation"]:
            active_configuration["node_announce_interval"] = lxmd_config["propagation"].as_int("announce_interval")*60
        else:
            active_configuration["node_announce_interval"] = None

        if "propagation" in lxmd_config and "message_storage_limit" in lxmd_config["propagation"]:
            active_configuration["message_storage_limit"] = lxmd_config["propagation"].as_float("message_storage_limit")
            if active_configuration["message_storage_limit"] < 0.005:
                active_configuration["message_storage_limit"] = 0.005
        else:
            active_configuration["message_storage_limit"] = 500
        
        if "propagation" in lxmd_config and "propagation_transfer_max_accepted_size" in lxmd_config["propagation"]:
            active_configuration["propagation_transfer_max_accepted_size"] = lxmd_config["propagation"].as_float("propagation_transfer_max_accepted_size")
            if active_configuration["propagation_transfer_max_accepted_size"] < 0.38:
                active_configuration["propagation_transfer_max_accepted_size"] = 0.38
        else:
            active_configuration["propagation_transfer_max_accepted_size"] = 256

        if "propagation" in lxmd_config and "propagation_message_max_accepted_size" in lxmd_config["propagation"]:
            active_configuration["propagation_transfer_max_accepted_size"] = lxmd_config["propagation"].as_float("propagation_message_max_accepted_size")
            if active_configuration["propagation_transfer_max_accepted_size"] < 0.38:
                active_configuration["propagation_transfer_max_accepted_size"] = 0.38
        else:
            active_configuration["propagation_transfer_max_accepted_size"] = 256
        
        if "propagation" in lxmd_config and "propagation_sync_max_accepted_size" in lxmd_config["propagation"]:
            active_configuration["propagation_sync_max_accepted_size"] = lxmd_config["propagation"].as_float("propagation_sync_max_accepted_size")
            if active_configuration["propagation_sync_max_accepted_size"] < 0.38:
                active_configuration["propagation_sync_max_accepted_size"] = 0.38
        else:
            active_configuration["propagation_sync_max_accepted_size"] = 256*40
        
        if "propagation" in lxmd_config and "propagation_stamp_cost_target" in lxmd_config["propagation"]:
            active_configuration["propagation_stamp_cost_target"] = lxmd_config["propagation"].as_int("propagation_stamp_cost_target")
            if active_configuration["propagation_stamp_cost_target"] < LXMF.LXMRouter.PROPAGATION_COST_MIN:
                active_configuration["propagation_stamp_cost_target"] = LXMF.LXMRouter.PROPAGATION_COST_MIN
        else:
            active_configuration["propagation_stamp_cost_target"] = LXMF.LXMRouter.PROPAGATION_COST
        
        if "propagation" in lxmd_config and "propagation_stamp_cost_flexibility" in lxmd_config["propagation"]:
            active_configuration["propagation_stamp_cost_flexibility"] = lxmd_config["propagation"].as_int("propagation_stamp_cost_flexibility")
            if active_configuration["propagation_stamp_cost_flexibility"] < 0:
                active_configuration["propagation_stamp_cost_flexibility"] = 0
        else:
            active_configuration["propagation_stamp_cost_flexibility"] = LXMF.LXMRouter.PROPAGATION_COST_FLEX
        
        if "propagation" in lxmd_config and "peering_cost" in lxmd_config["propagation"]:
            active_configuration["peering_cost"] = lxmd_config["propagation"].as_int("peering_cost")
            if active_configuration["peering_cost"] < 0:
                active_configuration["peering_cost"] = 0
        else:
            active_configuration["peering_cost"] = LXMF.LXMRouter.PEERING_COST
        
        if "propagation" in lxmd_config and "remote_peering_cost_max" in lxmd_config["propagation"]:
            active_configuration["remote_peering_cost_max"] = lxmd_config["propagation"].as_int("remote_peering_cost_max")
            if active_configuration["remote_peering_cost_max"] < 0:
                active_configuration["remote_peering_cost_max"] = 0
        else:
            active_configuration["remote_peering_cost_max"] = LXMF.LXMRouter.MAX_PEERING_COST
        
        if "propagation" in lxmd_config and "prioritise_destinations" in lxmd_config["propagation"]:
            active_configuration["prioritised_lxmf_destinations"] = lxmd_config["propagation"].as_list("prioritise_destinations")
        else:
            active_configuration["prioritised_lxmf_destinations"] = []
        
        if "propagation" in lxmd_config and "control_allowed" in lxmd_config["propagation"]:
            active_configuration["control_allowed_identities"] = lxmd_config["propagation"].as_list("control_allowed")
        else:
            active_configuration["control_allowed_identities"] = []

        if "propagation" in lxmd_config and "static_peers" in lxmd_config["propagation"]:
            static_peers = lxmd_config["propagation"].as_list("static_peers")
            active_configuration["static_peers"] = []
            for static_peer in static_peers:
                active_configuration["static_peers"].append(bytes.fromhex(static_peer))
        else:
            active_configuration["static_peers"] = []

        if "propagation" in lxmd_config and "max_peers" in lxmd_config["propagation"]:
            active_configuration["max_peers"] = lxmd_config["propagation"].as_int("max_peers")
        else:
            active_configuration["max_peers"] = None

        if "propagation" in lxmd_config and "from_static_only" in lxmd_config["propagation"]:
            active_configuration["from_static_only"] = lxmd_config["propagation"].as_bool("from_static_only")
        else:
            active_configuration["from_static_only"] = False

        # Load various settings
        if "logging" in lxmd_config and "loglevel" in lxmd_config["logging"]:
            targetloglevel = lxmd_config["logging"].as_int("loglevel")

        active_configuration["ignored_lxmf_destinations"] = []
        if os.path.isfile(ignoredpath):
            try:
                fh = open(ignoredpath, "rb")
                ignored_input = fh.read()
                fh.close()

                ignored_hash_strs = ignored_input.splitlines()

                for hash_str in ignored_hash_strs:
                    if len(hash_str) == RNS.Identity.TRUNCATED_HASHLENGTH//8*2:
                        try:
                            ignored_hash = bytes.fromhex(hash_str.decode("utf-8"))
                            active_configuration["ignored_lxmf_destinations"].append(ignored_hash)

                        except Exception as e:
                            RNS.log("Could not decode hash from: "+str(hash_str), RNS.LOG_DEBUG)
                            RNS.log("The contained exception was: "+str(e), RNS.LOG_DEBUG)

            except Exception as e:
                RNS.log("Error while loading list of ignored destinations: "+str(e), RNS.LOG_ERROR)

        active_configuration["allowed_identities"] = []
        if os.path.isfile(allowedpath):
            try:
                fh = open(allowedpath, "rb")
                allowed_input = fh.read()
                fh.close()

                allowed_hash_strs = allowed_input.splitlines()

                for hash_str in allowed_hash_strs:
                    if len(hash_str) == RNS.Identity.TRUNCATED_HASHLENGTH//8*2:
                        try:
                            allowed_hash = bytes.fromhex(hash_str.decode("utf-8"))
                            active_configuration["allowed_identities"].append(allowed_hash)

                        except Exception as e:
                            RNS.log("Could not decode hash from: "+str(hash_str), RNS.LOG_DEBUG)
                            RNS.log("The contained exception was: "+str(e), RNS.LOG_DEBUG)

            except Exception as e:
                RNS.log("Error while loading list of allowed identities: "+str(e), RNS.LOG_ERROR)

    except Exception as e:
        RNS.log("Could not apply LXM Daemon configuration. The contained exception was: "+str(e), RNS.LOG_ERROR)
        raise e
        exit(3)

def lxmf_delivery(lxm):
    global active_configuration, lxmdir

    try:
        written_path = lxm.write_to_directory(lxmdir)
        RNS.log("Received "+str(lxm)+" written to "+str(written_path), RNS.LOG_DEBUG)

        if active_configuration["on_inbound"]:
            RNS.log("Calling external program to handle message", RNS.LOG_DEBUG)
            command = active_configuration["on_inbound"]
            processing_command = command+" \""+written_path+"\""
            return_code = subprocess.call(shlex.split(processing_command), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        else:
            RNS.log("No action defined for inbound messages, ignoring", RNS.LOG_DEBUG)

    except Exception as e:
        RNS.log("Error occurred while processing received message "+str(lxm)+". The contained exception was: "+str(e), RNS.LOG_ERROR)


def program_setup(configdir = None, rnsconfigdir = None, run_pn = False, on_inbound = None, verbosity = 0, quietness = 0, service = False):
    global configpath, ignoredpath, identitypath, allowedpath, storagedir, lxmdir
    global lxmd_config, active_configuration, targetloglevel
    global message_router, lxmf_destination

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
    ignoredpath  = configdir+"/ignored"
    allowedpath  = configdir+"/allowed"
    identitypath = configdir+"/identity"
    storagedir   = configdir+"/storage"
    lxmdir       = storagedir+"/messages"

    if not os.path.isdir(storagedir):
        os.makedirs(storagedir)

    if not os.path.isdir(lxmdir):
        os.makedirs(lxmdir)

    if not os.path.isfile(configpath):
        RNS.log("Could not load config file, creating default configuration file...")
        create_default_config(configpath)
        RNS.log("Default config file created. Make any necessary changes in "+configpath+" and restart lxmd if needed.")
        time.sleep(1.5)

    if os.path.isfile(configpath):
        try:
            lxmd_config = ConfigObj(configpath)
        except Exception as e:
            RNS.log("Could not parse the configuration at "+configpath, RNS.LOG_ERROR)
            RNS.log("Check your configuration file for errors!", RNS.LOG_ERROR)
            RNS.panic()
    
    apply_config()
    RNS.log("Configuration loaded from "+configpath, RNS.LOG_VERBOSE)

    if targetloglevel == None:
        targetloglevel = 3

    if verbosity != 0 or quietness != 0:
        targetloglevel = targetloglevel+verbosity-quietness
    
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
                exit(4)
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
    message_router = LXMF.LXMRouter(
        identity = identity,
        storagepath = storagedir,
        autopeer = active_configuration["autopeer"],
        autopeer_maxdepth = active_configuration["autopeer_maxdepth"],
        propagation_limit = active_configuration["propagation_transfer_max_accepted_size"],
        propagation_cost = active_configuration["propagation_stamp_cost_target"],
        propagation_cost_flexibility = active_configuration["propagation_stamp_cost_flexibility"],
        peering_cost = active_configuration["peering_cost"],
        max_peering_cost = active_configuration["remote_peering_cost_max"],
        sync_limit = active_configuration["propagation_sync_max_accepted_size"],
        delivery_limit = active_configuration["delivery_transfer_max_accepted_size"],
        max_peers = active_configuration["max_peers"],
        static_peers = active_configuration["static_peers"],
        from_static_only = active_configuration["from_static_only"],
        name = active_configuration["node_name"])
    
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

    # Set up authentication
    if active_configuration["auth_required"]:
        message_router.set_authentication(required=True)

        if len(active_configuration["allowed_identities"]) == 0:
            RNS.log("Clint authentication was enabled, but no identity hashes could be loaded from "+str(allowedpath)+". Nobody will be able to sync messages from this propagation node.", RNS.LOG_WARNING)
            
        for identity_hash in active_configuration["allowed_identities"]:
            message_router.allow(identity_hash)

    RNS.log("LXMF Router ready to receive on "+RNS.prettyhexrep(lxmf_destination.hash))

    if run_pn or active_configuration["enable_propagation_node"]:
        message_router.set_message_storage_limit(megabytes=active_configuration["message_storage_limit"])
        for dest_str in active_configuration["prioritised_lxmf_destinations"]:
            try:
                dest_hash = bytes.fromhex(dest_str)
                if len(dest_hash) == RNS.Reticulum.TRUNCATED_HASHLENGTH//8: message_router.prioritise(dest_hash)
            except Exception as e: RNS.log("Cannot prioritise "+str(dest_str)+", it is not a valid destination hash", RNS.LOG_ERROR)

        message_router.enable_propagation()
        
        for ident_str in active_configuration["control_allowed_identities"]:
            try:
                identity_hash = bytes.fromhex(ident_str)
                if len(identity_hash) == RNS.Reticulum.TRUNCATED_HASHLENGTH//8: message_router.allow_control(identity_hash)
            except Exception as e: RNS.log(f"Cannot allow control from {ident_str}, it is not a valid identity hash", RNS.LOG_ERROR)

        RNS.log("LXMF Propagation Node started on "+RNS.prettyhexrep(message_router.propagation_destination.hash))

    RNS.log("Started lxmd version {version}".format(version=__version__), RNS.LOG_NOTICE)

    threading.Thread(target=deferred_start_jobs, daemon=True).start()

    while True:
        time.sleep(1)

def jobs():
    global active_configuration, last_peer_announce, last_node_announce
    global message_router, lxmf_destination
    
    while True:
        try:
            if "peer_announce_interval" in active_configuration and active_configuration["peer_announce_interval"] != None:
                if time.time() > last_peer_announce + active_configuration["peer_announce_interval"]:
                    RNS.log("Sending announce for LXMF delivery destination", RNS.LOG_VERBOSE)
                    message_router.announce(lxmf_destination.hash)
                    last_peer_announce = time.time()

            if "node_announce_interval" in active_configuration and active_configuration["node_announce_interval"] != None:
                if time.time() > last_node_announce + active_configuration["node_announce_interval"]:
                    RNS.log("Sending announce for LXMF Propagation Node", RNS.LOG_VERBOSE)
                    message_router.announce_propagation_node()
                    last_node_announce = time.time()

        except Exception as e:
            RNS.log("An error occurred while running periodic jobs. The contained exception was: "+str(e), RNS.LOG_ERROR)

        time.sleep(JOBS_INTERVAL)

def deferred_start_jobs():
    global active_configuration, last_peer_announce, last_node_announce
    global message_router, lxmf_destination
    time.sleep(DEFFERED_JOBS_DELAY)
    RNS.log("Running deferred start jobs", RNS.LOG_DEBUG)
    if active_configuration["peer_announce_at_start"]:
        RNS.log("Sending announce for LXMF delivery destination", RNS.LOG_EXTREME)
        message_router.announce(lxmf_destination.hash)

    if active_configuration["node_announce_at_start"]:
        RNS.log("Sending announce for LXMF Propagation Node", RNS.LOG_EXTREME)
        message_router.announce_propagation_node()

    last_peer_announce = time.time()
    last_node_announce = time.time()
    threading.Thread(target=jobs, daemon=True).start()

def _request_sync(identity, destination_hash, remote_identity, timeout=15, exit_on_fail=False):
    control_destination = RNS.Destination(remote_identity, RNS.Destination.OUT, RNS.Destination.SINGLE, APP_NAME, "propagation", "control")

    timeout = time.time()+timeout
    def check_timeout():
        if time.time() > timeout:
            if exit_on_fail:
                print("Requesting lxmd peer sync timed out, exiting now")
                exit(200)
            else:
                return LXMF.LXMPeer.LXMPeer.ERROR_TIMEOUT
        else:
            time.sleep(0.1)

    if not RNS.Transport.has_path(control_destination.hash):
        RNS.Transport.request_path(control_destination.hash)
        while not RNS.Transport.has_path(control_destination.hash):
            tc = check_timeout()
            if tc:
                return tc

    link = RNS.Link(control_destination)
    while not link.status == RNS.Link.ACTIVE:
        tc = check_timeout()
        if tc:
            return tc

    link.identify(identity)
    request_receipt = link.request(LXMF.LXMRouter.SYNC_REQUEST_PATH, data=destination_hash, response_callback=None, failed_callback=None)
    while not request_receipt.get_status() == RNS.RequestReceipt.READY:
        tc = check_timeout()
        if tc:
            return tc

    link.teardown()
    return request_receipt.get_response()


def request_sync(target, remote=None, configdir=None, rnsconfigdir=None, verbosity=0, quietness=0, timeout=15, identity_path=None):
    global configpath, identitypath, storagedir, lxmdir
    global lxmd_config, active_configuration, targetloglevel

    try:
        peer_destination_hash = bytes.fromhex(target)
        if len(peer_destination_hash) != RNS.Identity.TRUNCATED_HASHLENGTH//8: raise ValueError(f"Destination hash length must be {RNS.Identity.TRUNCATED_HASHLENGTH//8*2} characters")
    except Exception as e:
        print(f"Invalid peer destination hash: {e}")
        exit(203)
    remote
    _remote_init(configdir, rnsconfigdir, verbosity, quietness, identity_path)
    response = _request_sync(identity, peer_destination_hash, remote_identity=_get_target_identity(remote), timeout=timeout, exit_on_fail=True)

    if response == LXMF.LXMPeer.LXMPeer.ERROR_NO_IDENTITY:
        print("Remote received no identity")
        exit(203)
    elif response == LXMF.LXMPeer.LXMPeer.ERROR_NO_ACCESS:
        print("Access denied")
        exit(204)
    elif response == LXMF.LXMPeer.LXMPeer.ERROR_INVALID_DATA:
        print("Invalid data received by remote")
        exit(205)
    elif response == LXMF.LXMPeer.LXMPeer.ERROR_NOT_FOUND:
        print("The requested peer was not found")
        exit(206)
    elif response == None:
        print("Empty response received")
        exit(207)
    else:
        print(f"Sync requested for peer {RNS.prettyhexrep(peer_destination_hash)}")
        exit(0)

def _request_unpeer(identity, destination_hash, remote_identity, timeout=15, exit_on_fail=False):
    control_destination = RNS.Destination(remote_identity, RNS.Destination.OUT, RNS.Destination.SINGLE, APP_NAME, "propagation", "control")

    timeout = time.time()+timeout
    def check_timeout():
        if time.time() > timeout:
            if exit_on_fail:
                print("Requesting lxmd peering break timed out, exiting now")
                exit(200)
            else: return LXMF.LXMPeer.LXMPeer.ERROR_TIMEOUT
        else: time.sleep(0.1)

    if not RNS.Transport.has_path(control_destination.hash):
        RNS.Transport.request_path(control_destination.hash)
        while not RNS.Transport.has_path(control_destination.hash):
            tc = check_timeout()
            if tc:
                return tc

    link = RNS.Link(control_destination)
    while not link.status == RNS.Link.ACTIVE:
        tc = check_timeout()
        if tc:
            return tc

    link.identify(identity)
    request_receipt = link.request(LXMF.LXMRouter.UNPEER_REQUEST_PATH, data=destination_hash, response_callback=None, failed_callback=None)
    while not request_receipt.get_status() == RNS.RequestReceipt.READY:
        tc = check_timeout()
        if tc:
            return tc

    link.teardown()
    return request_receipt.get_response()


def request_unpeer(target, remote=None, configdir=None, rnsconfigdir=None, verbosity=0, quietness=0, timeout=15, identity_path=None):
    global configpath, identitypath, storagedir, lxmdir
    global lxmd_config, active_configuration, targetloglevel

    try:
        peer_destination_hash = bytes.fromhex(target)
        if len(peer_destination_hash) != RNS.Identity.TRUNCATED_HASHLENGTH//8: raise ValueError(f"Destination hash length must be {RNS.Identity.TRUNCATED_HASHLENGTH//8*2} characters")
    except Exception as e:
        print(f"Invalid peer destination hash: {e}")
        exit(203)
    remote
    _remote_init(configdir, rnsconfigdir, verbosity, quietness, identity_path)
    response = _request_unpeer(identity, peer_destination_hash, remote_identity=_get_target_identity(remote), timeout=timeout, exit_on_fail=True)

    if response == LXMF.LXMPeer.LXMPeer.ERROR_NO_IDENTITY:
        print("Remote received no identity")
        exit(203)
    elif response == LXMF.LXMPeer.LXMPeer.ERROR_NO_ACCESS:
        print("Access denied")
        exit(204)
    elif response == LXMF.LXMPeer.LXMPeer.ERROR_INVALID_DATA:
        print("Invalid data received by remote")
        exit(205)
    elif response == LXMF.LXMPeer.LXMPeer.ERROR_NOT_FOUND:
        print("The requested peer was not found")
        exit(206)
    elif response == None:
        print("Empty response received")
        exit(207)
    else:
        print(f"Broke peering with {RNS.prettyhexrep(peer_destination_hash)}")
        exit(0)

def query_status(identity, remote_identity=None, timeout=5, exit_on_fail=False):
    if remote_identity == None: remote_identity = identity
    control_destination = RNS.Destination(remote_identity, RNS.Destination.OUT, RNS.Destination.SINGLE, APP_NAME, "propagation", "control")

    timeout = time.time()+timeout
    def check_timeout():
        if time.time() > timeout:
            if exit_on_fail:
                print("Getting lxmd statistics timed out, exiting now")
                exit(200)
            else: return LXMF.LXMPeer.LXMPeer.ERROR_TIMEOUT
        else: time.sleep(0.1)

    if not RNS.Transport.has_path(control_destination.hash):
        RNS.Transport.request_path(control_destination.hash)
        while not RNS.Transport.has_path(control_destination.hash):
            tc = check_timeout()
            if tc: return tc

    link = RNS.Link(control_destination)
    while not link.status == RNS.Link.ACTIVE:
        tc = check_timeout()
        if tc: return tc

    link.identify(identity)
    request_receipt = link.request(LXMF.LXMRouter.STATS_GET_PATH, data=None, response_callback=None, failed_callback=None)
    while not request_receipt.get_status() == RNS.RequestReceipt.READY:
        tc = check_timeout()
        if tc: return tc

    link.teardown()
    return request_receipt.get_response()

def get_status(remote=None, configdir=None, rnsconfigdir=None, verbosity=0, quietness=0, timeout=5,
               show_status=False, show_peers=False, identity_path=None):

    global identity
    _remote_init(configdir, rnsconfigdir, verbosity, quietness, identity_path)
    response = query_status(identity, remote_identity=_get_target_identity(remote), timeout=timeout, exit_on_fail=True)

    if response == LXMF.LXMPeer.LXMPeer.ERROR_NO_IDENTITY:
        print("Remote received no identity")
        exit(203)
    if response == LXMF.LXMPeer.LXMPeer.ERROR_NO_ACCESS:
        print("Access denied")
        exit(204)
    elif response == None:
        print("Empty response received")
        exit(207)
    else:
        s = response
        mutil = round((s["messagestore"]["bytes"]/s["messagestore"]["limit"])*100, 2)
        ms_util = f"{mutil}%"
        if s["from_static_only"]:
            who_str = "static peers only"
        else:
            who_str = "all nodes"

        available_peers = 0
        unreachable_peers = 0
        peered_incoming = 0
        peered_outgoing = 0
        peered_rx_bytes = 0
        peered_tx_bytes = 0
        for peer_id in s["peers"]:
            p = s["peers"][peer_id]
            pm = p["messages"]
            peered_incoming += pm["incoming"]
            peered_outgoing += pm["outgoing"]
            peered_rx_bytes += p["rx_bytes"]
            peered_tx_bytes += p["tx_bytes"]

            if p["alive"]: available_peers   += 1
            else:          unreachable_peers += 1

        total_incoming = peered_incoming+s["unpeered_propagation_incoming"]+s["clients"]["client_propagation_messages_received"]
        total_rx_bytes = peered_rx_bytes+s["unpeered_propagation_rx_bytes"]
        if total_incoming != 0: df = round(peered_outgoing/total_incoming, 2)
        else:                   df = 0

        dhs = RNS.prettyhexrep(s["destination_hash"]); uts = RNS.prettytime(s["uptime"])
        print(f"\nLXMF Propagation Node running on {dhs}, uptime is {uts}")

        if show_status:
            msb   = RNS.prettysize(s["messagestore"]["bytes"]); msl = RNS.prettysize(s["messagestore"]["limit"])
            ptl   = RNS.prettysize(s["propagation_limit"]*1000); psl = RNS.prettysize(s["sync_limit"]*1000); 
            uprx = RNS.prettysize(s["unpeered_propagation_rx_bytes"])
            mscnt = s["messagestore"]["count"]; stp = s["total_peers"]; smp = s["max_peers"]; sdp = s["discovered_peers"]
            ssp   = s["static_peers"]; cprr = s["clients"]["client_propagation_messages_received"]
            cprs  = s["clients"]["client_propagation_messages_served"]; upi = s["unpeered_propagation_incoming"]
            psc   = s["target_stamp_cost"]; scf = s["stamp_cost_flexibility"]
            pc    = s["peering_cost"]; pcm = s["max_peering_cost"]
            print(f"Messagestore contains {mscnt} messages, {msb} ({ms_util} utilised of {msl})")
            print(f"Required propagation stamp cost is {psc}, flexibility is {scf}")
            print(f"Peering cost is {pc}, max remote peering cost is {pcm}")
            print(f"Accepting propagated messages from {who_str}")
            print(f"{ptl} message limit, {psl} sync limit")
            print(f"")
            print(f"Peers   : {stp} total (peer limit is {smp})")
            print(f"          {sdp} discovered, {ssp} static")
            print(f"          {available_peers} available, {unreachable_peers} unreachable")
            print(f"")
            print(f"Traffic : {total_incoming} messages received in total ({RNS.prettysize(total_rx_bytes)})")
            print(f"          {peered_incoming} messages received from peered nodes ({RNS.prettysize(peered_rx_bytes)})")
            print(f"          {upi} messages received from unpeered nodes ({uprx})")
            print(f"          {peered_outgoing} messages transferred to peered nodes ({RNS.prettysize(peered_tx_bytes)})")
            print(f"          {cprr} propagation messages received directly from clients")
            print(f"          {cprs} propagation messages served to clients")
            print(f"          Distribution factor is {df}")
            print(f"")

        if show_peers:
            if not show_status:
                print("")

            for peer_id in s["peers"]:
                ind = "  "
                p = s["peers"][peer_id]
                if p["type"] == "static":
                    t = "Static peer     "
                elif p["type"] == "discovered":
                    t = "Discovered peer "
                else:
                    t = "Unknown peer    "
                a = "Available" if p["alive"] == True else "Unreachable"
                h = max(time.time()-p["last_heard"], 0)
                hops = p["network_distance"]
                hs = "hops unknown" if hops == RNS.Transport.PATHFINDER_M else f"{hops} hop away" if hops == 1 else f"{hops} hops away"
                pm = p["messages"]; pk = p["peering_key"]
                pc = p["peering_cost"]; psc = p["target_stamp_cost"]; psf = p["stamp_cost_flexibility"]
                if pc == None: pc = "unknown"
                if psc == None: psc = "unknown"
                if psf == None: psf = "unknown"
                if pk == None: pk = "Not generated"
                else:          pk = f"Generated, value is {pk}"
                if p["last_sync_attempt"] != 0:
                    lsa = p["last_sync_attempt"]
                    ls = f"last synced {RNS.prettytime(max(time.time()-lsa, 0))} ago"
                else:
                    ls = "never synced"

                sstr = RNS.prettyspeed(p["str"]); sler = RNS.prettyspeed(p["ler"])
                stl = RNS.prettysize(p["transfer_limit"]*1000) if p["transfer_limit"] else "Unknown"
                ssl = RNS.prettysize(p["sync_limit"]*1000) if p["sync_limit"] else "unknown"
                srxb = RNS.prettysize(p["rx_bytes"]); stxb = RNS.prettysize(p["tx_bytes"]); pmo = pm["offered"]; pmout = pm["outgoing"]
                pmi  = pm["incoming"]; pmuh = pm["unhandled"]; ar = round(p["acceptance_rate"]*100, 2)
                if p["name"] == None: nn = ""
                else: nn = p["name"].strip().replace("\n", "").replace("\r", "")
                if len(nn) > 45: nn = f"{nn[:45]}..."
                print(f"{ind}{t}{RNS.prettyhexrep(peer_id)}")
                if len(nn): print(f"{ind*2}Name       : {nn}")
                print(f"{ind*2}Status     : {a}, {hs}, last heard {RNS.prettytime(h)} ago")
                print(f"{ind*2}Costs      : Propagation {psc} (flex {psf}), peering {pc}")
                print(f"{ind*2}Sync key   : {pk}")
                print(f"{ind*2}Speeds     : {sstr} STR, {sler} LER")
                print(f"{ind*2}Limits     : {stl} message limit, {ssl} sync limit")
                print(f"{ind*2}Messages   : {pmo} offered, {pmout} outgoing, {pmi} incoming, {ar}% acceptance rate")
                print(f"{ind*2}Traffic    : {srxb} received, {stxb} sent")
                ms = "" if pm["unhandled"] == 1 else "s"
                print(f"{ind*2}Sync state : {pmuh} unhandled message{ms}, {ls}")
                print("")

def _get_target_identity(remote=None, timeout=5):
    global identity
    timeout = time.time()+timeout
    def check_timeout():
        if time.time() > timeout:
            print("Resolving remote identity timed out, exiting now")
            exit(200)
        else: time.sleep(0.1)

    if remote == None: return identity
    else:
        try:
            destination_hash = bytes.fromhex(remote)
            if len(destination_hash) != RNS.Identity.TRUNCATED_HASHLENGTH//8: raise ValueError(f"Destination hash length must be {RNS.Identity.TRUNCATED_HASHLENGTH//8*2} characters")
        except Exception as e:
            print(f"Invalid remote destination hash: {e}")
            exit(203)

        remote_identity = RNS.Identity.recall(destination_hash)
        if remote_identity: return remote_identity
        else:
            if not RNS.Transport.has_path(destination_hash):
                RNS.Transport.request_path(destination_hash)
                while not RNS.Transport.has_path(destination_hash):
                    tc = check_timeout()
                    if tc: return tc

            return RNS.Identity.recall(destination_hash)

def _remote_init(configdir=None, rnsconfigdir=None, verbosity=0, quietness=0, identity_path=None):
    global configpath, identitypath, storagedir, lxmdir, identity
    global lxmd_config, active_configuration, targetloglevel
    targetlogdest  = RNS.LOG_STDOUT

    if identity_path == None:
        if configdir == None:
            if os.path.isdir("/etc/lxmd") and os.path.isfile("/etc/lxmd/config"): configdir = "/etc/lxmd"
            elif os.path.isdir(RNS.Reticulum.userdir+"/.config/lxmd") and os.path.isfile(Reticulum.userdir+"/.config/lxmd/config"): configdir = RNS.Reticulum.userdir+"/.config/lxmd"
            else: configdir = RNS.Reticulum.userdir+"/.lxmd"

        configpath   = configdir+"/config"
        identitypath = configdir+"/identity"
        identity = None

        if not os.path.isdir(configdir):
            RNS.log("Specified configuration directory does not exist, exiting now", RNS.LOG_ERROR)
            exit(201)
        if not os.path.isfile(identitypath):
            RNS.log("Identity file not found in specified configuration directory, exiting now", RNS.LOG_ERROR)
            exit(202)
        else:
            identity = RNS.Identity.from_file(identitypath)
            if identity == None:
                RNS.log("Could not load the Primary Identity from "+identitypath, RNS.LOG_ERROR)
                exit(4)

    else:
        if not os.path.isfile(identity_path):
            RNS.log("Identity file not found in specified configuration directory, exiting now", RNS.LOG_ERROR)
            exit(202)
        else:
            identity = RNS.Identity.from_file(identity_path)
            if identity == None:
                RNS.log("Could not load the Primary Identity from "+identity_path, RNS.LOG_ERROR)
                exit(4)        

    if targetloglevel == None: targetloglevel = 3
    if verbosity != 0 or quietness != 0: targetloglevel = targetloglevel+verbosity-quietness
    
    reticulum = RNS.Reticulum(configdir=rnsconfigdir, loglevel=targetloglevel, logdest=targetlogdest)

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
        parser.add_argument("--status", action="store_true", default=False, help="display node status")
        parser.add_argument("--peers", action="store_true", default=False, help="display peered nodes")
        parser.add_argument("--sync", action="store", default=None, help="request a sync with the specified peer", type=str)
        parser.add_argument("-b", "--break", dest="unpeer", action="store", default=None, help="break peering with the specified peer", type=str)
        parser.add_argument("--timeout", action="store", default=None, help="timeout in seconds for query operations", type=float)
        parser.add_argument("-r", "--remote", action="store", default=None, help="remote propagation node destination hash", type=str)
        parser.add_argument("--identity", action="store", default=None, help="path to identity used for remote requests", type=str)
        parser.add_argument("--exampleconfig", action="store_true", default=False, help="print verbose configuration example to stdout and exit")
        parser.add_argument("--version", action="version", version="lxmd {version}".format(version=__version__))
        
        args = parser.parse_args()

        if args.exampleconfig:
            print(__default_lxmd_config__)
            exit()

        if args.status or args.peers:
            if not args.timeout: args.timeout = 5
            get_status(configdir = args.config,
                       rnsconfigdir=args.rnsconfig,
                       verbosity=args.verbose,
                       quietness=args.quiet,
                       timeout=args.timeout,
                       show_status=args.status,
                       show_peers=args.peers,
                       identity_path=args.identity,
                       remote=args.remote)
            exit()

        if args.sync:
            if not args.timeout: args.timeout = 10
            request_sync(target=args.sync,
                         configdir = args.config,
                         rnsconfigdir=args.rnsconfig,
                         verbosity=args.verbose,
                         quietness=args.quiet,
                         timeout=args.timeout,
                         identity_path=args.identity,
                         remote=args.remote)
            exit()

        if args.unpeer:
            if not args.timeout: args.timeout = 10
            request_unpeer(target=args.unpeer,
                           configdir = args.config,
                           rnsconfigdir=args.rnsconfig,
                           verbosity=args.verbose,
                           quietness=args.quiet,
                           timeout=args.timeout,
                           identity_path=args.identity,
                           remote=args.remote)
            exit()

        program_setup(configdir = args.config,
                      rnsconfigdir=args.rnsconfig,
                      run_pn=args.propagation_node,
                      on_inbound=args.on_inbound,
                      verbosity=args.verbose,
                      quietness=args.quiet,
                      service=args.service)

    except KeyboardInterrupt:
        print("")
        exit()

__default_lxmd_config__ = """# This is an example LXM Daemon config file.
# You should probably edit it to suit your
# intended usage.

[propagation]

# Whether to enable propagation node

enable_node = no

# You can specify identity hashes for remotes
# that are allowed to control and query status
# for this propagation node.

# control_allowed = 7d7e542829b40f32364499b27438dba8, 437229f8e29598b2282b88bad5e44698

# An optional name for this node, included
# in announces.

# node_name = Anonymous Propagation Node

# Automatic announce interval in minutes.
# 6 hours by default.

announce_interval = 360

# Whether to announce when the node starts.

announce_at_start = yes

# Wheter to automatically peer with other
# propagation nodes on the network.

autopeer = yes

# The maximum peering depth (in hops) for
# automatically peered nodes.

autopeer_maxdepth = 4

# The maximum amount of storage to use for
# the LXMF Propagation Node message store,
# specified in megabytes. When this limit
# is reached, LXMF will periodically remove
# messages in its message store. By default,
# LXMF prioritises keeping messages that are
# new and small. Large and old messages will
# be removed first. This setting is optional
# and defaults to 500 megabytes.

# message_storage_limit = 500

# The maximum accepted transfer size per in-
# coming propagation message, in kilobytes.
# This sets the upper limit for the size of
# single messages accepted onto this node.

# propagation_message_max_accepted_size = 256

# The maximum accepted transfer size per in-
# coming propagation node sync.
#
# If a node wants to propagate a larger number
# of messages to this node, than what can fit
# within this limit, it will prioritise sending
# the smallest messages first, and try again
# with any remaining messages at a later point.

# propagation_sync_max_accepted_size = 10240

# You can configure the target stamp cost
# required to deliver messages via this node.

# propagation_stamp_cost_target = 16

# If set higher than 0, the stamp cost flexi-
# bility option will make this node accept
# messages with a lower stamp cost than the
# target from other propagation nodes (but
# not from peers directly). This allows the
# network to gradually adjust stamp cost.

# propagation_stamp_cost_flexibility = 3

# The peering_cost option configures the target
# value required for a remote node to peer with
# and deliver messages to this node.

# peering_cost = 18

# You can configure the maximum peering cost
# of remote nodes that this node will peer with.
# Setting this to a higher number will allow
# this node to peer with other nodes requiring
# a higher peering key value, but will require
# more computation time during initial peering
# when generating the peering key.

# remote_peering_cost_max = 26

# You can tell the LXMF message router to
# prioritise storage for one or more
# destinations. If the message store reaches
# the specified limit, LXMF will prioritise
# keeping messages for destinations specified
# with this option. This setting is optional,
# and generally you do not need to use it.

# prioritise_destinations = 41d20c727598a3fbbdf9106133a3a0ed, d924b81822ca24e68e2effea99bcb8cf

# You can configure the maximum number of other
# propagation nodes that this node will peer
# with automatically. The default is 20.

# max_peers = 20

# You can configure a list of static propagation
# node peers, that this node will always be
# peered with, by specifying a list of
# destination hashes.

# static_peers = e17f833c4ddf8890dd3a79a6fea8161d, 5a2d0029b6e5ec87020abaea0d746da4

# You can configure the propagation node to
# only accept incoming propagation messages
# from configured static peers.

# from_static_only = True

# By default, any destination is allowed to
# connect and download messages, but you can
# optionally restrict this. If you enable
# authentication, you must provide a list of
# allowed identity hashes in the a file named
# "allowed" in the lxmd config directory.

auth_required = no


[lxmf]

# The LXM Daemon will create an LXMF destination
# that it can receive messages on. This option sets
# the announced display name for this destination.

display_name = Anonymous Peer

# It is possible to announce the internal LXMF
# destination when the LXM Daemon starts up.

announce_at_start = no

# You can also announce the delivery destination
# at a specified interval. This is not enabled by
# default.

# announce_interval = 360

# The maximum accepted unpacked size for mes-
# sages received directly from other peers,
# specified in kilobytes. Messages larger than
# this will be rejected before the transfer
# begins.

delivery_transfer_max_accepted_size = 1000

# You can configure an external program to be run
# every time a message is received. The program
# will receive as an argument the full path to the
# message saved as a file. The example below will
# simply result in the message getting deleted as
# soon as it has been received.

# on_inbound = rm


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
