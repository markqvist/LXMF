import os
import time
import random
import base64
import atexit
import threading

import RNS
import RNS.vendor.umsgpack as msgpack

from .LXMF import APP_NAME
from .LXMF import FIELD_TICKET

from .LXMPeer import LXMPeer
from .LXMessage import LXMessage
from .Handlers import LXMFDeliveryAnnounceHandler
from .Handlers import LXMFPropagationAnnounceHandler

class LXMRouter:
    MAX_DELIVERY_ATTEMPTS = 5
    PROCESSING_INTERVAL   = 4
    DELIVERY_RETRY_WAIT   = 10
    PATH_REQUEST_WAIT     = 7
    MAX_PATHLESS_TRIES    = 1
    LINK_MAX_INACTIVITY   = 10*60
    P_LINK_MAX_INACTIVITY = 3*60

    MESSAGE_EXPIRY        = 30*24*60*60
    STAMP_COST_EXPIRY     = 45*24*60*60

    NODE_ANNOUNCE_DELAY   = 20

    AUTOPEER              = True
    AUTOPEER_MAXDEPTH     = 4
    FASTEST_N_RANDOM_POOL = 2

    PROPAGATION_LIMIT     = 256
    DELIVERY_LIMIT        = 1000

    PR_PATH_TIMEOUT       = 10

    PR_IDLE               = 0x00
    PR_PATH_REQUESTED     = 0x01
    PR_LINK_ESTABLISHING  = 0x02
    PR_LINK_ESTABLISHED   = 0x03
    PR_REQUEST_SENT       = 0x04
    PR_RECEIVING          = 0x05
    PR_RESPONSE_RECEIVED  = 0x06
    PR_COMPLETE           = 0x07
    PR_NO_PATH            = 0xf0
    PR_LINK_FAILED        = 0xf1
    PR_TRANSFER_FAILED    = 0xf2
    PR_NO_IDENTITY_RCVD   = 0xf3
    PR_NO_ACCESS          = 0xf4
    PR_FAILED             = 0xfe

    PR_ALL_MESSAGES       = 0x00


    ### Developer-facing API ##############################
    #######################################################

    def __init__(self, identity = None, storagepath = None, autopeer = AUTOPEER, autopeer_maxdepth = None, propagation_limit = PROPAGATION_LIMIT, delivery_limit = DELIVERY_LIMIT, enforce_ratchets = False, enforce_stamps = False):
        random.seed(os.urandom(10))

        self.pending_inbound       = []
        self.pending_outbound      = []
        self.failed_outbound       = []
        self.direct_links          = {}
        self.backchannel_links     = {}
        self.delivery_destinations = {}

        self.prioritised_list      = []
        self.ignored_list          = []
        self.allowed_list          = []
        self.auth_required         = False
        self.retain_synced_on_node = False

        self.processing_outbound = False
        self.processing_inbound  = False
        self.processing_count = 0

        self.propagation_node = False

        if storagepath == None:
            raise ValueError("LXMF cannot be initialised without a storage path")
        else:
            self.storagepath = storagepath+"/lxmf"
            self.ratchetpath = self.storagepath+"/ratchets"

        self.outbound_propagation_node = None
        self.outbound_propagation_link = None

        self.message_storage_limit = None
        self.information_storage_limit = None
        self.propagation_per_transfer_limit = propagation_limit
        self.delivery_per_transfer_limit = delivery_limit
        self.enforce_ratchets = enforce_ratchets
        self._enforce_stamps = enforce_stamps
        self.pending_deferred_stamps = {}

        self.wants_download_on_path_available_from = None
        self.wants_download_on_path_available_to = None
        self.propagation_transfer_state = LXMRouter.PR_IDLE
        self.propagation_transfer_progress = 0.0
        self.propagation_transfer_last_result = None
        self.propagation_transfer_max_messages = None
        self.active_propagation_links = []
        self.locally_delivered_transient_ids = {}
        self.locally_processed_transient_ids = {}
        self.outbound_stamp_costs = {}
        self.available_tickets = {"outbound": {}, "inbound": {}, "last_deliveries": {}}

        self.cost_file_lock = threading.Lock()
        self.ticket_file_lock = threading.Lock()
        self.stamp_gen_lock = threading.Lock()

        if identity == None:
            identity = RNS.Identity()

        self.identity = identity
        self.propagation_destination = RNS.Destination(self.identity, RNS.Destination.IN, RNS.Destination.SINGLE, APP_NAME, "propagation")

        if autopeer != None:
            self.autopeer = autopeer
        else:
            self.autopeer = LXMRouter.AUTOPEER

        if autopeer_maxdepth != None:
            self.autopeer_maxdepth = autopeer_maxdepth
        else:
            self.autopeer_maxdepth = LXMRouter.AUTOPEER_MAXDEPTH

        self.peers = {}
        self.propagation_entries = {}

        RNS.Transport.register_announce_handler(LXMFDeliveryAnnounceHandler(self))
        RNS.Transport.register_announce_handler(LXMFPropagationAnnounceHandler(self))

        self.__delivery_callback = None

        try:
            if os.path.isfile(self.storagepath+"/local_deliveries"):
                locally_delivered_file = open(self.storagepath+"/local_deliveries", "rb")
                data = locally_delivered_file.read()
                self.locally_delivered_transient_ids = msgpack.unpackb(data)
                locally_delivered_file.close()

            if os.path.isfile(self.storagepath+"/locally_processed"):
                locally_processed_file = open(self.storagepath+"/locally_processed", "rb")
                data = locally_processed_file.read()
                self.locally_processed_transient_ids = msgpack.unpackb(data)
                locally_processed_file.close()
            
            self.clean_transient_id_caches()

        except Exception as e:
            RNS.log("Could not load locally delivered message ID cache from storage. The contained exception was: "+str(e), RNS.LOG_ERROR)

        try:
            if os.path.isfile(self.storagepath+"/outbound_stamp_costs"):
                with self.cost_file_lock:
                    with open(self.storagepath+"/outbound_stamp_costs", "rb") as outbound_stamp_cost_file:
                        data = outbound_stamp_cost_file.read()
                        self.outbound_stamp_costs = msgpack.unpackb(data)

                self.clean_outbound_stamp_costs()
                self.save_outbound_stamp_costs()

        except Exception as e:
            RNS.log("Could not load outbound stamp costs from storage. The contained exception was: "+str(e), RNS.LOG_ERROR)

        try:
            if os.path.isfile(self.storagepath+"/available_tickets"):
                with self.ticket_file_lock:
                    with open(self.storagepath+"/available_tickets", "rb") as available_tickets_file:
                        data = available_tickets_file.read()
                        self.available_tickets = msgpack.unpackb(data)
                        if not type(self.available_tickets) == dict:
                            RNS.log("Invalid data format for loaded available tickets, recreating...", RNS.LOG_ERROR)
                            self.available_tickets = {"outbound": {}, "inbound": {}, "last_deliveries": {}}
                        if not "outbound" in self.available_tickets:
                            RNS.log("Missing outbound entry in loaded available tickets, recreating...", RNS.LOG_ERROR)
                            self.available_tickets["outbound"] = {}
                        if not "inbound" in self.available_tickets:
                            RNS.log("Missing inbound entry in loaded available tickets, recreating...", RNS.LOG_ERROR)
                            self.available_tickets["inbound"] = {}
                        if not "last_deliveries" in self.available_tickets:
                            RNS.log("Missing local_deliveries entry in loaded available tickets, recreating...", RNS.LOG_ERROR)
                            self.available_tickets["last_deliveries"] = {}

                self.clean_available_tickets()
                self.save_available_tickets()

        except Exception as e:
            RNS.log("Could not load outbound stamp costs from storage. The contained exception was: "+str(e), RNS.LOG_ERROR)

        atexit.register(self.exit_handler)

        job_thread = threading.Thread(target=self.jobloop)
        job_thread.setDaemon(True)
        job_thread.start()

    def announce(self, destination_hash, attached_interface=None):
        if destination_hash in self.delivery_destinations:
            self.delivery_destinations[destination_hash].announce(app_data=self.get_announce_app_data(destination_hash), attached_interface=attached_interface)

    def announce_propagation_node(self):
        def delayed_announce():
            time.sleep(LXMRouter.NODE_ANNOUNCE_DELAY)
            announce_data = [
                self.propagation_node,                  # Boolean flag signalling propagation node state
                int(time.time()),                       # Current node timebase
                self.propagation_per_transfer_limit,    # Per-transfer limit for message propagation in kilobytes
            ]

            data = msgpack.packb(announce_data)
            self.propagation_destination.announce(app_data=data)

        da_thread = threading.Thread(target=delayed_announce)
        da_thread.setDaemon(True)
        da_thread.start()

    def register_delivery_identity(self, identity, display_name = None, stamp_cost = None):
        if len(self.delivery_destinations) != 0:
            RNS.log("Currently only one delivery identity is supported per LXMF router instance", RNS.LOG_ERROR)
            return None

        if not os.path.isdir(self.ratchetpath):
            os.makedirs(self.ratchetpath)

        delivery_destination = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE, APP_NAME, "delivery")
        delivery_destination.enable_ratchets(f"{self.ratchetpath}/{RNS.hexrep(delivery_destination.hash, delimit=False)}.ratchets")
        delivery_destination.set_packet_callback(self.delivery_packet)
        delivery_destination.set_link_established_callback(self.delivery_link_established)
        delivery_destination.display_name = display_name

        if self.enforce_ratchets:
            delivery_destination.enforce_ratchets()

        if display_name != None:
            def get_app_data():
                return self.get_announce_app_data(delivery_destination.hash)
            delivery_destination.set_default_app_data(get_app_data)

        self.delivery_destinations[delivery_destination.hash] = delivery_destination
        self.set_inbound_stamp_cost(delivery_destination.hash, stamp_cost)

        return delivery_destination

    def register_delivery_callback(self, callback):
        self.__delivery_callback = callback

    def set_inbound_stamp_cost(self, destination_hash, stamp_cost):
        if destination_hash in self.delivery_destinations:
            delivery_destination = self.delivery_destinations[destination_hash]
            if stamp_cost == None:
                delivery_destination.stamp_cost = None
                return True
            elif type(stamp_cost) == int:
                if stamp_cost < 1:
                    delivery_destination.stamp_cost = None
                elif stamp_cost < 255:
                    delivery_destination.stamp_cost = stamp_cost
                else:
                    return False
    
                return True

        return False

    def get_outbound_stamp_cost(self, destination_hash):
        if destination_hash in self.outbound_stamp_costs:
            stamp_cost = self.outbound_stamp_costs[destination_hash][1]
            return stamp_cost
        else:
            return None

    def set_active_propagation_node(self, destination_hash):
        self.set_outbound_propagation_node(destination_hash)
        # self.set_inbound_propagation_node(destination_hash)

    def set_outbound_propagation_node(self, destination_hash):
        if len(destination_hash) != RNS.Identity.TRUNCATED_HASHLENGTH//8 or type(destination_hash) != bytes:
            raise ValueError("Invalid destination hash for outbound propagation node")
        else:
            self.outbound_propagation_node = destination_hash
            if self.outbound_propagation_link != None:
                if self.outbound_propagation_link.destination.hash != destination_hash:
                    self.outbound_propagation_link.teardown()
                    self.outbound_propagation_link = None

    def get_outbound_propagation_node(self):
        return self.outbound_propagation_node

    def set_inbound_propagation_node(self, destination_hash):
        # TODO: Implement
        raise NotImplementedError("Inbound/outbound propagation node differentiation is currently not implemented")

    def get_inbound_propagation_node(self):
        return self.get_outbound_propagation_node()

    def set_retain_node_lxms(self, retain):
        if retain == True:
            self.retain_synced_on_node = True
        else:
            self.retain_synced_on_node = False

    def set_authentication(self, required=None):
        if required != None:
            self.auth_required = required

    def requires_authentication(self):
        return self.auth_required

    def allow(self, identity_hash=None):
        if isinstance(identity_hash, bytes) and len(identity_hash) == RNS.Identity.TRUNCATED_HASHLENGTH//8:
            if not identity_hash in self.allowed_list:
                self.allowed_list.append(identity_hash)
        else:
            raise ValueError("Allowed identity hash must be "+str(RNS.Identity.TRUNCATED_HASHLENGTH//8)+" bytes")

    def disallow(self, identity_hash=None):
        if isinstance(identity_hash, bytes) and len(identity_hash) == RNS.Identity.TRUNCATED_HASHLENGTH//8:
            if identity_hash in self.allowed_list:
                self.allowed_list.pop(identity_hash)
        else:
            raise ValueError("Disallowed identity hash must be "+str(RNS.Identity.TRUNCATED_HASHLENGTH//8)+" bytes")

    def prioritise(self, destination_hash=None):
        if isinstance(destination_hash, bytes) and len(destination_hash) == RNS.Reticulum.TRUNCATED_HASHLENGTH//8:
            if not destination_hash in self.prioritised_list:
                self.prioritised_list.append(destination_hash)
        else:
            raise ValueError("Prioritised destination hash must be "+str(RNS.Reticulum.TRUNCATED_HASHLENGTH//8)+" bytes")

    def unprioritise(self, identity_hash=None):
        if isinstance(destination_hash, bytes) and len(destination_hash) == RNS.Reticulum.TRUNCATED_HASHLENGTH//8:
            if destination_hash in self.prioritised_list:
                self.prioritised_list.pop(destination_hash)
        else:
            raise ValueError("Prioritised destination hash must be "+str(RNS.Reticulum.TRUNCATED_HASHLENGTH//8)+" bytes")

    def request_messages_from_propagation_node(self, identity, max_messages = PR_ALL_MESSAGES):
        if max_messages == None:
            max_messages = LXMRouter.PR_ALL_MESSAGES

        self.propagation_transfer_progress = 0.0
        self.propagation_transfer_max_messages = max_messages
        if self.outbound_propagation_node != None:
            if self.outbound_propagation_link != None and self.outbound_propagation_link.status == RNS.Link.ACTIVE:
                self.propagation_transfer_state = LXMRouter.PR_LINK_ESTABLISHED
                self.outbound_propagation_link.identify(identity)
                self.outbound_propagation_link.request(
                    LXMPeer.MESSAGE_GET_PATH,
                    [None, None], # Set both want and have fields to None to get message list
                    response_callback=self.message_list_response,
                    failed_callback=self.message_get_failed
                )
                self.propagation_transfer_state = LXMRouter.PR_REQUEST_SENT
            else:
                if self.outbound_propagation_link == None:
                    if RNS.Transport.has_path(self.outbound_propagation_node):
                        self.wants_download_on_path_available_from = None
                        self.propagation_transfer_state = LXMRouter.PR_LINK_ESTABLISHING
                        RNS.log("Establishing link to "+RNS.prettyhexrep(self.outbound_propagation_node)+" for message download", RNS.LOG_DEBUG)
                        propagation_node_identity = RNS.Identity.recall(self.outbound_propagation_node)
                        propagation_node_destination = RNS.Destination(propagation_node_identity, RNS.Destination.OUT, RNS.Destination.SINGLE, APP_NAME, "propagation")
                        def msg_request_established_callback(link):
                            self.request_messages_from_propagation_node(identity, self.propagation_transfer_max_messages)

                        self.outbound_propagation_link = RNS.Link(propagation_node_destination, established_callback=msg_request_established_callback)
                    else:
                        RNS.log("No path known for message download from propagation node "+RNS.prettyhexrep(self.outbound_propagation_node)+". Requesting path...", RNS.LOG_DEBUG)
                        RNS.Transport.request_path(self.outbound_propagation_node)
                        self.wants_download_on_path_available_from = self.outbound_propagation_node
                        self.wants_download_on_path_available_to = identity
                        self.wants_download_on_path_available_timeout = time.time() + LXMRouter.PR_PATH_TIMEOUT
                        self.propagation_transfer_state = LXMRouter.PR_PATH_REQUESTED
                        self.request_messages_path_job()
                else:
                    RNS.log("Waiting for propagation node link to become active", RNS.LOG_EXTREME)
        else:
            RNS.log("Cannot request LXMF propagation node sync, no default propagation node configured", RNS.LOG_WARNING)

    def cancel_propagation_node_requests(self):
        if self.outbound_propagation_link != None:
            self.outbound_propagation_link.teardown()
            self.outbound_propagation_link = None

        self.acknowledge_sync_completion(reset_state=True)

    def enable_propagation(self):
        try:
            self.messagepath = self.storagepath+"/messagestore"

            if not os.path.isdir(self.storagepath):
                os.makedirs(self.storagepath)

            if not os.path.isdir(self.messagepath):
                os.makedirs(self.messagepath)

            self.propagation_entries = {}
            for filename in os.listdir(self.messagepath):
                components = filename.split("_")
                if len(components) == 2:
                    if float(components[1]) > 0:
                        if len(components[0]) == RNS.Identity.HASHLENGTH//8*2:
                            try:
                                transient_id = bytes.fromhex(components[0])
                                received = float(components[1])

                                filepath = self.messagepath+"/"+filename
                                msg_size = os.path.getsize(filepath)
                                file = open(filepath, "rb")
                                destination_hash = file.read(LXMessage.DESTINATION_LENGTH)
                                file.close()

                                self.propagation_entries[transient_id] = [
                                    destination_hash,
                                    filepath,
                                    received,
                                    msg_size,
                                ]

                            except Exception as e:
                                RNS.log("Could not read LXM from message store. The contained exception was: "+str(e), RNS.LOG_ERROR)
            
            if os.path.isfile(self.storagepath+"/peers"):
                peers_file = open(self.storagepath+"/peers", "rb")
                peers_data = peers_file.read()

                if len(peers_data) > 0:
                    serialised_peers = msgpack.unpackb(peers_data)

                    for serialised_peer in serialised_peers:
                        peer = LXMPeer.from_bytes(serialised_peer, self)
                        if peer.identity != None:
                            self.peers[peer.destination_hash] = peer
                            lim_str = ", no transfer limit"
                            if peer.propagation_transfer_limit != None:
                                lim_str = ", "+RNS.prettysize(peer.propagation_transfer_limit*1000)+" transfer limit"
                            RNS.log("Loaded peer "+RNS.prettyhexrep(peer.destination_hash)+" with "+str(len(peer.unhandled_messages))+" unhandled messages"+lim_str, RNS.LOG_DEBUG)
                        else:
                            RNS.log("Peer "+RNS.prettyhexrep(peer.destination_hash)+" could not be loaded, because its identity could not be recalled. Dropping peer.", RNS.LOG_DEBUG)


            self.propagation_node = True
            self.propagation_destination.set_link_established_callback(self.propagation_link_established)
            self.propagation_destination.set_packet_callback(self.propagation_packet)

            self.propagation_destination.register_request_handler(LXMPeer.OFFER_REQUEST_PATH, self.offer_request, allow = RNS.Destination.ALLOW_ALL)
            self.propagation_destination.register_request_handler(LXMPeer.MESSAGE_GET_PATH, self.message_get_request, allow = RNS.Destination.ALLOW_ALL)

            if self.message_storage_limit != None:
                limit_str = ", limit is "+RNS.prettysize(self.message_storage_limit)
            else:
                limit_str = ""

            RNS.log("LXMF Propagation Node message store size is "+RNS.prettysize(self.message_storage_size())+limit_str, RNS.LOG_DEBUG)

            self.announce_propagation_node()

        except Exception as e:
            RNS.log("Could not enable propagation node. The contained exception was: "+str(e), RNS.LOG_ERROR)
            raise e
            RNS.panic()

    def disable_propagation(self):
        self.propagation_node = False
        self.announce_propagation_node()

    def enforce_stamps(self):
        self._enforce_stamps = True

    def ignore_stamps(self):
        self._enforce_stamps = False

    def ignore_destination(self, destination_hash):
        if not destination_hash in self.ignored_list:
            self.ignored_list.append(destination_hash)

    def unignore_destination(self, destination_hash):
        if destination_hash in self.ignored_list:
            self.ignored_list.remove(destination_hash)

    def set_message_storage_limit(self, kilobytes = None, megabytes = None, gigabytes = None):
        limit_bytes = 0

        if kilobytes != None:
            limit_bytes += kilobytes*1000

        if megabytes != None:
            limit_bytes += megabytes*1000*1000

        if gigabytes != None:
            limit_bytes += gigabytes*1000*1000*1000

        if limit_bytes == 0:
            limit_bytes = None

        try:
            if limit_bytes == None or int(limit_bytes) > 0:
                self.message_storage_limit = int(limit_bytes)
            else:
                raise ValueError("Cannot set LXMF information storage limit to "+str(limit_bytes))
        
        except Exception as e:
            raise ValueError("Cannot set LXMF information storage limit to "+str(limit_bytes))

    def message_storage_limit(self):
        return self.message_storage_limit

    def message_storage_size(self):
        if self.propagation_node:
            return sum(self.propagation_entries[f][3] for f in self.propagation_entries)
        else:
            return None

    def set_information_storage_limit(self, kilobytes = None, megabytes = None, gigabytes = None):
        limit_bytes = 0

        if kilobytes != None:
            limit_bytes += kilobytes*1000

        if megabytes != None:
            limit_bytes += megabytes*1000*1000

        if gigabytes != None:
            limit_bytes += gigabytes*1000*1000*1000

        if limit_bytes == 0:
            limit_bytes = None

        try:
            if limit_bytes == None or int(limit_bytes) > 0:
                self.information_storage_limit = int(limit_bytes)
            else:
                raise ValueError("Cannot set LXMF information storage limit to "+str(limit_bytes))
        
        except Exception as e:
            raise ValueError("Cannot set LXMF information storage limit to "+str(limit_bytes))

    def information_storage_limit(self):
        return self.information_storage_limit

    def information_storage_size(self):
        pass

    def delivery_link_available(self, destination_hash):
        if destination_hash in self.direct_links or destination_hash in self.backchannel_links:
            return True
        else:
            return False


    ### Utility & Maintenance #############################
    #######################################################

    JOB_OUTBOUND_INTERVAL  = 1
    JOB_STAMPS_INTERVAL    = 1
    JOB_LINKS_INTERVAL     = 1
    JOB_TRANSIENT_INTERVAL = 60
    JOB_STORE_INTERVAL     = 120
    JOB_PEERSYNC_INTERVAL  = 12
    def jobs(self):
        self.processing_count += 1

        if self.processing_count % LXMRouter.JOB_OUTBOUND_INTERVAL == 0:
            self.process_outbound()

        if self.processing_count % LXMRouter.JOB_STAMPS_INTERVAL == 0:
            threading.Thread(target=self.process_deferred_stamps, daemon=True).start()

        if self.processing_count % LXMRouter.JOB_LINKS_INTERVAL == 0:
            self.clean_links()

        if self.processing_count % LXMRouter.JOB_TRANSIENT_INTERVAL == 0:
            self.clean_transient_id_caches()

        if self.processing_count % LXMRouter.JOB_STORE_INTERVAL == 0:
            self.clean_message_store()

        if self.processing_count % LXMRouter.JOB_PEERSYNC_INTERVAL == 0:
            self.sync_peers()

    def jobloop(self):
        while (True):
            # TODO: Improve this to scheduling, so manual
            # triggers can delay next run

            try:
                self.jobs()
            except Exception as e:
                RNS.log("An error ocurred while running LXMF Router jobs.", RNS.LOG_ERROR)
                RNS.log("The contained exception was: "+str(e), RNS.LOG_ERROR)
            time.sleep(LXMRouter.PROCESSING_INTERVAL)

    def clean_links(self):
        closed_links = []
        for link_hash in self.direct_links:
            link = self.direct_links[link_hash]
            inactive_time = link.inactive_for()

            if inactive_time > LXMRouter.LINK_MAX_INACTIVITY:
                link.teardown()
                closed_links.append(link_hash)

        for link_hash in closed_links:
            cleaned_link = self.direct_links.pop(link_hash)
            RNS.log("Cleaned link "+str(cleaned_link), RNS.LOG_DEBUG)

        try:
            inactive_links = []
            for link in self.active_propagation_links:
                if link.no_data_for() > LXMRouter.P_LINK_MAX_INACTIVITY:
                    inactive_links.append(link)

            for link in inactive_links:
                self.active_propagation_links.remove(link)
                link.teardown()
        
        except Exception as e:
            RNS.log("An error occurred while cleaning inbound propagation links. The contained exception was: "+str(e), RNS.LOG_ERROR)

        if self.outbound_propagation_link != None and self.outbound_propagation_link.status == RNS.Link.CLOSED:
            self.outbound_propagation_link = None
            if self.propagation_transfer_state == LXMRouter.PR_COMPLETE:
                self.acknowledge_sync_completion()
            elif self.propagation_transfer_state < LXMRouter.PR_LINK_ESTABLISHED:
                self.acknowledge_sync_completion(failure_state=LXMRouter.PR_LINK_FAILED)
            elif self.propagation_transfer_state >= LXMRouter.PR_LINK_ESTABLISHED and self.propagation_transfer_state < LXMRouter.PR_COMPLETE:
                self.acknowledge_sync_completion(failure_state=LXMRouter.PR_TRANSFER_FAILED)
            else:
                RNS.log(f"Unknown propagation transfer state on link cleaning: {self.propagation_transfer_state}", RNS.LOG_DEBUG)
                self.acknowledge_sync_completion()

            RNS.log("Cleaned outbound propagation link", RNS.LOG_DEBUG)

    def clean_transient_id_caches(self):
        now = time.time()
        removed_entries = []
        for transient_id in self.locally_delivered_transient_ids:
            timestamp = self.locally_delivered_transient_ids[transient_id]
            if now > timestamp+LXMRouter.MESSAGE_EXPIRY*1.25:
                removed_entries.append(transient_id)

        for transient_id in removed_entries:
            self.locally_delivered_transient_ids.pop(transient_id)
            RNS.log("Cleaned "+RNS.prettyhexrep(transient_id)+" from local delivery cache", RNS.LOG_DEBUG)

        removed_entries = []
        for transient_id in self.locally_processed_transient_ids:
            timestamp = self.locally_processed_transient_ids[transient_id]
            if now > timestamp+LXMRouter.MESSAGE_EXPIRY*1.25:
                removed_entries.append(transient_id)

        for transient_id in removed_entries:
            self.locally_processed_transient_ids.pop(transient_id)
            RNS.log("Cleaned "+RNS.prettyhexrep(transient_id)+" from locally processed cache", RNS.LOG_DEBUG)

    def update_stamp_cost(self, destination_hash, stamp_cost):
        RNS.log(f"Updating outbound stamp cost for {RNS.prettyhexrep(destination_hash)} to {stamp_cost}", RNS.LOG_DEBUG)
        self.outbound_stamp_costs[destination_hash] = [time.time(), stamp_cost]
        
        def job():
            self.save_outbound_stamp_costs()
        threading.Thread(target=self.save_outbound_stamp_costs, daemon=True).start()

    def get_announce_app_data(self, destination_hash):
        if destination_hash in self.delivery_destinations:
            delivery_destination = self.delivery_destinations[destination_hash]
            
            display_name = None
            if delivery_destination.display_name != None:
                display_name = delivery_destination.display_name.encode("utf-8")

            stamp_cost = None
            if delivery_destination.stamp_cost != None and type(delivery_destination.stamp_cost) == int:
                if delivery_destination.stamp_cost > 0 and delivery_destination.stamp_cost < 255:
                    stamp_cost = delivery_destination.stamp_cost

            peer_data = [display_name, stamp_cost]

            return msgpack.packb(peer_data)

    def get_weight(self, transient_id):
        dst_hash = self.propagation_entries[transient_id][0]
        lxm_rcvd = self.propagation_entries[transient_id][2]
        lxm_size = self.propagation_entries[transient_id][3]

        now = time.time()
        age_weight = max(1, (now - lxm_rcvd)/60/60/24/4)

        if dst_hash in self.prioritised_list:
            priority_weight = 0.1
        else:
            priority_weight = 1.0
        
        weight = priority_weight * age_weight * lxm_size

        return weight

    def generate_ticket(self, destination_hash, expiry=LXMessage.TICKET_EXPIRY):
        now = time.time()
        ticket = None
        if destination_hash in self.available_tickets["last_deliveries"]:
            last_delivery = self.available_tickets["last_deliveries"][destination_hash]
            elapsed = now - last_delivery
            if elapsed < LXMessage.TICKET_INTERVAL:
                RNS.log(f"A ticket for {RNS.prettyhexrep(destination_hash)} was already delivered {RNS.prettytime(elapsed)} ago, not including another ticket yet", RNS.LOG_DEBUG)
                return None

        if destination_hash in self.available_tickets["inbound"]:
            for ticket in self.available_tickets["inbound"][destination_hash]:
                ticket_entry = self.available_tickets["inbound"][destination_hash][ticket]
                expires = ticket_entry[0]; validity_left = expires - now
                if validity_left > LXMessage.TICKET_RENEW:
                    RNS.log(f"Found generated ticket for {RNS.prettyhexrep(destination_hash)} with {RNS.prettytime(validity_left)} of validity left, re-using this one", RNS.LOG_DEBUG)
                    return [expires, ticket]
        
        else:
            self.available_tickets["inbound"][destination_hash] = {}

        RNS.log(f"No generated tickets for {RNS.prettyhexrep(destination_hash)} with enough validity found, generating a new one", RNS.LOG_DEBUG)
        expires = now+expiry
        ticket  = os.urandom(LXMessage.TICKET_LENGTH)
        self.available_tickets["inbound"][destination_hash][ticket] = [expires]
        self.save_available_tickets()

        return [expires, ticket]

    def remember_ticket(self, destination_hash, ticket_entry):
        expires = ticket_entry[0]-time.time()
        RNS.log(f"Remembering ticket for {RNS.prettyhexrep(destination_hash)}, expires in {RNS.prettytime(expires)}", RNS.LOG_DEBUG)
        self.available_tickets["outbound"][destination_hash] = [ticket_entry[0], ticket_entry[1]]

    def get_outbound_ticket(self, destination_hash):
        if destination_hash in self.available_tickets["outbound"]:
            entry = self.available_tickets["outbound"][destination_hash]
            if entry[0] > time.time():
                return entry[1]

        return None

    def get_outbound_ticket_expiry(self, destination_hash):
        if destination_hash in self.available_tickets["outbound"]:
            entry = self.available_tickets["outbound"][destination_hash]
            if entry[0] > time.time():
                return entry[0]

        return None

    def get_inbound_tickets(self, destination_hash):
        now = time.time()
        available_tickets = []
        if destination_hash in self.available_tickets["inbound"]:
            for inbound_ticket in self.available_tickets["inbound"][destination_hash]:
                if now < self.available_tickets["inbound"][destination_hash][inbound_ticket][0]:
                    available_tickets.append(inbound_ticket)

        if len(available_tickets) == 0:
            return None
        else:
            return available_tickets

    def get_size(self, transient_id):
        lxm_size = self.propagation_entries[transient_id][3]
        return lxm_size


    def clean_message_store(self):
        # Check and remove expired messages
        now = time.time()
        removed_entries = {}
        for transient_id in self.propagation_entries:
            entry = self.propagation_entries[transient_id]
            filepath = entry[1]
            components = filepath.split("_")

            if len(components) == 2 and float(components[1]) > 0 and len(os.path.split(components[0])[1]) == (RNS.Identity.HASHLENGTH//8)*2:
                timestamp = float(components[1])
                if now > timestamp+LXMRouter.MESSAGE_EXPIRY:
                    RNS.log("Purging message "+RNS.prettyhexrep(transient_id)+" due to expiry", RNS.LOG_DEBUG)
                    removed_entries[transient_id] = filepath
            else:
                RNS.log("Purging message "+RNS.prettyhexrep(transient_id)+" due to invalid file path", RNS.LOG_WARNING)
                removed_entries[transient_id] = filepath
        
        removed_count = 0
        for transient_id in removed_entries:
            try:
                filepath = removed_entries[transient_id]
                self.propagation_entries.pop(transient_id)
                if os.path.isfile(filepath):
                        os.unlink(filepath)
                removed_count += 1
            except Exception as e:
                RNS.log("Could not remove "+RNS.prettyhexrep(transient_id)+" from message store. The contained exception was: "+str(e), RNS.LOG_ERROR)

        if removed_count > 0:
            RNS.log("Cleaned "+str(removed_count)+" entries from the message store", RNS.LOG_DEBUG)

        # Check size of message store and cull if needed
        try:
            message_storage_size = self.message_storage_size()
            if message_storage_size != None:
                if self.message_storage_limit != None and message_storage_size > self.message_storage_limit:
                    # Clean the message storage according to priorities
                    bytes_needed = message_storage_size - self.message_storage_limit
                    bytes_cleaned = 0

                    weighted_entries = []
                    for transient_id in self.propagation_entries:
                        weighted_entries.append([
                            self.propagation_entries[transient_id],
                            self.get_weight(transient_id),
                            transient_id
                        ])

                    weighted_entries.sort(key=lambda we: we[1], reverse=True)

                    i = 0
                    while i < len(weighted_entries) and bytes_cleaned < bytes_needed:
                        try:
                            w = weighted_entries[i]
                            entry = w[0]
                            transient_id = w[2]
                            filepath = entry[1]

                            if os.path.isfile(filepath):
                                os.unlink(filepath)
                            
                            self.propagation_entries.pop(transient_id)
                            bytes_cleaned += entry[3]

                            RNS.log("Removed "+RNS.prettyhexrep(transient_id)+" with weight "+str(w[1])+" to clear up "+RNS.prettysize(entry[3])+", now cleaned "+RNS.prettysize(bytes_cleaned)+" out of "+RNS.prettysize(bytes_needed)+" needed", RNS.LOG_EXTREME)
    
                        except Exception as e:
                            RNS.log("Error while cleaning LXMF message from message store. The contained exception was: "+str(e), RNS.LOG_ERROR)
    
                        finally:
                            i += 1

                    RNS.log("LXMF message store size is now "+RNS.prettysize(self.message_storage_size())+" for "+str(len(self.propagation_entries))+" items", RNS.LOG_EXTREME)


        except Exception as e:
            RNS.log("Could not clean the LXMF message store. The contained exception was: "+str(e), RNS.LOG_ERROR)

    def save_locally_delivered_transient_ids(self):
        try:
            if not os.path.isdir(self.storagepath):
                    os.makedirs(self.storagepath)

            locally_delivered_file = open(self.storagepath+"/local_deliveries", "wb")
            locally_delivered_file.write(msgpack.packb(self.locally_delivered_transient_ids))
            locally_delivered_file.close()

        except Exception as e:
            RNS.log("Could not save locally delivered message ID cache to storage. The contained exception was: "+str(e), RNS.LOG_ERROR)

    def save_locally_processed_transient_ids(self):
        try:
            if not os.path.isdir(self.storagepath):
                    os.makedirs(self.storagepath)

            locally_processed_file = open(self.storagepath+"/locally_processed", "wb")
            locally_processed_file.write(msgpack.packb(self.locally_processed_transient_ids))
            locally_processed_file.close()

        except Exception as e:
            RNS.log("Could not save locally processed transient ID cache to storage. The contained exception was: "+str(e), RNS.LOG_ERROR)

    def clean_outbound_stamp_costs(self):
        try:
            expired = []
            for destination_hash in self.outbound_stamp_costs:
                entry = self.outbound_stamp_costs[destination_hash]
                if time.time() > entry[0] + LXMRouter.STAMP_COST_EXPIRY:
                    expired.append(destination_hash)

            for destination_hash in expired:
                self.outbound_stamp_costs.pop(destination_hash)
        
        except Exception as e:
            RNS.log(f"Error while cleaning outbound stamp costs. The contained exception was: {e}", RNS.LOG_ERROR)
            RNS.trace_exception(e)

    def save_outbound_stamp_costs(self):
        with self.cost_file_lock:
            try:
                if not os.path.isdir(self.storagepath):
                        os.makedirs(self.storagepath)

                outbound_stamp_costs_file = open(self.storagepath+"/outbound_stamp_costs", "wb")
                outbound_stamp_costs_file.write(msgpack.packb(self.outbound_stamp_costs))
                outbound_stamp_costs_file.close()

            except Exception as e:
                RNS.log("Could not save outbound stamp costs to storage. The contained exception was: "+str(e), RNS.LOG_ERROR)

    def clean_available_tickets(self):
        try:
            # Clean outbound tickets
            expired_outbound = []
            for destination_hash in self.available_tickets["outbound"]:
                entry = self.available_tickets["outbound"][destination_hash]
                if time.time() > entry[0]:
                    expired_outbound.append(destination_hash)

            for destination_hash in expired_outbound:
                self.available_tickets["outbound"].pop(destination_hash)

            # Clean inbound tickets
            for destination_hash in self.available_tickets["inbound"]:
                expired_inbound = []
                for inbound_ticket in self.available_tickets["inbound"][destination_hash]:
                    entry = self.available_tickets["inbound"][destination_hash][inbound_ticket]
                    ticket_expiry = entry[0]
                    if time.time() > ticket_expiry+LXMessage.TICKET_GRACE:
                        expired_inbound.append(inbound_ticket)

                for inbound_ticket in expired_inbound:
                    self.available_tickets["inbound"][destination_hash].pop(destination_hash)
        
        except Exception as e:
            RNS.log(f"Error while cleaning available tickets. The contained exception was: {e}", RNS.LOG_ERROR)
            RNS.trace_exception(e)

    def save_available_tickets(self):
        with self.ticket_file_lock:
            try:
                if not os.path.isdir(self.storagepath):
                        os.makedirs(self.storagepath)

                available_tickets_file = open(self.storagepath+"/available_tickets", "wb")
                available_tickets_file.write(msgpack.packb(self.available_tickets))
                available_tickets_file.close()

            except Exception as e:
                RNS.log("Could not save available tickets to storage. The contained exception was: "+str(e), RNS.LOG_ERROR)

    def reload_available_tickets(self):
        RNS.log("Reloading available tickets from storage", RNS.LOG_DEBUG)
        try:
            with self.ticket_file_lock:
                with open(self.storagepath+"/available_tickets", "rb") as available_tickets_file:
                    data = available_tickets_file.read()
                    self.available_tickets = msgpack.unpackb(data)
                    if not type(self.available_tickets) == dict:
                        RNS.log("Invalid data format for loaded available tickets, recreating...", RNS.LOG_ERROR)
                        self.available_tickets = {"outbound": {}, "inbound": {}, "last_deliveries": {}}
                    if not "outbound" in self.available_tickets:
                        RNS.log("Missing outbound entry in loaded available tickets, recreating...", RNS.LOG_ERROR)
                        self.available_tickets["outbound"] = {}
                    if not "inbound" in self.available_tickets:
                        RNS.log("Missing inbound entry in loaded available tickets, recreating...", RNS.LOG_ERROR)
                        self.available_tickets["inbound"] = {}
                    if not "last_deliveries" in self.available_tickets:
                        RNS.log("Missing local_deliveries entry in loaded available tickets, recreating...", RNS.LOG_ERROR)
                        self.available_tickets["last_deliveries"] = {}
        
        except Exception as e:
            RNS.log(f"An error occurred while reloading available tickets from storage: {e}", RNS.LOG_ERROR)

    def exit_handler(self):
        if self.propagation_node:
            try:
                serialised_peers = []
                for peer_id in self.peers:
                    peer = self.peers[peer_id]
                    serialised_peers.append(peer.to_bytes())

                peers_file = open(self.storagepath+"/peers", "wb")
                peers_file.write(msgpack.packb(serialised_peers))
                peers_file.close()

                RNS.log("Saved "+str(len(serialised_peers))+" peers to storage", RNS.LOG_DEBUG)

            except Exception as e:
                RNS.log("Could not save propagation node peers to storage. The contained exception was: "+str(e), RNS.LOG_ERROR)

        self.save_locally_delivered_transient_ids()
        self.save_locally_processed_transient_ids()

    def __str__(self):
        return "<LXMRouter "+RNS.hexrep(self.identity.hash, delimit=False)+">"


    ### Message Download ##################################
    #######################################################
    
    def request_messages_path_job(self):
        job_thread = threading.Thread(target=self.__request_messages_path_job)
        job_thread.setDaemon(True)
        job_thread.start()

    def __request_messages_path_job(self):
        path_timeout = self.wants_download_on_path_available_timeout
        while not RNS.Transport.has_path(self.wants_download_on_path_available_from) and time.time() < path_timeout:
            time.sleep(0.1)

        if RNS.Transport.has_path(self.wants_download_on_path_available_from):
            self.request_messages_from_propagation_node(self.wants_download_on_path_available_to, self.propagation_transfer_max_messages)
        else:
            RNS.log("Propagation node path request timed out", RNS.LOG_DEBUG)
            self.acknowledge_sync_completion(failure_state=LXMRouter.PR_NO_PATH)
    
    def identity_allowed(self, identity):
        if self.auth_required:
            if identity.hash in self.allowed_list:
                return True
            else:
                return False
        
        else:
            return True

    def message_get_request(self, path, data, request_id, remote_identity, requested_at):
        if remote_identity == None:
            return LXMPeer.ERROR_NO_IDENTITY
        
        elif not self.identity_allowed(remote_identity):
            return LXMPeer.ERROR_NO_ACCESS

        else:
            try:
                remote_destination = RNS.Destination(remote_identity, RNS.Destination.OUT, RNS.Destination.SINGLE, APP_NAME, "delivery")

                # If both want and have fields are empty, send a list of
                # available messages.
                if data[0] == None and data[1] == None:
                    available_messages = []
                    for transient_id in self.propagation_entries:
                        message_entry = self.propagation_entries[transient_id]
                        if message_entry[0] == remote_destination.hash:
                            message_size = os.path.getsize(message_entry[1])
                            available_entry = [transient_id, message_size]
                            available_messages.append(available_entry)

                    available_messages.sort(key=lambda e: e[1], reverse=False)

                    transient_ids = []
                    for available_entry in available_messages:
                        transient_ids.append(available_entry[0])

                    return transient_ids

                else:
                    # Process messages the client already have
                    if data[1] != None and len(data[1]) > 0:
                        for transient_id in data[1]:
                            if transient_id in self.propagation_entries and self.propagation_entries[transient_id][0] == remote_destination.hash:
                                try:
                                    filepath = self.propagation_entries[transient_id][1]
                                    self.propagation_entries.pop(transient_id)
                                    os.unlink(filepath)
                                    RNS.log("Client "+RNS.prettyhexrep(remote_destination.hash)+" purged message "+RNS.prettyhexrep(transient_id)+" at "+str(filepath), RNS.LOG_DEBUG)
                                
                                except Exception as e:
                                    RNS.log("Error while processing message purge request from "+RNS.prettyhexrep(remote_destination.hash)+". The contained exception was: "+str(e), RNS.LOG_ERROR)


                    # Process wanted messages
                    response_messages = []
                    if data[0] != None and len(data[0]) > 0:
                        client_transfer_limit = None
                        if len(data) >= 3:
                            try:
                                client_transfer_limit = float(data[2])*1000
                                RNS.log("Client indicates transfer limit of "+RNS.prettysize(client_transfer_limit), RNS.LOG_DEBUG)
                            except:
                                pass

                        per_message_overhead = 16 # Really only 2 bytes, but set a bit higher for now
                        cumulative_size = 24 # Initialised to highest reasonable binary structure overhead
                        for transient_id in data[0]:
                            if transient_id in self.propagation_entries and self.propagation_entries[transient_id][0] == remote_destination.hash:
                                try:
                                    filepath = self.propagation_entries[transient_id][1]
                                    RNS.log("Client "+RNS.prettyhexrep(remote_destination.hash)+" requested message "+RNS.prettyhexrep(transient_id)+" at "+str(filepath), RNS.LOG_DEBUG)

                                    message_file = open(filepath, "rb")
                                    lxmf_data = message_file.read()
                                    message_file.close()

                                    lxm_size = len(lxmf_data)
                                    next_size = cumulative_size + (lxm_size+per_message_overhead)

                                    if client_transfer_limit != None and next_size > client_transfer_limit:
                                        pass
                                    else:
                                        response_messages.append(lxmf_data)
                                        cumulative_size += (lxm_size+per_message_overhead)

                                except Exception as e:
                                    RNS.log("Error while processing message download request from "+RNS.prettyhexrep(remote_destination.hash)+". The contained exception was: "+str(e), RNS.LOG_ERROR)

                    return response_messages

               
            except Exception as e:
                RNS.log("Error occurred while generating response for download request, the contained exception was: "+str(e), RNS.LOG_DEBUG)
                return None

    def message_list_response(self, request_receipt):
        if request_receipt.response == LXMPeer.ERROR_NO_IDENTITY:
            RNS.log("Propagation node indicated missing identification on list request, tearing down link.", RNS.LOG_DEBUG)
            if self.outbound_propagation_link != None:
                self.outbound_propagation_link.teardown()
            self.propagation_transfer_state = LXMRouter.PR_NO_IDENTITY_RCVD

        elif request_receipt.response == LXMPeer.ERROR_NO_ACCESS:
            RNS.log("Propagation node did not allow list request, tearing down link.", RNS.LOG_DEBUG)
            if self.outbound_propagation_link != None:
                self.outbound_propagation_link.teardown()
            self.propagation_transfer_state = LXMRouter.PR_NO_ACCESS

        else:
            if request_receipt.response != None and isinstance(request_receipt.response, list):
                haves = []
                wants = []
                if len(request_receipt.response) > 0:
                    for transient_id in request_receipt.response:
                        if not self.retain_synced_on_node and self.has_message(transient_id):
                            haves.append(transient_id)
                        else:
                            if self.propagation_transfer_max_messages == LXMRouter.PR_ALL_MESSAGES or len(wants) < self.propagation_transfer_max_messages:
                                wants.append(transient_id)

                    request_receipt.link.request(
                        LXMPeer.MESSAGE_GET_PATH,
                        [wants, haves, self.delivery_per_transfer_limit],
                        response_callback=self.message_get_response,
                        failed_callback=self.message_get_failed,
                        progress_callback=self.message_get_progress
                    )
                else:
                    self.propagation_transfer_state = LXMRouter.PR_COMPLETE
                    self.propagation_transfer_progress = 1.0
                    self.propagation_transfer_last_result = 0

    def message_get_response(self, request_receipt):
        if request_receipt.response == LXMPeer.ERROR_NO_IDENTITY:
            RNS.log("Propagation node indicated missing identification on get request, tearing down link.", RNS.LOG_DEBUG)
            if self.outbound_propagation_link != None:
                self.outbound_propagation_link.teardown()
            self.propagation_transfer_state = LXMRouter.PR_NO_IDENTITY_RCVD

        elif request_receipt.response == LXMPeer.ERROR_NO_ACCESS:
            RNS.log("Propagation node did not allow get request, tearing down link.", RNS.LOG_DEBUG)
            if self.outbound_propagation_link != None:
                self.outbound_propagation_link.teardown()
            self.propagation_transfer_state = LXMRouter.PR_NO_ACCESS

        else:
            if request_receipt.response != None and len(request_receipt.response) > 0:
                haves = []
                for lxmf_data in request_receipt.response:
                    self.lxmf_propagation(lxmf_data)
                    haves.append(RNS.Identity.full_hash(lxmf_data))

                # Return a list of successfully received messages to the node.
                # This deletes the messages on the propagation node.
                # TODO: Add option to keep messages on node.
                request_receipt.link.request(
                    LXMPeer.MESSAGE_GET_PATH,
                    [None, haves],
                    # response_callback=self.message_syncfinal_response,
                    failed_callback=self.message_get_failed,
                    # progress_callback=self.message_get_progress
                )

            self.propagation_transfer_state = LXMRouter.PR_COMPLETE
            self.propagation_transfer_progress = 1.0
            self.propagation_transfer_last_result = len(request_receipt.response)
            self.save_locally_delivered_transient_ids()

    def message_get_progress(self, request_receipt):
        self.propagation_transfer_state = LXMRouter.PR_RECEIVING
        self.propagation_transfer_progress = request_receipt.get_progress()

    def message_get_failed(self, request_receipt):
        RNS.log("Message list/get request failed", RNS.LOG_DEBUG)
        if self.outbound_propagation_link != None:
            self.outbound_propagation_link.teardown()

    def acknowledge_sync_completion(self, reset_state=False, failure_state=None):
        self.propagation_transfer_last_result = None
        if reset_state or self.propagation_transfer_state <= LXMRouter.PR_COMPLETE:
            if failure_state == None:
                self.propagation_transfer_state = LXMRouter.PR_IDLE
            else:
                self.propagation_transfer_state = failure_state

        self.propagation_transfer_progress = 0.0
        self.wants_download_on_path_available_from = None
        self.wants_download_on_path_available_to = None

    def has_message(self, transient_id):
        if transient_id in self.locally_delivered_transient_ids:
            return True
        else:
            return False
    
    def handle_outbound(self, lxmessage):
        destination_hash = lxmessage.get_destination().hash

        if lxmessage.stamp_cost == None:
            if destination_hash in self.outbound_stamp_costs:
                stamp_cost = self.outbound_stamp_costs[destination_hash][1]
                lxmessage.stamp_cost = stamp_cost
                RNS.log(f"No stamp cost set on LXM to {RNS.prettyhexrep(destination_hash)}, autoconfigured to {stamp_cost}, as required by latest announce", RNS.LOG_DEBUG)

        lxmessage.state = LXMessage.OUTBOUND

        # If an outbound ticket is available for this
        # destination, attach it to the message.
        lxmessage.outbound_ticket = self.get_outbound_ticket(destination_hash)
        if lxmessage.outbound_ticket != None and lxmessage.defer_stamp:
            RNS.log(f"Deferred stamp generation was requested for {lxmessage}, but outbound ticket was applied, processing immediately", RNS.LOG_DEBUG)
            lxmessage.defer_stamp = False

        # If requested, include a ticket to allow the
        # destination to reply without generating a stamp.
        if lxmessage.include_ticket:
            ticket = self.generate_ticket(lxmessage.destination_hash)
            if ticket:
                lxmessage.fields[FIELD_TICKET] = ticket

        if not lxmessage.packed:
            lxmessage.pack()

        unknown_path_requested = False
        if not RNS.Transport.has_path(destination_hash) and lxmessage.method == LXMessage.OPPORTUNISTIC:
            RNS.log(f"Pre-emptively requesting unknown path for opportunistic {lxmessage}", RNS.LOG_DEBUG)
            RNS.Transport.request_path(destination_hash)
            lxmessage.next_delivery_attempt = time.time() + LXMRouter.PATH_REQUEST_WAIT
            unknown_path_requested = True

        lxmessage.determine_transport_encryption()

        if lxmessage.defer_stamp and lxmessage.stamp_cost == None:
            RNS.log(f"Deferred stamp generation was requested for {lxmessage}, but no stamp is required, processing immediately", RNS.LOG_DEBUG)
            lxmessage.defer_stamp = False

        if not lxmessage.defer_stamp:
            while not unknown_path_requested and self.processing_outbound:
                time.sleep(0.05)

            self.pending_outbound.append(lxmessage)
            if not unknown_path_requested:
                self.process_outbound()

        else:
            self.pending_deferred_stamps[lxmessage.message_id] = lxmessage

    def get_outbound_progress(self, lxm_hash):
        for lxm in self.pending_outbound:
            if lxm.hash == lxm_hash:
                return lxm.progress

        for lxm_id in self.pending_deferred_stamps:
            if self.pending_deferred_stamps[lxm_id].hash == lxm_hash:
                return self.pending_deferred_stamps[lxm_id].progress
        
        return None

    def get_outbound_lxm_stamp_cost(self, lxm_hash):
        for lxm in self.pending_outbound:
            if lxm.hash == lxm_hash:
                return lxm.stamp_cost

        for lxm_id in self.pending_deferred_stamps:
            if self.pending_deferred_stamps[lxm_id].hash == lxm_hash:
                return self.pending_deferred_stamps[lxm_id].stamp_cost
        
        return None


    ### Message Routing & Delivery ########################
    #######################################################

    def lxmf_delivery(self, lxmf_data, destination_type = None, phy_stats = None, ratchet_id = None, method = None, no_stamp_enforcement=False):
        try:
            message = LXMessage.unpack_from_bytes(lxmf_data)
            if ratchet_id and not message.ratchet_id:
                message.ratchet_id = ratchet_id

            if method:
                message.method = method

            if message.signature_validated and FIELD_TICKET in message.fields:
                ticket_entry = message.fields[FIELD_TICKET]
                if type(ticket_entry) == list and len(ticket_entry) > 1:
                    expires = ticket_entry[0]
                    ticket  = ticket_entry[1]

                    if time.time() < expires:
                        if type(ticket) == bytes and len(ticket) == LXMessage.TICKET_LENGTH:
                            self.remember_ticket(message.source_hash, ticket_entry)
                            def save_job():
                                self.save_available_tickets()
                            threading.Thread(target=save_job, daemon=True).start()

            required_stamp_cost = self.delivery_destinations[message.destination_hash].stamp_cost
            if required_stamp_cost != None:
                destination_tickets = self.get_inbound_tickets(message.source_hash)
                if message.validate_stamp(required_stamp_cost, tickets=destination_tickets):
                    message.stamp_valid = True
                    message.stamp_checked = True
                else:
                    message.stamp_valid = False
                    message.stamp_checked = True

                if not message.stamp_valid:
                    if no_stamp_enforcement:
                        RNS.log(f"Received {message} with invalid stamp, but allowing anyway, since stamp enforcement was temporarily disabled", RNS.LOG_NOTICE)
                    else:
                        if self._enforce_stamps:
                            RNS.log(f"Dropping {message} with invalid stamp", RNS.LOG_NOTICE)
                            return False
                        else:
                            RNS.log(f"Received {message} with invalid stamp, but allowing anyway, since stamp enforcement is disabled", RNS.LOG_NOTICE)
                else:
                    RNS.log(f"Received {message} with valid stamp", RNS.LOG_DEBUG)

            if phy_stats != None:
                if "rssi" in phy_stats: message.rssi = phy_stats["rssi"]
                if "snr" in phy_stats: message.snr = phy_stats["snr"]
                if "q" in phy_stats: message.q = phy_stats["q"]

            # TODO: Update these descriptions to account for ratchets
            if destination_type == RNS.Destination.SINGLE:
                message.transport_encrypted = True
                message.transport_encryption = LXMessage.ENCRYPTION_DESCRIPTION_EC
            elif destination_type == RNS.Destination.GROUP:
                message.transport_encrypted = True
                message.transport_encryption = LXMessage.ENCRYPTION_DESCRIPTION_AES
            elif destination_type == RNS.Destination.LINK:
                message.transport_encrypted = True
                message.transport_encryption = LXMessage.ENCRYPTION_DESCRIPTION_EC
            else:
                message.transport_encrypted = False
                message.transport_encryption = None

            if message.source_hash in self.ignored_list:
                RNS.log(str(self)+" ignored message from "+RNS.prettyhexrep(message.source_hash), RNS.LOG_DEBUG)
                return False

            if self.has_message(message.hash):
                RNS.log(str(self)+" ignored already received message from "+RNS.prettyhexrep(message.source_hash), RNS.LOG_DEBUG)
                return False
            else:
                self.locally_delivered_transient_ids[message.hash] = time.time()

            if self.__delivery_callback != None and callable(self.__delivery_callback):
                try:
                    self.__delivery_callback(message)
                except Exception as e:
                    RNS.log("An error occurred in the external delivery callback for "+str(message), RNS.LOG_ERROR)
                    RNS.trace_exception(e)

            return True

        except Exception as e:
            RNS.log("Could not assemble LXMF message from received data", RNS.LOG_NOTICE)
            RNS.log("The contained exception was: "+str(e), RNS.LOG_DEBUG)
            return False

    def delivery_packet(self, data, packet):
        packet.prove()
        try:
            method = None
            if packet.destination_type != RNS.Destination.LINK:
                method = LXMessage.OPPORTUNISTIC
                lxmf_data  = b""
                lxmf_data += packet.destination.hash
                lxmf_data += data
            else:
                method = LXMessage.DIRECT
                lxmf_data = data

            try:
                reticulum = RNS.Reticulum.get_instance()
                if packet.rssi == None: packet.rssi = reticulum.get_packet_rssi(packet.packet_hash)
                if packet.snr  == None: packet.snr  = reticulum.get_packet_snr(packet.packet_hash)
                if packet.q    == None: packet.q    = reticulum.get_packet_q(packet.packet_hash)
            except Exception as e:
                RNS.log("Error while retrieving physical link stats for LXMF delivery packet: "+str(e), RNS.LOG_ERROR)

            phy_stats = {"rssi": packet.rssi, "snr": packet.snr, "q": packet.q}

            self.lxmf_delivery(lxmf_data, packet.destination_type, phy_stats=phy_stats, ratchet_id=packet.ratchet_id, method=method)

        except Exception as e:
            RNS.log("Exception occurred while parsing incoming LXMF data.", RNS.LOG_ERROR)
            RNS.log("The contained exception was: "+str(e), RNS.LOG_ERROR)

    def delivery_link_established(self, link):
        link.track_phy_stats(True)
        link.set_packet_callback(self.delivery_packet)
        link.set_resource_strategy(RNS.Link.ACCEPT_APP)
        link.set_resource_callback(self.delivery_resource_advertised)
        link.set_resource_started_callback(self.resource_transfer_began)
        link.set_resource_concluded_callback(self.delivery_resource_concluded)
        link.set_remote_identified_callback(self.delivery_remote_identified)

    def delivery_link_closed(self, link):
        pass

    def resource_transfer_began(self, resource):
        RNS.log("Transfer began for LXMF delivery resource "+str(resource), RNS.LOG_DEBUG)

    def delivery_resource_advertised(self, resource):
        size = resource.get_data_size()
        limit = self.delivery_per_transfer_limit*1000
        if limit != None and size > limit:
            RNS.log("Rejecting "+RNS.prettysize(size)+" incoming LXMF delivery resource, since it exceeds the limit of "+RNS.prettysize(limit), RNS.LOG_DEBUG)
            return False
        else:
            return True

    def delivery_resource_concluded(self, resource):
        RNS.log("Transfer concluded for LXMF delivery resource "+str(resource), RNS.LOG_DEBUG)
        if resource.status == RNS.Resource.COMPLETE:
            ratchet_id = None
            # Set ratchet ID to link ID if available
            if resource.link and hasattr(resource.link, "link_id"):
                ratchet_id = resource.link.link_id
            phy_stats = {"rssi": resource.link.rssi, "snr": resource.link.snr, "q": resource.link.q}
            self.lxmf_delivery(resource.data.read(), resource.link.type, phy_stats=phy_stats, ratchet_id=ratchet_id, method=LXMessage.DIRECT)

    def delivery_remote_identified(self, link, identity):
        destination_hash = RNS.Destination.hash_from_name_and_identity("lxmf.delivery", identity)
        self.backchannel_links[destination_hash] = link
        RNS.log(f"Backchannel became available for {RNS.prettyhexrep(destination_hash)} on delivery link {link}", RNS.LOG_DEBUG)


    ### Peer Sync & Propagation ###########################
    #######################################################

    def peer(self, destination_hash, timestamp, propagation_transfer_limit):
        if destination_hash in self.peers:
            peer = self.peers[destination_hash]
            if timestamp > peer.peering_timebase:
                peer.alive = True
                peer.sync_backoff = 0
                peer.next_sync_attempt = 0
                peer.peering_timebase = timestamp
                peer.last_heard = time.time()
                peer.propagation_transfer_limit = propagation_transfer_limit
            
        else:
            peer = LXMPeer(self, destination_hash)
            peer.alive = True
            peer.last_heard = time.time()
            peer.propagation_transfer_limit = propagation_transfer_limit
            self.peers[destination_hash] = peer
            RNS.log("Peered with "+str(peer.destination))

    def unpeer(self, destination_hash, timestamp = None):
        if timestamp == None:
            timestamp = int(time.time())

        if destination_hash in self.peers:
            peer = self.peers[destination_hash]

            if timestamp >= peer.peering_timebase:
                self.peers.pop(destination_hash)
                RNS.log("Broke peering with "+str(peer.destination))

    def sync_peers(self):
        culled_peers  = []
        waiting_peers = []
        unresponsive_peers = []
        for peer_id in self.peers:
            peer = self.peers[peer_id]
            if time.time() > peer.last_heard + LXMPeer.MAX_UNREACHABLE:
                culled_peers.append(peer_id)
            else:
                if peer.state == LXMPeer.IDLE and len(peer.unhandled_messages) > 0:
                    if peer.alive:
                        waiting_peers.append(peer)
                    else:
                        if hasattr(peer, "next_sync_attempt") and time.time() > peer.next_sync_attempt:
                            unresponsive_peers.append(peer)
                        else:
                            pass
                            # RNS.log("Not adding peer "+str(peer)+" since it is in sync backoff", RNS.LOG_DEBUG)

        peer_pool = []
        if len(waiting_peers) > 0:
            fastest_peers = sorted(
                waiting_peers,
                key=lambda p: p.link_establishment_rate,
                reverse=True
            )[0:min(LXMRouter.FASTEST_N_RANDOM_POOL, len(waiting_peers))]
            peer_pool.extend(fastest_peers)
            
            unknown_speed_peers = [p for p in waiting_peers if p.link_establishment_rate == 0]
            if len(unknown_speed_peers) > 0:
                peer_pool.extend(
                    unknown_speed_peers[
                        0:min(
                            len(unknown_speed_peers),
                            len(fastest_peers)
                        )]
                )

            RNS.log("Selecting peer to sync from "+str(len(waiting_peers))+" waiting peers.", RNS.LOG_DEBUG)
            
        elif len(unresponsive_peers) > 0:
            RNS.log("No active peers available, randomly selecting peer to sync from "+str(len(unresponsive_peers))+" unresponsive peers.", RNS.LOG_DEBUG)
            peer_pool = unresponsive_peers
        
        if len(peer_pool) > 0:
            selected_index = random.randint(0,len(peer_pool)-1)
            selected_peer = peer_pool[selected_index]
            RNS.log("Selected waiting peer "+str(selected_index)+": "+RNS.prettyhexrep(selected_peer.destination.hash), RNS.LOG_DEBUG)
            selected_peer.sync()

        for peer_id in culled_peers:
            RNS.log("Removing peer "+RNS.prettyhexrep(peer_id)+" due to excessive unreachability", RNS.LOG_WARNING)
            try:
                if peer_id in self.peers:
                    self.peers.pop(peer_id)
            except Exception as e:
                RNS.log("Error while removing peer "+RNS.prettyhexrep(peer_id)+". The contained exception was: "+str(e), RNS.LOG_ERROR)

    def propagation_link_established(self, link):
        link.set_packet_callback(self.propagation_packet)
        link.set_resource_strategy(RNS.Link.ACCEPT_APP)
        link.set_resource_callback(self.propagation_resource_advertised)
        link.set_resource_started_callback(self.resource_transfer_began)
        link.set_resource_concluded_callback(self.propagation_resource_concluded)
        self.active_propagation_links.append(link)

    def propagation_resource_advertised(self, resource):
        size = resource.get_data_size()
        limit = self.propagation_per_transfer_limit*1000
        if limit != None and size > limit:
            RNS.log("Rejecting "+RNS.prettysize(size)+" incoming LXMF propagation resource, since it exceeds the limit of "+RNS.prettysize(limit), RNS.LOG_DEBUG)
            return False
        else:
            return True

    def propagation_packet(self, data, packet):
        try:
            if packet.destination_type != RNS.Destination.LINK:
                pass
            else:
                data = msgpack.unpackb(data)
                remote_timebase = data[0]

                messages = data[1]
                for lxmf_data in messages:
                    self.lxmf_propagation(lxmf_data)

                packet.prove()

        except Exception as e:
            RNS.log("Exception occurred while parsing incoming LXMF propagation data.", RNS.LOG_ERROR)
            RNS.log("The contained exception was: "+str(e), RNS.LOG_ERROR)

    def offer_request(self, path, data, request_id, link_id, remote_identity, requested_at):
        if remote_identity == None:
            return LXMPeer.ERROR_NO_IDENTITY
        else:
            try:
                transient_ids = data
                wanted_ids = []

                for transient_id in transient_ids:
                    if not transient_id in self.propagation_entries:
                        wanted_ids.append(transient_id)

                if len(wanted_ids) == 0:
                    return False

                elif len(wanted_ids) == len(transient_ids):
                    return True

                else:
                    return wanted_ids

            except Exception as e:
                RNS.log("Error occurred while generating response for sync request, the contained exception was: "+str(e), RNS.LOG_DEBUG)
                return None

    def propagation_resource_concluded(self, resource):
        RNS.log("Transfer concluded for incoming propagation resource "+str(resource), RNS.LOG_DEBUG)
        if resource.status == RNS.Resource.COMPLETE:
            # TODO: The peer this was received from should
            # have the transient id added to its list of
            # already handled messages.
            try:
                data = msgpack.unpackb(resource.data.read())

                if type(data) == list and len(data) == 2 and type(data[0] == float) and type(data[1]) == list:
                    # This is a series of propagation messages from a peer or originator
                    remote_timebase = data[0]
                    remote_hash = None
                    remote_identity = resource.link.get_remote_identity()

                    if remote_identity != None:
                        remote_destination = RNS.Destination(remote_identity, RNS.Destination.OUT, RNS.Destination.SINGLE, APP_NAME, "propagation")
                        remote_hash = remote_destination.hash

                        if not remote_hash in self.peers:
                            if self.autopeer and RNS.Transport.hops_to(remote_hash) <= self.autopeer_maxdepth:
                                self.peer(remote_hash, remote_timebase)

                    messages = data[1]
                    for lxmf_data in messages:
                        if remote_hash != None and remote_hash in self.peers:
                            transient_id = RNS.Identity.full_hash(lxmf_data)
                            peer = self.peers[remote_hash]
                            peer.handled_messages[transient_id] = [transient_id, remote_timebase, lxmf_data]

                        self.lxmf_propagation(lxmf_data)
                else:
                    RNS.log("Invalid data structure received at propagation destination, ignoring", RNS.LOG_DEBUG)
    
            except Exception as e:
                RNS.log("Error while unpacking received propagation resource", RNS.LOG_DEBUG)

    def lxmf_propagation(self, lxmf_data, signal_local_delivery=None, signal_duplicate=None, is_paper_message=False):
        no_stamp_enforcement = False
        if is_paper_message:
            no_stamp_enforcement = True

        try:
            if len(lxmf_data) >= LXMessage.LXMF_OVERHEAD:
                transient_id = RNS.Identity.full_hash(lxmf_data)

                if not transient_id in self.propagation_entries and not transient_id in self.locally_processed_transient_ids:
                    received = time.time()
                    propagation_entry = [transient_id, received, lxmf_data]
                    destination_hash  = lxmf_data[:LXMessage.DESTINATION_LENGTH]

                    self.locally_processed_transient_ids[transient_id] = received

                    if destination_hash in self.delivery_destinations:
                        delivery_destination = self.delivery_destinations[destination_hash]
                        encrypted_lxmf_data = lxmf_data[LXMessage.DESTINATION_LENGTH:]
                        decrypted_lxmf_data = delivery_destination.decrypt(encrypted_lxmf_data)
                        if decrypted_lxmf_data != None:
                            delivery_data = lxmf_data[:LXMessage.DESTINATION_LENGTH]+decrypted_lxmf_data
                            self.lxmf_delivery(delivery_data, delivery_destination.type, ratchet_id=delivery_destination.latest_ratchet_id, method=LXMessage.PROPAGATED, no_stamp_enforcement=no_stamp_enforcement)
                            self.locally_delivered_transient_ids[transient_id] = time.time()

                            if signal_local_delivery != None:
                                return signal_local_delivery

                    else:
                        if self.propagation_node:
                            file_path = self.messagepath+"/"+RNS.hexrep(transient_id, delimit=False)+"_"+str(received)
                            msg_file = open(file_path, "wb")
                            msg_file.write(lxmf_data)
                            msg_file.close()

                            self.propagation_entries[transient_id] = [destination_hash, file_path, time.time(), len(lxmf_data)]

                            RNS.log("Received propagated LXMF message "+RNS.prettyhexrep(transient_id)+", adding to peer distribution queues...", RNS.LOG_DEBUG)
                            for peer_id in self.peers:
                                peer = self.peers[peer_id]
                                peer.handle_message(transient_id)

                        else:
                            # TODO: Add message to sneakernet queues when implemented
                            RNS.log("Received propagated LXMF message "+RNS.prettyhexrep(transient_id)+", but this instance is not hosting a propagation node, discarding message.", RNS.LOG_DEBUG)

                    return True

                else:
                    if signal_duplicate != None:
                        return signal_duplicate

                    else:
                        return False

            return False

        except Exception as e:
            RNS.log("Could not assemble propagated LXMF message from received data", RNS.LOG_DEBUG)
            RNS.log("The contained exception was: "+str(e), RNS.LOG_DEBUG)
            return False

    def ingest_lxm_uri(self, uri, signal_local_delivery=None, signal_duplicate=None):
        try:
            if not uri.lower().startswith(LXMessage.URI_SCHEMA+"://"):
                RNS.log("Cannot ingest LXM, invalid URI provided.", RNS.LOG_ERROR)
                return False

            else:
                lxmf_data = base64.urlsafe_b64decode(uri.replace(LXMessage.URI_SCHEMA+"://", "").replace("/", "")+"==")
                transient_id = RNS.Identity.full_hash(lxmf_data)
                
                router_propagation_result = self.lxmf_propagation(lxmf_data, signal_local_delivery=signal_local_delivery, signal_duplicate=signal_duplicate, is_paper_message=True)
                if router_propagation_result != False:
                    RNS.log("LXM with transient ID "+RNS.prettyhexrep(transient_id)+" was ingested.", RNS.LOG_DEBUG)
                    return router_propagation_result
                else:
                    RNS.log("No valid LXM could be ingested from the provided URI", RNS.LOG_DEBUG)
                    return False

        except Exception as e:
            RNS.log("Error while decoding URI-encoded LXMF message. The contained exception was: "+str(e), RNS.LOG_ERROR)
            return False

    def fail_message(self, lxmessage):
        RNS.log(str(lxmessage)+" failed to send", RNS.LOG_DEBUG)

        if lxmessage in self.pending_outbound:
            self.pending_outbound.remove(lxmessage)

        self.failed_outbound.append(lxmessage)

        lxmessage.state = LXMessage.FAILED
        if lxmessage.failed_callback != None and callable(lxmessage.failed_callback):
            lxmessage.failed_callback(lxmessage)

    def process_deferred_stamps(self):
        if len(self.pending_deferred_stamps) > 0:

            if self.stamp_gen_lock.locked():
                return

            else:
                with self.stamp_gen_lock:
                    selected_lxm = None
                    selected_message_id = None
                    for message_id in self.pending_deferred_stamps:
                        lxmessage = self.pending_deferred_stamps[message_id]
                        if selected_lxm == None:
                            selected_lxm = lxmessage
                            selected_message_id = message_id

                    if selected_lxm != None:
                        RNS.log(f"Starting stamp generation for {selected_lxm}...", RNS.LOG_DEBUG)
                        generated_stamp = selected_lxm.get_stamp()
                        if generated_stamp:
                            selected_lxm.stamp = generated_stamp
                            selected_lxm.defer_stamp = False
                            selected_lxm.packed = None
                            selected_lxm.pack()
                            self.pending_deferred_stamps.pop(selected_message_id)
                            self.pending_outbound.append(selected_lxm)
                            RNS.log(f"Stamp generation completed for {selected_lxm}", RNS.LOG_DEBUG)
                        else:
                            RNS.log(f"Deferred stamp generation did not succeed. Failing {selected_lxm}.", RNS.LOG_ERROR)
                            selected_lxm.stamp_generation_failed = True
                            self.pending_deferred_stamps.pop(selected_message_id)
                            self.fail_message(selected_lxm)


    def process_outbound(self, sender = None):
        if self.processing_outbound:
            return

        for lxmessage in self.pending_outbound:
            if lxmessage.state == LXMessage.DELIVERED:
                RNS.log("Delivery has occurred for "+str(lxmessage)+", removing from outbound queue", RNS.LOG_DEBUG)
                self.pending_outbound.remove(lxmessage)

                # Udate ticket delivery stats
                if lxmessage.include_ticket and FIELD_TICKET in lxmessage.fields:
                    RNS.log(f"Updating latest ticket delivery for {RNS.prettyhexrep(lxmessage.destination_hash)}", RNS.LOG_DEBUG)
                    self.available_tickets["last_deliveries"][lxmessage.destination_hash] = time.time()
                    self.save_available_tickets()

                # Prepare link for backchannel communications
                delivery_destination_hash = lxmessage.get_destination().hash
                if lxmessage.method == LXMessage.DIRECT and delivery_destination_hash in self.direct_links:
                    direct_link = self.direct_links[delivery_destination_hash]
                    if not hasattr(direct_link, "backchannel_identified") or direct_link.backchannel_identified == False:
                        if direct_link.initiator == True:
                            source_destination_hash = lxmessage.get_source().hash
                            if source_destination_hash in self.delivery_destinations:
                                backchannel_identity = self.delivery_destinations[source_destination_hash].identity
                                backchannel_desthash = RNS.Destination.hash_from_name_and_identity("lxmf.delivery", backchannel_identity)
                                direct_link.identify(backchannel_identity)
                                direct_link.backchannel_identified = True
                                self.delivery_link_established(direct_link)
                                RNS.log(f"Performed backchannel identification as {RNS.prettyhexrep(backchannel_desthash)} on {direct_link}", RNS.LOG_DEBUG)

            elif lxmessage.method == LXMessage.PROPAGATED and lxmessage.state == LXMessage.SENT:
                RNS.log("Propagation has occurred for "+str(lxmessage)+", removing from outbound queue", RNS.LOG_DEBUG)
                self.pending_outbound.remove(lxmessage)

            else:
                RNS.log("Starting outbound processing for "+str(lxmessage)+" to "+RNS.prettyhexrep(lxmessage.get_destination().hash), RNS.LOG_DEBUG)

                if lxmessage.progress == None or lxmessage.progress < 0.01:
                    lxmessage.progress = 0.01

                # Outbound handling for opportunistic messages
                if lxmessage.method == LXMessage.OPPORTUNISTIC:
                    if lxmessage.delivery_attempts <= LXMRouter.MAX_DELIVERY_ATTEMPTS:
                        if lxmessage.delivery_attempts >= LXMRouter.MAX_PATHLESS_TRIES and not RNS.Transport.has_path(lxmessage.get_destination().hash):
                            RNS.log(f"Requesting path to {RNS.prettyhexrep(lxmessage.get_destination().hash)} after {lxmessage.delivery_attempts} pathless tries for {lxmessage}", RNS.LOG_DEBUG)
                            lxmessage.delivery_attempts += 1
                            RNS.Transport.request_path(lxmessage.get_destination().hash)
                            lxmessage.next_delivery_attempt = time.time() + LXMRouter.PATH_REQUEST_WAIT
                            lxmessage.progress = 0.00
                        elif lxmessage.delivery_attempts == LXMRouter.MAX_PATHLESS_TRIES+1 and RNS.Transport.has_path(lxmessage.get_destination().hash):
                            RNS.log(f"Opportunistic delivery for {lxmessage} still unsuccessful after {lxmessage.delivery_attempts} attempts, trying to rediscover path to {RNS.prettyhexrep(lxmessage.get_destination().hash)}", RNS.LOG_DEBUG)
                            lxmessage.delivery_attempts += 1
                            RNS.Reticulum.get_instance().drop_path(lxmessage.get_destination().hash)
                            def rediscover_job():
                                time.sleep(0.5)
                                RNS.Transport.request_path(lxmessage.get_destination().hash)
                            threading.Thread(target=rediscover_job, daemon=True).start()
                            lxmessage.next_delivery_attempt = time.time() + LXMRouter.PATH_REQUEST_WAIT
                            lxmessage.progress = 0.00
                        else:
                            if not hasattr(lxmessage, "next_delivery_attempt") or time.time() > lxmessage.next_delivery_attempt:
                                lxmessage.delivery_attempts += 1
                                lxmessage.next_delivery_attempt = time.time() + LXMRouter.DELIVERY_RETRY_WAIT
                                RNS.log("Opportunistic delivery attempt "+str(lxmessage.delivery_attempts)+" for "+str(lxmessage)+" to "+RNS.prettyhexrep(lxmessage.get_destination().hash), RNS.LOG_DEBUG)
                                lxmessage.send()
                    else:
                        RNS.log("Max delivery attempts reached for oppertunistic "+str(lxmessage)+" to "+RNS.prettyhexrep(lxmessage.get_destination().hash), RNS.LOG_DEBUG)
                        self.fail_message(lxmessage)

                # Outbound handling for messages transferred
                # over a direct link to the final recipient
                elif lxmessage.method == LXMessage.DIRECT:
                    if lxmessage.delivery_attempts <= LXMRouter.MAX_DELIVERY_ATTEMPTS:
                        delivery_destination_hash = lxmessage.get_destination().hash
                        direct_link = None
                        
                        if delivery_destination_hash in self.direct_links:
                            # An established direct link already exists to
                            # the destination, so we'll try to use it for
                            # delivering the message
                            direct_link = self.direct_links[delivery_destination_hash]
                            RNS.log(f"Using available direct link {direct_link} to {RNS.prettyhexrep(delivery_destination_hash)}", RNS.LOG_DEBUG)

                        elif delivery_destination_hash in self.backchannel_links:
                            # An established backchannel link exists to
                            # the destination, so we'll try to use it for
                            # delivering the message
                            direct_link = self.backchannel_links[delivery_destination_hash]
                            RNS.log(f"Using available backchannel link {direct_link} to {RNS.prettyhexrep(delivery_destination_hash)}", RNS.LOG_DEBUG)

                        if direct_link != None:
                            if direct_link.status == RNS.Link.ACTIVE:
                                if lxmessage.progress == None or lxmessage.progress < 0.05:
                                    lxmessage.progress = 0.05
                                if lxmessage.state != LXMessage.SENDING:
                                    RNS.log("Starting transfer of "+str(lxmessage)+" to "+RNS.prettyhexrep(lxmessage.get_destination().hash)+" on link "+str(direct_link), RNS.LOG_DEBUG)
                                    lxmessage.set_delivery_destination(direct_link)
                                    lxmessage.send()
                                else:
                                    if lxmessage.representation == LXMessage.RESOURCE:
                                        RNS.log("The transfer of "+str(lxmessage)+" is in progress ("+str(round(lxmessage.progress*100, 1))+"%)", RNS.LOG_DEBUG)
                                    else:
                                        RNS.log("Waiting for proof for "+str(lxmessage)+" sent as link packet", RNS.LOG_DEBUG)
                            elif direct_link.status == RNS.Link.CLOSED:
                                if direct_link.activated_at != None:
                                    RNS.log("The link to "+RNS.prettyhexrep(lxmessage.get_destination().hash)+" was closed", RNS.LOG_DEBUG)
                                else:
                                    if not hasattr(lxmessage, "path_request_retried"):
                                        RNS.log("The link to "+RNS.prettyhexrep(lxmessage.get_destination().hash)+" was never activated, retrying path request...", RNS.LOG_DEBUG)
                                        RNS.Transport.request_path(lxmessage.get_destination().hash)
                                        lxmessage.path_request_retried = True
                                    else:
                                        RNS.log("The link to "+RNS.prettyhexrep(lxmessage.get_destination().hash)+" was never activated", RNS.LOG_DEBUG)

                                    lxmessage.next_delivery_attempt = time.time() + LXMRouter.PATH_REQUEST_WAIT

                                lxmessage.set_delivery_destination(None)
                                if delivery_destination_hash in self.direct_links:
                                    self.direct_links.pop(delivery_destination_hash)
                                if delivery_destination_hash in self.backchannel_links:
                                    self.backchannel_links.pop(delivery_destination_hash)
                                lxmessage.next_delivery_attempt = time.time() + LXMRouter.DELIVERY_RETRY_WAIT
                            else:
                                # Simply wait for the link to become active or close
                                RNS.log("The link to "+RNS.prettyhexrep(lxmessage.get_destination().hash)+" is pending, waiting for link to become active", RNS.LOG_DEBUG)
                        else:
                            # No link exists, so we'll try to establish one, but
                            # only if we've never tried before, or the retry wait
                            # period has elapsed.
                            if not hasattr(lxmessage, "next_delivery_attempt") or time.time() > lxmessage.next_delivery_attempt:
                                lxmessage.delivery_attempts += 1
                                lxmessage.next_delivery_attempt = time.time() + LXMRouter.DELIVERY_RETRY_WAIT

                                if lxmessage.delivery_attempts < LXMRouter.MAX_DELIVERY_ATTEMPTS:
                                    if RNS.Transport.has_path(lxmessage.get_destination().hash):
                                        RNS.log("Establishing link to "+RNS.prettyhexrep(lxmessage.get_destination().hash)+" for delivery attempt "+str(lxmessage.delivery_attempts)+" to "+RNS.prettyhexrep(lxmessage.get_destination().hash), RNS.LOG_DEBUG)
                                        delivery_link = RNS.Link(lxmessage.get_destination())
                                        delivery_link.set_link_established_callback(self.process_outbound)
                                        self.direct_links[delivery_destination_hash] = delivery_link
                                        lxmessage.progress = 0.03
                                    else:
                                        RNS.log("No path known for delivery attempt "+str(lxmessage.delivery_attempts)+" to "+RNS.prettyhexrep(lxmessage.get_destination().hash)+". Requesting path...", RNS.LOG_DEBUG)
                                        RNS.Transport.request_path(lxmessage.get_destination().hash)
                                        lxmessage.next_delivery_attempt = time.time() + LXMRouter.PATH_REQUEST_WAIT
                                        lxmessage.progress = 0.00
                    else:
                        RNS.log("Max delivery attempts reached for direct "+str(lxmessage)+" to "+RNS.prettyhexrep(lxmessage.get_destination().hash), RNS.LOG_DEBUG)
                        self.fail_message(lxmessage)

                # Outbound handling for messages transported via
                # propagation to a LXMF router network.
                elif lxmessage.method == LXMessage.PROPAGATED:
                    RNS.log("Attempting propagated delivery for "+str(lxmessage)+" to "+RNS.prettyhexrep(lxmessage.get_destination().hash), RNS.LOG_DEBUG)

                    if self.outbound_propagation_node == None:
                        RNS.log("No outbound propagation node specified for propagated "+str(lxmessage)+" to "+RNS.prettyhexrep(lxmessage.get_destination().hash), RNS.LOG_ERROR)
                        self.fail_message(lxmessage)
                    else:
                        if lxmessage.delivery_attempts <= LXMRouter.MAX_DELIVERY_ATTEMPTS:

                            if self.outbound_propagation_link != None:
                                # A link already exists, so we'll try to use it
                                # to deliver the message
                                if self.outbound_propagation_link.status == RNS.Link.ACTIVE:
                                    if lxmessage.state != LXMessage.SENDING:
                                        RNS.log("Starting propagation transfer of "+str(lxmessage)+" to "+RNS.prettyhexrep(lxmessage.get_destination().hash)+" via "+RNS.prettyhexrep(self.outbound_propagation_node), RNS.LOG_DEBUG)
                                        lxmessage.set_delivery_destination(self.outbound_propagation_link)
                                        lxmessage.send()
                                    else:
                                        if lxmessage.representation == LXMessage.RESOURCE:
                                            RNS.log("The transfer of "+str(lxmessage)+" is in progress ("+str(round(lxmessage.progress*100, 1))+"%)", RNS.LOG_DEBUG)
                                        else:
                                            RNS.log("Waiting for proof for "+str(lxmessage)+" sent as link packet", RNS.LOG_DEBUG)
                                elif self.outbound_propagation_link.status == RNS.Link.CLOSED:
                                    RNS.log("The link to "+RNS.prettyhexrep(self.outbound_propagation_node)+" was closed", RNS.LOG_DEBUG)
                                    self.outbound_propagation_link = None
                                    lxmessage.next_delivery_attempt = time.time() + LXMRouter.DELIVERY_RETRY_WAIT
                                else:
                                    # Simply wait for the link to become
                                    # active or close
                                    RNS.log("The propagation link to "+RNS.prettyhexrep(self.outbound_propagation_node)+" is pending, waiting for link to become active", RNS.LOG_DEBUG)
                            else:
                                # No link exists, so we'll try to establish one, but
                                # only if we've never tried before, or the retry wait
                                # period has elapsed.
                                if not hasattr(lxmessage, "next_delivery_attempt") or time.time() > lxmessage.next_delivery_attempt:
                                    lxmessage.delivery_attempts += 1
                                    lxmessage.next_delivery_attempt = time.time() + LXMRouter.DELIVERY_RETRY_WAIT

                                    if lxmessage.delivery_attempts < LXMRouter.MAX_DELIVERY_ATTEMPTS:
                                        if RNS.Transport.has_path(self.outbound_propagation_node):
                                            RNS.log("Establishing link to "+RNS.prettyhexrep(self.outbound_propagation_node)+" for propagation attempt "+str(lxmessage.delivery_attempts)+" to "+RNS.prettyhexrep(lxmessage.get_destination().hash), RNS.LOG_DEBUG)
                                            propagation_node_identity = RNS.Identity.recall(self.outbound_propagation_node)
                                            propagation_node_destination = RNS.Destination(propagation_node_identity, RNS.Destination.OUT, RNS.Destination.SINGLE, APP_NAME, "propagation")
                                            self.outbound_propagation_link = RNS.Link(propagation_node_destination, established_callback=self.process_outbound)
                                        else:
                                            RNS.log("No path known for propagation attempt "+str(lxmessage.delivery_attempts)+" to "+RNS.prettyhexrep(self.outbound_propagation_node)+". Requesting path...", RNS.LOG_DEBUG)
                                            RNS.Transport.request_path(self.outbound_propagation_node)
                                            lxmessage.next_delivery_attempt = time.time() + LXMRouter.PATH_REQUEST_WAIT

                        else:
                            RNS.log("Max delivery attempts reached for propagated "+str(lxmessage)+" to "+RNS.prettyhexrep(lxmessage.get_destination().hash), RNS.LOG_DEBUG)
                            self.fail_message(lxmessage)
