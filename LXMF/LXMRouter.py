import os
import time
import random
import base64
import atexit
import threading

import RNS
import RNS.vendor.umsgpack as msgpack

from .LXMF import APP_NAME

from .LXMPeer import LXMPeer
from .LXMessage import LXMessage
from .Handlers import LXMFDeliveryAnnounceHandler
from .Handlers import LXMFPropagationAnnounceHandler

class LXMRouter:
    MAX_DELIVERY_ATTEMPTS = 5
    PROCESSING_INTERVAL   = 4
    DELIVERY_RETRY_WAIT   = 7
    PATH_REQUEST_WAIT     = 5
    LINK_MAX_INACTIVITY   = 10*60

    MESSAGE_EXPIRY        = 30*24*60*60

    NODE_ANNOUNCE_DELAY   = 20

    AUTOPEER              = True
    AUTOPEER_MAXDEPTH     = 4

    PR_PATH_TIMEOUT      = 10

    PR_IDLE              = 0x00
    PR_PATH_REQUESTED    = 0x01
    PR_LINK_ESTABLISHING = 0x02
    PR_LINK_ESTABLISHED  = 0x03
    PR_REQUEST_SENT      = 0x04
    PR_RECEIVING         = 0x05
    PR_RESPONSE_RECEIVED = 0x06
    PR_COMPLETE          = 0x07
    PR_NO_IDENTITY_RCVD  = 0xf0
    PR_NO_ACCESS         = 0xf1

    PR_ALL_MESSAGES      = 0x00


    ### Developer-facing API ##############################
    #######################################################

    def __init__(self, identity = None, storagepath = None, autopeer = AUTOPEER, autopeer_maxdepth = None):
        random.seed(os.urandom(10))

        self.pending_inbound       = []
        self.pending_outbound      = []
        self.failed_outbound       = []
        self.direct_links          = {}
        self.delivery_destinations = {}

        self.prioritised_list      = []
        self.ignored_list          = []
        self.allowed_list          = []
        self.auth_required         = False

        self.processing_outbound = False
        self.processing_inbound  = False
        self.processing_count = 0

        self.propagation_node = False

        if storagepath == None:
            raise ValueError("LXMF cannot be initialised without a storage path")
        else:
            self.storagepath = storagepath+"/lxmf"

        self.outbound_propagation_node = None
        self.outbound_propagation_link = None

        self.message_storage_limit = None
        self.information_storage_limit = None

        self.wants_download_on_path_available_from = None
        self.wants_download_on_path_available_to = None
        self.propagation_transfer_state = LXMRouter.PR_IDLE
        self.propagation_transfer_progress = 0.0
        self.propagation_transfer_last_result = None
        self.propagation_transfer_max_messages = None
        self.locally_delivered_transient_ids = {}
        self.locally_processed_transient_ids = {}

        if identity == None:
            identity = RNS.Identity()

        self.identity = identity
        self.lxmf_query_destination  = RNS.Destination(None, RNS.Destination.IN, RNS.Destination.PLAIN, APP_NAME, "query")
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

        atexit.register(self.exit_handler)

        job_thread = threading.Thread(target=self.jobloop)
        job_thread.setDaemon(True)
        job_thread.start()

    def announce(self, destination_hash):
        if destination_hash in self.delivery_destinations:
            delivery_destination = self.delivery_destinations[destination_hash]
            delivery_destination.announce(delivery_destination.display_name.encode("utf-8"))

    def announce_propagation_node(self):
        def delayed_announce():
            time.sleep(LXMRouter.NODE_ANNOUNCE_DELAY)
            data = msgpack.packb([self.propagation_node, int(time.time())])
            self.propagation_destination.announce(app_data=data)

        da_thread = threading.Thread(target=delayed_announce)
        da_thread.setDaemon(True)
        da_thread.start()

    def register_delivery_identity(self, identity, display_name = None):
        delivery_destination = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE, "lxmf", "delivery")
        delivery_destination.set_packet_callback(self.delivery_packet)
        delivery_destination.set_link_established_callback(self.delivery_link_established)
        delivery_destination.display_name = display_name

        if display_name != None:
            delivery_destination.set_default_app_data(display_name.encode("utf-8"))

        self.delivery_destinations[delivery_destination.hash] = delivery_destination
        return delivery_destination

    def register_delivery_callback(self, callback):
        self.__delivery_callback = callback

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

        self.propagation_transfer_max_messages = max_messages
        if self.outbound_propagation_node != None:
            self.propagation_transfer_progress = 0.0
            if self.outbound_propagation_link != None and self.outbound_propagation_link.status == RNS.Link.ACTIVE:
                self.propagation_transfer_state = LXMRouter.PR_LINK_ESTABLISHED
                self.outbound_propagation_link.identify(identity)
                self.outbound_propagation_link.request(
                    LXMPeer.MESSAGE_GET_PATH,
                    [None, None],
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
                    # TODO: Remove at some point
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
                            RNS.log("Loaded peer "+RNS.prettyhexrep(peer.destination_hash)+" with "+str(len(peer.unhandled_messages))+" unhandled messages", RNS.LOG_DEBUG)
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


    ### Utility & Maintenance #############################
    #######################################################

    JOB_OUTBOUND_INTERVAL  = 1
    JOB_LINKS_INTERVAL     = 1
    JOB_TRANSIENT_INTERVAL = 60
    JOB_STORE_INTERVAL     = 120
    JOB_PEERSYNC_INTERVAL  = 12
    def jobs(self):
        self.processing_count += 1

        if self.processing_count % LXMRouter.JOB_OUTBOUND_INTERVAL == 0:
            self.process_outbound()

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
            self.jobs()
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

        if self.outbound_propagation_link != None and self.outbound_propagation_link.status == RNS.Link.CLOSED:
            self.outbound_propagation_link = None
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

                    now = time.time()
                    weighted_entries = []
                    for transient_id in self.propagation_entries:
                        entry = self.propagation_entries[transient_id]

                        dst_hash = entry[0]
                        lxm_rcvd = entry[2]
                        lxm_size = entry[3]
                        age_weight = max(1, (now - lxm_rcvd)/60/60/24/4)
                        if dst_hash in self.prioritised_list:
                            priority_weight = 0.1
                        else:
                            priority_weight = 1.0
                        
                        weight = priority_weight * age_weight * lxm_size
                        weighted_entries.append([entry, weight, transient_id])

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

                    RNS.log("LXMF message store size is now "+RNS.prettysize(self.message_storage_size()), RNS.LOG_EXTREME)
                    RNS.log("PE len "+str(len(self.propagation_entries)))


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
            RNS.log("Could not save locally processed message ID cache to storage. The contained exception was: "+str(e), RNS.LOG_ERROR)

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
        while not RNS.Transport.has_path(self.wants_download_on_path_available_from) and time.time() < self.wants_download_on_path_available_timeout:
            time.sleep(0.1)

        if RNS.Transport.has_path(self.wants_download_on_path_available_from):
            self.request_messages_from_propagation_node(self.wants_download_on_path_available_to, self.propagation_transfer_max_messages)
        else:
            RNS.log("Propagation node path request timed out", RNS.LOG_DEBUG)
            self.acknowledge_sync_completion()
    
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
                        for transient_id in data[0]:
                            if transient_id in self.propagation_entries and self.propagation_entries[transient_id][0] == remote_destination.hash:
                                try:
                                    filepath = self.propagation_entries[transient_id][1]
                                    RNS.log("Client "+RNS.prettyhexrep(remote_destination.hash)+" requested message "+RNS.prettyhexrep(transient_id)+" at "+str(filepath), RNS.LOG_DEBUG)

                                    message_file = open(filepath, "rb")
                                    lxmf_data = message_file.read()
                                    response_messages.append(lxmf_data)
                                    message_file.close()

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
                        if self.has_message(transient_id):
                            haves.append(transient_id)
                        else:
                            if self.propagation_transfer_max_messages == LXMRouter.PR_ALL_MESSAGES or len(wants) < self.propagation_transfer_max_messages:
                                wants.append(transient_id)

                    request_receipt.link.request(
                        LXMPeer.MESSAGE_GET_PATH,
                        [wants, haves],
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

    def acknowledge_sync_completion(self, reset_state=False):
        if reset_state or self.propagation_transfer_state <= LXMRouter.PR_COMPLETE:
            self.propagation_transfer_state = LXMRouter.PR_IDLE

        self.propagation_transfer_progress = 0.0
        self.propagation_transfer_last_result = None
        self.wants_download_on_path_available_from = None
        self.wants_download_on_path_available_to = None

    def has_message(self, transient_id):
        if transient_id in self.locally_delivered_transient_ids:
            return True
        else:
            return False


    ### Message Routing & Delivery ########################
    #######################################################
    
    def handle_outbound(self, lxmessage):
        lxmessage.state = LXMessage.OUTBOUND
        if not lxmessage.packed:
            lxmessage.pack()

        lxmessage.determine_transport_encryption()

        while self.processing_outbound:
            time.sleep(0.1)

        self.pending_outbound.append(lxmessage)
        self.process_outbound()

    def lxmf_delivery(self, lxmf_data, destination_type = None):
        try:
            message = LXMessage.unpack_from_bytes(lxmf_data)

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

            if self.__delivery_callback != None and callable(self.__delivery_callback):
                try:
                    self.__delivery_callback(message)
                except Exception as e:
                    RNS.log("An error occurred in the external delivery callback for "+str(message), RNS.LOG_ERROR)

            return True

        except Exception as e:
            RNS.log("Could not assemble LXMF message from received data", RNS.LOG_NOTICE)
            RNS.log("The contained exception was: "+str(e), RNS.LOG_DEBUG)
            return False

    def delivery_packet(self, data, packet):
        try:
            if packet.destination_type != RNS.Destination.LINK:
                lxmf_data  = b""
                lxmf_data += packet.destination.hash
                lxmf_data += data
            else:
                lxmf_data = data

            if self.lxmf_delivery(lxmf_data, packet.destination_type):
                packet.prove()

        except Exception as e:
            RNS.log("Exception occurred while parsing incoming LXMF data.", RNS.LOG_ERROR)
            RNS.log("The contained exception was: "+str(e), RNS.LOG_ERROR)

    def delivery_link_established(self, link):
        link.set_packet_callback(self.delivery_packet)
        link.set_resource_strategy(RNS.Link.ACCEPT_ALL)
        link.set_resource_started_callback(self.resource_transfer_began)
        link.set_resource_concluded_callback(self.delivery_resource_concluded)

    def delivery_link_closed(self, link):
        pass

    def resource_transfer_began(self, resource):
        RNS.log("Transfer began for LXMF delivery resource "+str(resource), RNS.LOG_DEBUG)

    def delivery_resource_concluded(self, resource):
        RNS.log("Transfer concluded for LXMF delivery resource "+str(resource), RNS.LOG_DEBUG)
        if resource.status == RNS.Resource.COMPLETE:
            self.lxmf_delivery(resource.data.read(), resource.link.type)


    ### Peer Sync & Propagation ###########################
    #######################################################

    def peer(self, destination_hash, timestamp):
        if destination_hash in self.peers:
            peer = self.peers[destination_hash]
            if timestamp > peer.peering_timebase:
                peer.alive = True
                peer.sync_backoff = 0
                peer.next_sync_attempt = 0

            peer.peering_timebase = timestamp
            peer.last_heard = time.time()
        else:
            peer = LXMPeer(self, destination_hash)
            peer.alive = True
            peer.last_heard = time.time()
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
            RNS.log("Randomly selecting peer to sync from "+str(len(waiting_peers))+" waiting peers.", RNS.LOG_DEBUG)
            peer_pool = waiting_peers
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
        link.set_resource_strategy(RNS.Link.ACCEPT_ALL)
        link.set_resource_started_callback(self.resource_transfer_began)
        link.set_resource_concluded_callback(self.propagation_resource_concluded)

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

    def offer_request(self, path, data, request_id, remote_identity, requested_at):
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
            # have the transient id added to it's list of
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

    def lxmf_propagation(self, lxmf_data, signal_local_delivery=None, signal_duplicate=None):
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
                        delivery_data = lxmf_data[:LXMessage.DESTINATION_LENGTH]+decrypted_lxmf_data
                        self.lxmf_delivery(delivery_data, delivery_destination.type)
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
                
                router_propagation_result = self.lxmf_propagation(lxmf_data, signal_local_delivery=signal_local_delivery, signal_duplicate=signal_duplicate)
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

        self.pending_outbound.remove(lxmessage)
        self.failed_outbound.append(lxmessage)

        lxmessage.state = LXMessage.FAILED
        if lxmessage.failed_callback != None and callable(lxmessage.failed_callback):
            lxmessage.failed_callback(lxmessage)

    def process_outbound(self, sender = None):
        if self.processing_outbound:
            return

        for lxmessage in self.pending_outbound:
            if lxmessage.state == LXMessage.DELIVERED:
                RNS.log("Delivery has occurred for "+str(lxmessage)+", removing from outbound queue", RNS.LOG_DEBUG)
                self.pending_outbound.remove(lxmessage)
            elif lxmessage.state == LXMessage.SENT:
                RNS.log("Propagation has occurred for "+str(lxmessage)+", removing from outbound queue", RNS.LOG_DEBUG)
                self.pending_outbound.remove(lxmessage)
            else:
                RNS.log("Starting outbound processing for "+str(lxmessage)+" to "+RNS.prettyhexrep(lxmessage.get_destination().hash), RNS.LOG_DEBUG)
                # Outbound handling for opportunistic messages
                if lxmessage.method == LXMessage.OPPORTUNISTIC:                
                    if lxmessage.delivery_attempts <= LXMRouter.MAX_DELIVERY_ATTEMPTS:
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

                        if delivery_destination_hash in self.direct_links:
                            # A link already exists, so we'll try to use it
                            # to deliver the message
                            direct_link = self.direct_links[delivery_destination_hash]
                            if direct_link.status == RNS.Link.ACTIVE:
                                if lxmessage.state != LXMessage.SENDING:
                                    RNS.log("Starting transfer of "+str(lxmessage)+" to "+RNS.prettyhexrep(lxmessage.get_destination().hash), RNS.LOG_DEBUG)
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
                                self.direct_links.pop(delivery_destination_hash)
                                lxmessage.next_delivery_attempt = time.time() + LXMRouter.DELIVERY_RETRY_WAIT
                            else:
                                # Simply wait for the link to become
                                # active or close
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
                                    else:
                                        RNS.log("No path known for delivery attempt "+str(lxmessage.delivery_attempts)+" to "+RNS.prettyhexrep(lxmessage.get_destination().hash)+". Requesting path...", RNS.LOG_DEBUG)
                                        RNS.Transport.request_path(lxmessage.get_destination().hash)
                                        lxmessage.next_delivery_attempt = time.time() + LXMRouter.PATH_REQUEST_WAIT
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
                                    RNS.log("The propagation link to "+RNS.prettyhexrep(self.outbound_propagation_node)+" is pending, waiting for link to become active: "+str(self.outbound_propagation_link.status), RNS.LOG_DEBUG)
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
