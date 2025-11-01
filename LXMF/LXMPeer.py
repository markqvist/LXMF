import os
import time
import threading

import RNS
import RNS.vendor.umsgpack as msgpack
import LXMF.LXStamper as LXStamper

from collections import deque
from .LXMF import APP_NAME
from .LXMF import PN_META_NAME

class LXMPeer:
    OFFER_REQUEST_PATH = "/offer"
    MESSAGE_GET_PATH   = "/get"

    IDLE                  = 0x00
    LINK_ESTABLISHING     = 0x01
    LINK_READY            = 0x02
    REQUEST_SENT          = 0x03
    RESPONSE_RECEIVED     = 0x04
    RESOURCE_TRANSFERRING = 0x05

    ERROR_NO_IDENTITY     = 0xf0
    ERROR_NO_ACCESS       = 0xf1
    ERROR_INVALID_KEY     = 0xf3
    ERROR_INVALID_DATA    = 0xf4
    ERROR_INVALID_STAMP   = 0xf5
    ERROR_THROTTLED       = 0xf6
    ERROR_NOT_FOUND       = 0xfd
    ERROR_TIMEOUT         = 0xfe

    STRATEGY_LAZY         = 0x01
    STRATEGY_PERSISTENT   = 0x02
    DEFAULT_SYNC_STRATEGY = STRATEGY_PERSISTENT

    # Maximum amount of time a peer can
    # be unreachable before it is removed
    MAX_UNREACHABLE   = 14*24*60*60

    # Everytime consecutive time a sync
    # link fails to establish, add this
    # amount off time to wait before the
    # next sync is attempted.
    SYNC_BACKOFF_STEP = 12*60

    # How long to wait for an answer to
    # peer path requests before deferring
    # sync to later.
    PATH_REQUEST_GRACE = 7.5

    @staticmethod
    def from_bytes(peer_bytes, router):
        dictionary = msgpack.unpackb(peer_bytes)
        peer_destination_hash = dictionary["destination_hash"]
        peer_peering_timebase = dictionary["peering_timebase"]
        peer_alive = dictionary["alive"]
        peer_last_heard = dictionary["last_heard"]

        peer = LXMPeer(router, peer_destination_hash)
        peer.peering_timebase = peer_peering_timebase
        peer.alive = peer_alive
        peer.last_heard = peer_last_heard

        if "link_establishment_rate" in dictionary: peer.link_establishment_rate = dictionary["link_establishment_rate"]
        else: peer.link_establishment_rate = 0
        
        if "sync_transfer_rate" in dictionary: peer.sync_transfer_rate = dictionary["sync_transfer_rate"]
        else:                                  peer.sync_transfer_rate = 0

        if "propagation_transfer_limit" in dictionary:
            try:                   peer.propagation_transfer_limit = float(dictionary["propagation_transfer_limit"])
            except Exception as e: peer.propagation_transfer_limit = None
        else:                      peer.propagation_transfer_limit = None

        if "propagation_sync_limit" in dictionary:
            try:    peer.propagation_sync_limit = int(dictionary["propagation_sync_limit"])
            except: peer.propagation_sync_limit = peer.propagation_transfer_limit
        else:       peer.propagation_sync_limit = peer.propagation_transfer_limit

        if "propagation_stamp_cost" in dictionary:
            try:    peer.propagation_stamp_cost = int(dictionary["propagation_stamp_cost"])
            except: peer.propagation_stamp_cost = None
        else:       peer.propagation_stamp_cost = None

        if "propagation_stamp_cost_flexibility" in dictionary:
            try:    peer.propagation_stamp_cost_flexibility = int(dictionary["propagation_stamp_cost_flexibility"])
            except: peer.propagation_stamp_cost_flexibility = None
        else:       peer.propagation_stamp_cost_flexibility = None

        if "peering_cost" in dictionary:
            try:    peer.peering_cost = int(dictionary["peering_cost"])
            except: peer.peering_cost = None
        else:       peer.peering_cost = None

        if "sync_strategy" in dictionary:
            try: peer.sync_strategy = int(dictionary["sync_strategy"])
            except: peer.sync_strategy = LXMPeer.DEFAULT_SYNC_STRATEGY
        else: peer.sync_strategy = LXMPeer.DEFAULT_SYNC_STRATEGY
        
        if "offered"  in dictionary:          peer.offered = dictionary["offered"]
        else:                                 peer.offered = 0
        if "outgoing" in dictionary:          peer.outgoing = dictionary["outgoing"]
        else:                                 peer.outgoing = 0
        if "incoming" in dictionary:          peer.incoming = dictionary["incoming"]
        else:                                 peer.incoming = 0
        if "rx_bytes" in dictionary:          peer.rx_bytes = dictionary["rx_bytes"]
        else:                                 peer.rx_bytes = 0
        if "tx_bytes" in dictionary:          peer.tx_bytes = dictionary["tx_bytes"]
        else:                                 peer.tx_bytes = 0
        if "last_sync_attempt" in dictionary: peer.last_sync_attempt = dictionary["last_sync_attempt"]
        else:                                 peer.last_sync_attempt = 0
        if "peering_key" in dictionary:       peer.peering_key = dictionary["peering_key"]
        else:                                 peer.peering_key = None
        if "metadata" in dictionary:          peer.metadata = dictionary["metadata"]
        else:                                 peer.metadata = None

        hm_count = 0
        for transient_id in dictionary["handled_ids"]:
            if transient_id in router.propagation_entries:
                peer.add_handled_message(transient_id)
                hm_count += 1

        um_count = 0
        for transient_id in dictionary["unhandled_ids"]:
            if transient_id in router.propagation_entries:
                peer.add_unhandled_message(transient_id)
                um_count += 1

        peer._hm_count = hm_count
        peer._um_count = um_count
        peer._hm_counts_synced = True
        peer._um_counts_synced = True

        del dictionary
        return peer

    def to_bytes(self):
        dictionary = {}
        dictionary["peering_timebase"] = self.peering_timebase
        dictionary["alive"] = self.alive
        dictionary["metadata"] = self.metadata
        dictionary["last_heard"] = self.last_heard
        dictionary["sync_strategy"] = self.sync_strategy
        dictionary["peering_key"] = self.peering_key
        dictionary["destination_hash"] = self.destination_hash
        dictionary["link_establishment_rate"] = self.link_establishment_rate
        dictionary["sync_transfer_rate"] = self.sync_transfer_rate
        dictionary["propagation_transfer_limit"] = self.propagation_transfer_limit
        dictionary["propagation_sync_limit"] = self.propagation_sync_limit
        dictionary["propagation_stamp_cost"] = self.propagation_stamp_cost
        dictionary["propagation_stamp_cost_flexibility"] = self.propagation_stamp_cost_flexibility
        dictionary["peering_cost"] = self.peering_cost
        dictionary["last_sync_attempt"] = self.last_sync_attempt
        dictionary["offered"]  = self.offered
        dictionary["outgoing"] = self.outgoing
        dictionary["incoming"] = self.incoming
        dictionary["rx_bytes"] = self.rx_bytes
        dictionary["tx_bytes"] = self.tx_bytes

        handled_ids = []
        for transient_id in self.handled_messages:
            handled_ids.append(transient_id)

        unhandled_ids = []
        for transient_id in self.unhandled_messages:
            unhandled_ids.append(transient_id)

        dictionary["handled_ids"] = handled_ids
        dictionary["unhandled_ids"] = unhandled_ids

        peer_bytes = msgpack.packb(dictionary)
        del dictionary

        return peer_bytes

    def __init__(self, router, destination_hash, sync_strategy=DEFAULT_SYNC_STRATEGY):
        self.alive         = False
        self.last_heard    = 0
        self.sync_strategy = sync_strategy
        self.peering_key   = None
        self.peering_cost  = None
        self.metadata      = None

        self.next_sync_attempt       = 0
        self.last_sync_attempt       = 0
        self.sync_backoff            = 0
        self.peering_timebase        = 0
        self.link_establishment_rate = 0
        self.sync_transfer_rate      = 0

        self.propagation_transfer_limit         = None
        self.propagation_sync_limit             = None
        self.propagation_stamp_cost             = None
        self.propagation_stamp_cost_flexibility = None
        self.currently_transferring_messages    = None
        self.handled_messages_queue             = deque()
        self.unhandled_messages_queue           = deque()

        self.offered   = 0   # Messages offered to this peer
        self.outgoing  = 0   # Messages transferred to this peer
        self.incoming  = 0   # Messages received from this peer
        self.rx_bytes  = 0   # Bytes received from this peer
        self.tx_bytes  = 0   # Bytes sent to this peer

        self._hm_count = 0
        self._um_count = 0
        self._hm_counts_synced = False
        self._um_counts_synced = False

        self._peering_key_lock = threading.Lock()

        self.link = None
        self.state = LXMPeer.IDLE

        self.last_offer = []
        
        self.router = router
        self.destination_hash = destination_hash
        self.identity = RNS.Identity.recall(destination_hash)
        if self.identity != None:
            self.destination = RNS.Destination(self.identity, RNS.Destination.OUT, RNS.Destination.SINGLE, APP_NAME, "propagation")
        else:
            self.destination = None
            RNS.log(f"Could not recall identity for LXMF propagation peer {RNS.prettyhexrep(self.destination_hash)}, will retry identity resolution on next sync", RNS.LOG_WARNING)

    def peering_key_ready(self):
        if not self.peering_cost: return False
        if type(self.peering_key) == list and len(self.peering_key) == 2:
            value = self.peering_key[1]
            if value >= self.peering_cost: return True
            else:
                RNS.log(f"Peering key value mismatch for {self}. Current value is {value}, but peer requires {self.peering_cost}. Scheduling regeneration...", RNS.LOG_WARNING)
                self.peering_key = None

        return False

    def peering_key_value(self):
        if type(self.peering_key) == list and len(self.peering_key) == 2: return self.peering_key[1]
        else: return None

    def generate_peering_key(self):
        if self.peering_cost == None: return False
        with self._peering_key_lock:
            if self.peering_key != None: return True
            else:
                RNS.log(f"Generating peering key for {self}", RNS.LOG_NOTICE)
                if self.router.identity == None:
                    RNS.log(f"Could not update peering key for {self} since the local LXMF router identity is not configured", RNS.LOG_ERROR)
                    return False

                if self.identity == None:
                    self.identity = RNS.Identity.recall(destination_hash)
                    if self.identity == None:
                        RNS.log(f"Could not update peering key for {self} since its identity could not be recalled", RNS.LOG_ERROR)
                        return False

                key_material        = self.identity.hash+self.router.identity.hash
                peering_key, value  = LXStamper.generate_stamp(key_material, self.peering_cost, expand_rounds=LXStamper.WORKBLOCK_EXPAND_ROUNDS_PEERING)
                if value >= self.peering_cost:
                    self.peering_key = [peering_key, value]
                    RNS.log(f"Peering key successfully generated for {self}", RNS.LOG_NOTICE)
                    return True

        return False

    def sync(self):
        RNS.log("Initiating LXMF Propagation Node sync with peer "+RNS.prettyhexrep(self.destination_hash), RNS.LOG_DEBUG)
        self.last_sync_attempt = time.time()

        sync_time_reached = time.time() > self.next_sync_attempt
        stamp_costs_known = self.propagation_stamp_cost != None and self.propagation_stamp_cost_flexibility != None and self.peering_cost != None
        peering_key_ready = self.peering_key_ready()
        sync_checks = sync_time_reached and stamp_costs_known and peering_key_ready

        if not sync_checks:
            try:
                if not sync_time_reached:
                    postpone_reason = " due to previous failures"
                    if self.last_sync_attempt > self.last_heard: self.alive = False
                elif not stamp_costs_known:
                    postpone_reason = " since its required stamp costs are not yet known"
                elif not peering_key_ready:
                    postpone_reason = " since a peering key has not been generated yet"
                    def job(): self.generate_peering_key()
                    threading.Thread(target=job, daemon=True).start()

                delay = self.next_sync_attempt-time.time()
                postpone_delay =  f" for {RNS.prettytime(delay)}" if delay > 0 else ""
                RNS.log(f"Postponing sync with peer {RNS.prettyhexrep(self.destination_hash)}{postpone_delay}{postpone_reason}", RNS.LOG_DEBUG)
            except Exception as e:
                RNS.trace_exception(e)

        else:
            if not RNS.Transport.has_path(self.destination_hash):
                RNS.log("No path to peer "+RNS.prettyhexrep(self.destination_hash)+" exists, requesting...", RNS.LOG_DEBUG)
                RNS.Transport.request_path(self.destination_hash)
                time.sleep(LXMPeer.PATH_REQUEST_GRACE)

            if not RNS.Transport.has_path(self.destination_hash):
                RNS.log("Path request was not answered, retrying sync with peer "+RNS.prettyhexrep(self.destination_hash)+" later", RNS.LOG_DEBUG)
            
            else:
                if self.identity == None:
                    self.identity = RNS.Identity.recall(destination_hash)
                    if self.identity != None:
                        self.destination = RNS.Destination(self.identity, RNS.Destination.OUT, RNS.Destination.SINGLE, APP_NAME, "propagation")

                if self.destination != None:
                    if len(self.unhandled_messages) == 0:
                        RNS.log(f"Sync requested for {self}, but no unhandled messages exist for peer. Sync complete.", RNS.LOG_DEBUG)
                        return

                    if len(self.unhandled_messages) > 0:
                        if self.currently_transferring_messages != None:
                            RNS.log(f"Sync requested for {self}, but current message transfer index was not clear. Aborting.", RNS.LOG_ERROR)
                            return

                        if self.state == LXMPeer.IDLE:
                            RNS.log("Establishing link for sync to peer "+RNS.prettyhexrep(self.destination_hash)+"...", RNS.LOG_DEBUG)
                            self.sync_backoff += LXMPeer.SYNC_BACKOFF_STEP
                            self.next_sync_attempt = time.time() + self.sync_backoff
                            self.link = RNS.Link(self.destination, established_callback = self.link_established, closed_callback = self.link_closed)
                            self.state = LXMPeer.LINK_ESTABLISHING

                        else:
                            if self.state == LXMPeer.LINK_READY:
                                self.alive = True
                                self.last_heard = time.time()
                                self.sync_backoff = 0
                                min_accepted_cost = min(0, self.propagation_stamp_cost-self.propagation_stamp_cost_flexibility)

                                RNS.log("Synchronisation link to peer "+RNS.prettyhexrep(self.destination_hash)+" established, preparing sync offer...", RNS.LOG_DEBUG)
                                unhandled_entries = []
                                unhandled_ids     = []
                                purged_ids        = []
                                low_value_ids     = []
                                for transient_id in self.unhandled_messages:
                                    if transient_id in self.router.propagation_entries:
                                        if self.router.get_stamp_value(transient_id) < min_accepted_cost: low_value_ids.append(transient_id)
                                        else:
                                            unhandled_entry = [ transient_id,
                                                                self.router.get_weight(transient_id),
                                                                self.router.get_size(transient_id) ]
                                            
                                            unhandled_entries.append(unhandled_entry)
                                    
                                    else: purged_ids.append(transient_id)

                                for transient_id in purged_ids:
                                    RNS.log(f"Dropping unhandled message {RNS.prettyhexrep(transient_id)} for peer {RNS.prettyhexrep(self.destination_hash)} since it no longer exists in the message store.", RNS.LOG_DEBUG)
                                    self.remove_unhandled_message(transient_id)

                                for transient_id in low_value_ids:
                                    RNS.log(f"Dropping unhandled message {RNS.prettyhexrep(transient_id)} for peer {RNS.prettyhexrep(self.destination_hash)} since its stamp value is lower than peer requirement of {min_accepted_cost}.", RNS.LOG_DEBUG)
                                    self.remove_unhandled_message(transient_id)

                                unhandled_entries.sort(key=lambda e: e[1], reverse=False)
                                per_message_overhead  = 16 # Really only 2 bytes, but set a bit higher for now
                                cumulative_size       = 24 # Initialised to highest reasonable binary structure overhead
                                RNS.log(f"Syncing to peer with per-message limit {RNS.prettysize(self.propagation_transfer_limit*1000)} and sync limit {RNS.prettysize(self.propagation_sync_limit*1000)}")  # TODO: Remove debug

                                for unhandled_entry in unhandled_entries:
                                    transient_id      = unhandled_entry[0]
                                    weight            = unhandled_entry[1]
                                    lxm_size          = unhandled_entry[2]
                                    lxm_transfer_size = lxm_size+per_message_overhead
                                    next_size         = cumulative_size + lxm_transfer_size

                                    if self.propagation_transfer_limit != None and lxm_transfer_size > (self.propagation_transfer_limit*1000):
                                        self.remove_unhandled_message(transient_id)
                                        self.add_handled_message(transient_id)
                                        continue

                                    if self.propagation_sync_limit != None and next_size >= (self.propagation_sync_limit*1000):
                                        continue

                                    cumulative_size += lxm_transfer_size
                                    unhandled_ids.append(transient_id)

                                offer = [self.peering_key[0], unhandled_ids]

                                RNS.log(f"Offering {len(unhandled_ids)} messages to peer {RNS.prettyhexrep(self.destination.hash)} ({RNS.prettysize(len(msgpack.packb(unhandled_ids)))})", RNS.LOG_VERBOSE)
                                self.last_offer = unhandled_ids
                                self.link.request(LXMPeer.OFFER_REQUEST_PATH, offer, response_callback=self.offer_response, failed_callback=self.request_failed)
                                self.state = LXMPeer.REQUEST_SENT

                else:
                    RNS.log(f"Could not request sync to peer {RNS.prettyhexrep(self.destination_hash)} since its identity could not be recalled.", RNS.LOG_ERROR)

    def request_failed(self, request_receipt):
        RNS.log(f"Sync request to peer {self.destination} failed", RNS.LOG_DEBUG)
        if self.link != None: self.link.teardown()
        self.state = LXMPeer.IDLE

    def offer_response(self, request_receipt):
        try:
            self.state = LXMPeer.RESPONSE_RECEIVED
            response = request_receipt.response

            wanted_messages = []
            wanted_message_ids = []

            if response == LXMPeer.ERROR_NO_IDENTITY:
                if self.link != None:
                    RNS.log("Remote peer indicated that no identification was received, retrying...", RNS.LOG_VERBOSE)
                    self.link.identify()
                    self.state = LXMPeer.LINK_READY
                    self.sync()
                    return

            elif response == LXMPeer.ERROR_NO_ACCESS:
                RNS.log("Remote indicated that access was denied, breaking peering", RNS.LOG_VERBOSE)
                self.router.unpeer(self.destination_hash)
                return

            elif response == LXMPeer.ERROR_THROTTLED:
                throttle_time = self.router.PN_STAMP_THROTTLE
                RNS.log(f"Remote indicated that we're throttled, postponing sync for {RNS.prettytime(throttle_time)}", RNS.LOG_VERBOSE)
                self.next_sync_attempt = time.time()+throttle_time
                return

            elif response == False:
                # Peer already has all advertised messages
                for transient_id in self.last_offer:
                    if transient_id in self.unhandled_messages:
                        self.add_handled_message(transient_id)
                        self.remove_unhandled_message(transient_id)
                    

            elif response == True:
                # Peer wants all advertised messages
                for transient_id in self.last_offer:
                    wanted_messages.append(self.router.propagation_entries[transient_id])
                    wanted_message_ids.append(transient_id)

            else:
                # Peer wants some advertised messages
                for transient_id in self.last_offer.copy():
                    # If the peer did not want the message, it has
                    # already received it from another peer.
                    if not transient_id in response:
                        self.add_handled_message(transient_id)
                        self.remove_unhandled_message(transient_id)

                for transient_id in response:
                    wanted_messages.append(self.router.propagation_entries[transient_id])
                    wanted_message_ids.append(transient_id)

            if len(wanted_messages) > 0:
                RNS.log(f"Peer {RNS.prettyhexrep(self.destination_hash)} wanted {str(len(wanted_messages))} of the available messages", RNS.LOG_VERBOSE)

                lxm_list = []
                for message_entry in wanted_messages:
                    file_path = message_entry[1]
                    if os.path.isfile(file_path):
                        file = open(file_path, "rb")
                        lxmf_data = file.read()
                        file.close()
                        lxm_list.append(lxmf_data)

                data = msgpack.packb([time.time(), lxm_list])
                RNS.log(f"Total transfer size for this sync is {RNS.prettysize(len(data))}", RNS.LOG_VERBOSE)
                resource = RNS.Resource(data, self.link, callback = self.resource_concluded)
                self.currently_transferring_messages = wanted_message_ids
                self.current_sync_transfer_started = time.time()
                self.state = LXMPeer.RESOURCE_TRANSFERRING

            else:
                RNS.log(f"Peer {RNS.prettyhexrep(self.destination_hash)} did not request any of the available messages, sync completed", RNS.LOG_VERBOSE)
                self.offered += len(self.last_offer)
                if self.link != None:
                    self.link.teardown()

                self.link = None
                self.state = LXMPeer.IDLE

        except Exception as e:
            RNS.log("Error while handling offer response from peer "+str(self.destination), RNS.LOG_ERROR)
            RNS.log("The contained exception was: "+str(e), RNS.LOG_ERROR)

            if self.link != None:
                self.link.teardown()

            self.link = None
            self.state = LXMPeer.IDLE

    def resource_concluded(self, resource):
        if resource.status == RNS.Resource.COMPLETE:
            if self.currently_transferring_messages == None:
                RNS.log(f"Sync transfer completed on {self}, but transferred message index was unavailable. Aborting.", RNS.LOG_ERROR)
                if self.link != None: self.link.teardown()
                self.link  = None
                self.state = LXMPeer.IDLE

            for transient_id in self.currently_transferring_messages:
                self.add_handled_message(transient_id)
                self.remove_unhandled_message(transient_id)
            
            if self.link != None: self.link.teardown()
            self.link     = None
            self.state    = LXMPeer.IDLE

            rate_str = ""
            if self.current_sync_transfer_started != None:
                self.sync_transfer_rate = (resource.get_transfer_size()*8)/(time.time()-self.current_sync_transfer_started)
                rate_str = f" at {RNS.prettyspeed(self.sync_transfer_rate)}"

            RNS.log(f"Syncing {len(self.currently_transferring_messages)} messages to peer {RNS.prettyhexrep(self.destination_hash)} completed{rate_str}", RNS.LOG_VERBOSE)
            self.alive      = True
            self.last_heard = time.time()
            self.offered   += len(self.last_offer)
            self.outgoing  += len(self.currently_transferring_messages)
            self.tx_bytes  += resource.get_data_size()

            self.currently_transferring_messages = None
            self.current_sync_transfer_started   = None

            if self.sync_strategy == self.STRATEGY_PERSISTENT:
                if self.unhandled_message_count > 0: self.sync()
        
        else:
            RNS.log("Resource transfer for LXMF peer sync failed to "+str(self.destination), RNS.LOG_VERBOSE)
            if self.link != None: self.link.teardown()
            self.link     = None
            self.state    = LXMPeer.IDLE
            self.currently_transferring_messages = None
            self.current_sync_transfer_started   = None

    def link_established(self, link):
        self.link.identify(self.router.identity)
        link_establishment_rate = link.get_establishment_rate()
        if link_establishment_rate != None:
            self.link_establishment_rate = link_establishment_rate

        self.state = LXMPeer.LINK_READY
        self.next_sync_attempt = 0
        self.sync()

    def link_closed(self, link):
        self.link  = None
        self.state = LXMPeer.IDLE

    def queued_items(self):
        return len(self.handled_messages_queue) > 0 or len(self.unhandled_messages_queue) > 0

    def queue_unhandled_message(self, transient_id):
        self.unhandled_messages_queue.append(transient_id)

    def queue_handled_message(self, transient_id):
        self.handled_messages_queue.append(transient_id)

    def process_queues(self):
        if len(self.unhandled_messages_queue) > 0 or len(self.handled_messages_queue) > 0:            
            handled_messages = self.handled_messages
            unhandled_messages = self.unhandled_messages

            while len(self.handled_messages_queue) > 0:
                transient_id = self.handled_messages_queue.pop()
                if not transient_id in handled_messages: self.add_handled_message(transient_id)
                if transient_id in unhandled_messages:   self.remove_unhandled_message(transient_id)

            while len(self.unhandled_messages_queue) > 0:
                transient_id = self.unhandled_messages_queue.pop()
                if not transient_id in handled_messages and not transient_id in unhandled_messages:
                    self.add_unhandled_message(transient_id)

            del handled_messages, unhandled_messages

    @property
    def handled_messages(self):
        pes = self.router.propagation_entries.copy()
        hm = list(filter(lambda tid: self.destination_hash in pes[tid][4], pes))
        self._hm_count = len(hm); del pes
        self._hm_counts_synced = True
        return hm

    @property
    def unhandled_messages(self):
        pes = self.router.propagation_entries.copy()
        um = list(filter(lambda tid: self.destination_hash in pes[tid][5], pes))
        self._um_count = len(um); del pes
        self._um_counts_synced = True
        return um

    @property
    def handled_message_count(self):
        if not self._hm_counts_synced: self._update_counts()
        return self._hm_count

    @property
    def unhandled_message_count(self):
        if not self._um_counts_synced: self._update_counts()
        return self._um_count

    @property
    def acceptance_rate(self):
        return 0 if self.offered == 0 else (self.outgoing/self.offered)

    def _update_counts(self):
        if not self._hm_counts_synced:
            hm = self.handled_messages; del hm

        if not self._um_counts_synced:
            um = self.unhandled_messages; del um

    def add_handled_message(self, transient_id):
        if transient_id in self.router.propagation_entries:
            if not self.destination_hash in self.router.propagation_entries[transient_id][4]:
                self.router.propagation_entries[transient_id][4].append(self.destination_hash)
                self._hm_counts_synced = False

    def add_unhandled_message(self, transient_id):
        if transient_id in self.router.propagation_entries:
            if not self.destination_hash in self.router.propagation_entries[transient_id][5]:
                self.router.propagation_entries[transient_id][5].append(self.destination_hash)
                self._um_count += 1

    def remove_handled_message(self, transient_id):
        if transient_id in self.router.propagation_entries:
            if self.destination_hash in self.router.propagation_entries[transient_id][4]:
                self.router.propagation_entries[transient_id][4].remove(self.destination_hash)
                self._hm_counts_synced = False

    def remove_unhandled_message(self, transient_id):
        if transient_id in self.router.propagation_entries:
            if self.destination_hash in self.router.propagation_entries[transient_id][5]:
                self.router.propagation_entries[transient_id][5].remove(self.destination_hash)
                self._um_counts_synced = False

    @property
    def name(self):
        if type(self.metadata) != dict: return None
        else:
            if not PN_META_NAME in self.metadata: return None
            else:
                try: return self.metadata[PN_META_NAME].decode("utf-8")
                except: return None
    
    def __str__(self):
        if self.destination_hash: return RNS.prettyhexrep(self.destination_hash)
        else: return "<Unknown>"