import os
import time

import RNS
import RNS.vendor.umsgpack as msgpack

from collections import deque
from .LXMF import APP_NAME

class LXMPeer:
    OFFER_REQUEST_PATH = "/offer"
    MESSAGE_GET_PATH   = "/get"

    IDLE              = 0x00
    LINK_ESTABLISHING = 0x01
    LINK_READY        = 0x02
    REQUEST_SENT      = 0x03
    RESPONSE_RECEIVED = 0x04
    RESOURCE_TRANSFERRING = 0x05

    ERROR_NO_IDENTITY = 0xf0
    ERROR_NO_ACCESS   = 0xf1
    ERROR_TIMEOUT     = 0xfe

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

        if "link_establishment_rate" in dictionary:
            peer.link_establishment_rate = dictionary["link_establishment_rate"]
        else:
            peer.link_establishment_rate = 0
        
        if "sync_transfer_rate" in dictionary:
            peer.sync_transfer_rate = dictionary["sync_transfer_rate"]
        else:
            peer.sync_transfer_rate = 0

        if "propagation_transfer_limit" in dictionary:
            try:
                peer.propagation_transfer_limit = float(dictionary["propagation_transfer_limit"])
            except Exception as e:
                peer.propagation_transfer_limit = None
        else:
            peer.propagation_transfer_limit = None
        
        if "offered" in dictionary:
            peer.offered = dictionary["offered"]
        else:
            peer.offered = 0

        if "outgoing" in dictionary:
            peer.outgoing = dictionary["outgoing"]
        else:
            peer.outgoing = 0

        if "incoming" in dictionary:
            peer.incoming = dictionary["incoming"]
        else:
            peer.incoming = 0

        if "rx_bytes" in dictionary:
            peer.rx_bytes = dictionary["rx_bytes"]
        else:
            peer.rx_bytes = 0
        
        if "tx_bytes" in dictionary:
            peer.tx_bytes = dictionary["tx_bytes"]
        else:
            peer.tx_bytes = 0
        
        if "last_sync_attempt" in dictionary:
            peer.last_sync_attempt = dictionary["last_sync_attempt"]
        else:
            peer.last_sync_attempt = 0

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
        dictionary["last_heard"] = self.last_heard
        dictionary["destination_hash"] = self.destination_hash
        dictionary["link_establishment_rate"] = self.link_establishment_rate
        dictionary["sync_transfer_rate"] = self.sync_transfer_rate
        dictionary["propagation_transfer_limit"] = self.propagation_transfer_limit
        dictionary["last_sync_attempt"] = self.last_sync_attempt
        dictionary["offered"] = self.offered
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

    def __init__(self, router, destination_hash):
        self.alive = False
        self.last_heard = 0
        self.next_sync_attempt = 0
        self.last_sync_attempt = 0
        self.sync_backoff = 0
        self.peering_timebase = 0
        self.link_establishment_rate = 0
        self.sync_transfer_rate = 0
        self.propagation_transfer_limit = None
        self.handled_messages_queue = deque()
        self.unhandled_messages_queue = deque()

        self.offered  = 0   # Messages offered to this peer
        self.outgoing = 0   # Messages transferred to this peer
        self.incoming = 0   # Messages received from this peer
        self.rx_bytes = 0   # Bytes received from this peer
        self.tx_bytes = 0   # Bytes sent to this peer

        self._hm_count = 0
        self._um_count = 0
        self._hm_counts_synced = False
        self._um_counts_synced = False

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

    def sync(self):
        RNS.log("Initiating LXMF Propagation Node sync with peer "+RNS.prettyhexrep(self.destination_hash), RNS.LOG_DEBUG)
        self.last_sync_attempt = time.time()

        if time.time() > self.next_sync_attempt:
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
                    if len(self.unhandled_messages) > 0:
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

                                RNS.log("Synchronisation link to peer "+RNS.prettyhexrep(self.destination_hash)+" established, preparing request...", RNS.LOG_DEBUG)
                                unhandled_entries = []
                                unhandled_ids = []
                                purged_ids = []
                                for transient_id in self.unhandled_messages:
                                    if transient_id in self.router.propagation_entries:
                                        unhandled_entry = [
                                            transient_id,
                                            self.router.get_weight(transient_id),
                                            self.router.get_size(transient_id),
                                        ]
                                        unhandled_entries.append(unhandled_entry)
                                    else:
                                        purged_ids.append(transient_id)

                                for transient_id in purged_ids:
                                    RNS.log("Dropping unhandled message "+RNS.prettyhexrep(transient_id)+" for peer "+RNS.prettyhexrep(self.destination_hash)+" since it no longer exists in the message store.", RNS.LOG_DEBUG)
                                    self.remove_unhandled_message(transient_id)

                                unhandled_entries.sort(key=lambda e: e[1], reverse=False)
                                per_message_overhead = 16 # Really only 2 bytes, but set a bit higher for now
                                cumulative_size = 24 # Initialised to highest reasonable binary structure overhead
                                for unhandled_entry in unhandled_entries:
                                    transient_id = unhandled_entry[0]
                                    weight = unhandled_entry[1]
                                    lxm_size = unhandled_entry[2]
                                    next_size = cumulative_size + (lxm_size+per_message_overhead)
                                    if self.propagation_transfer_limit != None and next_size > (self.propagation_transfer_limit*1000):
                                        if lxm_size+per_message_overhead > (self.propagation_transfer_limit*1000):
                                            self.remove_unhandled_message(transient_id)
                                            self.add_handled_message(transient_id)
                                            RNS.log(f"Message {RNS.prettyhexrep(transient_id)} exceeds transfer limit for {self}, considering handled", RNS.LOG_DEBUG)
                                    else:
                                        cumulative_size += (lxm_size+per_message_overhead)
                                        unhandled_ids.append(transient_id)

                                RNS.log(f"Offering {len(unhandled_ids)} messages to peer {RNS.prettyhexrep(self.destination.hash)}", RNS.LOG_VERBOSE)
                                self.last_offer = unhandled_ids
                                self.link.request(LXMPeer.OFFER_REQUEST_PATH, unhandled_ids, response_callback=self.offer_response, failed_callback=self.request_failed)
                                self.state = LXMPeer.REQUEST_SENT

                else:
                    RNS.log("Could not request sync to peer "+RNS.prettyhexrep(self.destination_hash)+" since its identity could not be recalled.", RNS.LOG_ERROR)

        else:
            RNS.log("Postponing sync with peer "+RNS.prettyhexrep(self.destination_hash)+" for "+RNS.prettytime(self.next_sync_attempt-time.time())+" due to previous failures", RNS.LOG_DEBUG)
            if self.last_sync_attempt > self.last_heard:
                self.alive = False

    def request_failed(self, request_receipt):
        RNS.log("Sync request to peer "+str(self.destination)+" failed", RNS.LOG_DEBUG)
        if self.link != None:
            self.link.teardown()
        
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
                RNS.log("Peer wanted "+str(len(wanted_messages))+" of the available messages", RNS.LOG_VERBOSE)

                lxm_list = []
                for message_entry in wanted_messages:
                    file_path = message_entry[1]
                    if os.path.isfile(file_path):
                        file = open(file_path, "rb")
                        lxmf_data = file.read()
                        file.close()
                        lxm_list.append(lxmf_data)

                data = msgpack.packb([time.time(), lxm_list])
                resource = RNS.Resource(data, self.link, callback = self.resource_concluded)
                resource.transferred_messages = wanted_message_ids
                resource.sync_transfer_started = time.time()
                self.state = LXMPeer.RESOURCE_TRANSFERRING

            else:
                RNS.log("Peer "+RNS.prettyhexrep(self.destination_hash)+" did not request any of the available messages, sync completed", RNS.LOG_VERBOSE)
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
            for transient_id in resource.transferred_messages:
                self.add_handled_message(transient_id)
                self.remove_unhandled_message(transient_id)
            
            if self.link != None:
                self.link.teardown()

            self.link = None
            self.state = LXMPeer.IDLE

            rate_str = ""
            if hasattr(resource, "sync_transfer_started") and resource.sync_transfer_started:
                self.sync_transfer_rate = (resource.get_transfer_size()*8)/(time.time()-resource.sync_transfer_started)
                rate_str = f" at {RNS.prettyspeed(self.sync_transfer_rate)}"

            RNS.log(f"Syncing {len(resource.transferred_messages)} messages to peer {RNS.prettyhexrep(self.destination_hash)} completed{rate_str}", RNS.LOG_VERBOSE)
            self.alive = True
            self.last_heard = time.time()
            self.offered   += len(self.last_offer)
            self.outgoing  += len(resource.transferred_messages)
            self.tx_bytes  += resource.get_data_size()
        
        else:
            RNS.log("Resource transfer for LXMF peer sync failed to "+str(self.destination), RNS.LOG_VERBOSE)
            if self.link != None:
                self.link.teardown()

            self.link = None
            self.state = LXMPeer.IDLE

    def link_established(self, link):
        self.link.identify(self.router.identity)
        link_establishment_rate = link.get_establishment_rate()
        if link_establishment_rate != None:
            self.link_establishment_rate = link_establishment_rate

        self.state = LXMPeer.LINK_READY
        self.next_sync_attempt = 0
        self.sync()

    def link_closed(self, link):
        self.link = None
        self.state = LXMPeer.IDLE

    def queued_items(self):
        return len(self.handled_messages_queue) > 0 or len(self.unhandled_messages_queue) > 0

    def queue_unhandled_message(self, transient_id):
        self.unhandled_messages_queue.append(transient_id)

    def queue_handled_message(self, transient_id):
        self.handled_messages_queue.append(transient_id)

    def process_queues(self):
        if len(self.unhandled_messages_queue) > 0 or len(self.handled_messages_queue) > 0:
            # TODO: Remove debug
            # st = time.time(); lu = len(self.unhandled_messages_queue); lh = len(self.handled_messages_queue)
            
            handled_messages = self.handled_messages
            unhandled_messages = self.unhandled_messages

            while len(self.handled_messages_queue) > 0:
                transient_id = self.handled_messages_queue.pop()
                if not transient_id in handled_messages:
                    self.add_handled_message(transient_id)
                if transient_id in unhandled_messages:
                    self.remove_unhandled_message(transient_id)

            while len(self.unhandled_messages_queue) > 0:
                transient_id = self.unhandled_messages_queue.pop()
                if not transient_id in handled_messages and not transient_id in unhandled_messages:
                    self.add_unhandled_message(transient_id)

            del handled_messages, unhandled_messages
            # TODO: Remove debug
            # RNS.log(f"{self} processed {lh}/{lu} in {RNS.prettytime(time.time()-st)}")

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
        if not self._hm_counts_synced:
            self._update_counts()

        return self._hm_count

    @property
    def unhandled_message_count(self):
        if not self._um_counts_synced:
            self._update_counts()

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

    def __str__(self):
        if self.destination_hash:
            return RNS.prettyhexrep(self.destination_hash)
        else:
            return "<Unknown>"