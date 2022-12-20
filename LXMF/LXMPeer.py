import os
import time

import RNS
import RNS.vendor.umsgpack as msgpack

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

    # Maximum amount of time a peer can
    # be unreachable before it is removed
    MAX_UNREACHABLE   = 4*24*60*60

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

        peer = LXMPeer(router, dictionary["destination_hash"])
        peer.peering_timebase = dictionary["peering_timebase"]
        peer.alive = dictionary["alive"]
        peer.last_heard = dictionary["last_heard"]

        for transient_id in dictionary["handled_ids"]:
            if transient_id in router.propagation_entries:
                peer.handled_messages[transient_id] = router.propagation_entries[transient_id]

        for transient_id in dictionary["unhandled_ids"]:
            if transient_id in router.propagation_entries:
                peer.unhandled_messages[transient_id] = router.propagation_entries[transient_id]

        return peer

    def to_bytes(self):
        dictionary = {}
        dictionary["peering_timebase"] = self.peering_timebase
        dictionary["alive"] = self.alive
        dictionary["last_heard"] = self.last_heard
        dictionary["destination_hash"] = self.destination_hash

        handled_ids = []
        for transient_id in self.handled_messages:
            handled_ids.append(transient_id)

        unhandled_ids = []
        for transient_id in self.unhandled_messages:
            unhandled_ids.append(transient_id)

        dictionary["handled_ids"] = handled_ids
        dictionary["unhandled_ids"] = unhandled_ids

        return msgpack.packb(dictionary)

    def __init__(self, router, destination_hash):
        self.alive = False
        self.last_heard = 0
        self.next_sync_attempt = 0
        self.last_sync_attempt = 0
        self.sync_backoff = 0
        self.peering_timebase = 0

        self.link = None
        self.state = LXMPeer.IDLE

        self.unhandled_messages = {}
        self.handled_messages = {}
        
        self.router = router
        self.destination_hash = destination_hash
        self.identity = RNS.Identity.recall(destination_hash)
        self.destination = RNS.Destination(self.identity, RNS.Destination.OUT, RNS.Destination.SINGLE, APP_NAME, "propagation")

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
                    self.destination = RNS.Destination(self.identity, RNS.Destination.OUT, RNS.Destination.SINGLE, APP_NAME, "propagation")

                if self.identity != None:
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
                                unhandled_ids = []
                                purged_ids = []
                                for transient_id in self.unhandled_messages:
                                    if transient_id in self.router.propagation_entries:
                                        unhandled_ids.append(transient_id)
                                    else:
                                        purged_ids.append(transient_id)

                                for transient_id in purged_ids:
                                    RNS.log("Dropping unhandled message "+RNS.prettyhexrep(transient_id)+" for peer "+RNS.prettyhexrep(self.destination_hash)+" since it no longer exists in the message store.", RNS.LOG_DEBUG)
                                    self.unhandled_messages.pop(transient_id)

                                RNS.log("Sending sync request to peer "+str(self.destination), RNS.LOG_DEBUG)
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
        else:
            self.state = LXMPeer.IDLE

    def offer_response(self, request_receipt):
        try:
            self.state = LXMPeer.RESPONSE_RECEIVED
            response = request_receipt.response

            wanted_messages = []
            wanted_message_ids = []

            if response == LXMPeer.ERROR_NO_IDENTITY:
                if self.link != None:
                    RNS.log("Remote peer indicated that no identification was received, retrying...", RNS.LOG_DEBUG)
                    self.link.indentify()
                    self.state = LXMPeer.LINK_READY
                    self.sync()

            elif response == False:
                # Peer already has all advertised messages
                for transient_id in self.unhandled_messages:
                    message_entry = self.unhandled_messages[transient_id]
                    self.handled_messages[transient_id] = message_entry

                self.unhandled_messages = {}

            elif response == True:
                # Peer wants all advertised messages
                for transient_id in self.unhandled_messages:
                    wanted_messages.append(self.unhandled_messages[transient_id])
                    wanted_message_ids.append(transient_id)

            else:
                # Peer wants some advertised messages
                peer_had_messages = []
                for transient_id in self.unhandled_messages.copy():
                    # If the peer did not want the message, it has
                    # already received it from another peer.
                    if not transient_id in response:
                        message_entry = self.unhandled_messages.pop(transient_id)
                        self.handled_messages[transient_id] = message_entry

                for transient_id in response:
                    wanted_messages.append(self.unhandled_messages[transient_id])
                    wanted_message_ids.append(transient_id)

            if len(wanted_messages) > 0:
                RNS.log("Peer wanted "+str(len(wanted_messages))+" of the available messages", RNS.LOG_DEBUG)

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
                self.state = LXMPeer.RESOURCE_TRANSFERRING
            else:
                RNS.log("Peer "+RNS.prettyhexrep(self.destination_hash)+" did not request any of the available messages, sync completed", RNS.LOG_DEBUG)
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
                message = self.unhandled_messages.pop(transient_id)
                self.handled_messages[transient_id] = message
            self.state = LXMPeer.IDLE
            self.link.teardown()
            RNS.log("Sync to peer "+RNS.prettyhexrep(self.destination_hash)+" completed", RNS.LOG_DEBUG)
            self.alive = True
            self.last_heard = time.time()
        else:
            RNS.log("Resource transfer for LXMF peer sync failed to "+str(self.destination), RNS.LOG_DEBUG)
            if self.link != None:
                self.link.teardown()
            else:
                self.state = LXMPeer.IDLE



    def link_established(self, link):
        self.link.identify(self.router.identity)
        self.state = LXMPeer.LINK_READY
        self.next_sync_attempt = 0
        self.sync()

    def link_closed(self, link):
        self.link = None
        self.state = LXMPeer.IDLE

    def handle_message(self, transient_id):
        if not transient_id in self.handled_messages and not transient_id in self.unhandled_messages:
            # TODO: Remove at some point
            RNS.log("The message "+RNS.prettyhexrep(transient_id)+" was added to distribution queue for "+RNS.prettyhexrep(self.destination_hash), RNS.LOG_EXTREME)
            self.unhandled_messages[transient_id] = self.router.propagation_entries[transient_id]

    def __str__(self):
        if self.destination_hash:
            return RNS.prettyhexrep(self.destination_hash)
        else:
            return "<Unknown>"