import os
import math
import time
import random
import atexit
import threading
import RNS
import RNS.vendor.umsgpack as msgpack

APP_NAME = "lxmf"

class LXMessage:
    DRAFT              = 0x00
    OUTBOUND           = 0x01
    SENDING            = 0x02
    SENT               = 0x04
    DELIVERED          = 0x08
    FAILED             = 0xFF
    states             = [DRAFT, OUTBOUND, SENDING, SENT, DELIVERED, FAILED]

    UNKNOWN            = 0x00
    PACKET             = 0x01
    RESOURCE           = 0x02
    representations    = [UNKNOWN, PACKET, RESOURCE]

    OPPORTUNISTIC      = 0x01
    DIRECT             = 0x02
    PROPAGATED         = 0x03
    valid_methods      = [OPPORTUNISTIC, DIRECT, PROPAGATED]

    SOURCE_UNKNOWN     = 0x01
    SIGNATURE_INVALID  = 0x02
    unverified_reasons = [SOURCE_UNKNOWN, SIGNATURE_INVALID]

    DESTINATION_LENGTH = RNS.Identity.TRUNCATED_HASHLENGTH//8
    SIGNATURE_LENGTH   = RNS.Identity.SIGLENGTH//8

    # LXMF overhead is 99 bytes per message:
    #   10  bytes for destination hash
    #   10  bytes for source hash
    #   64  bytes for Ed25519 signature
    #   8   bytes for timestamp
    #   7   bytes for msgpack structure
    LXMF_OVERHEAD  = 2*DESTINATION_LENGTH + SIGNATURE_LENGTH + 8 + 7

    # With an MTU of 500, the maximum amount of data
    # we can send in a single encrypted packet is
    # 383 bytes.
    ENCRYPTED_PACKET_MDU = RNS.Packet.ENCRYPTED_MDU
    
    # The max content length we can fit in LXMF message
    # inside a single RNS packet is the encrypted MDU, minus
    # the LXMF overhead. We can optimise a bit though, by
    # inferring the destination hash from the destination
    # field of the packet, therefore we also add the length
    # of a destination hash to the calculation. With default
    # RNS and LXMF parameters, the largest single-packet
    # LXMF message we can send is 294 bytes. If a message
    # is larger than that, a Reticulum link will be used.
    ENCRYPTED_PACKET_MAX_CONTENT = ENCRYPTED_PACKET_MDU - LXMF_OVERHEAD + DESTINATION_LENGTH
    
    # Links can carry a larger MDU, due to less overhead per
    # packet. The link MDU with default Reticulum parameters
    # is 431 bytes.
    LINK_PACKET_MDU = RNS.Link.MDU

    # Which means that we can deliver single-packet LXMF
    # messages with content of up to 332 bytes over a link.
    # If a message is larger than that, LXMF will sequence
    # and transfer it as a RNS resource over the link instead.
    LINK_PACKET_MAX_CONTENT = LINK_PACKET_MDU - LXMF_OVERHEAD

    # For plain packets without encryption, we can
    # fit up to 388 bytes of content.
    PLAIN_PACKET_MDU = RNS.Packet.PLAIN_MDU
    PLAIN_PACKET_MAX_CONTENT = PLAIN_PACKET_MDU - LXMF_OVERHEAD + DESTINATION_LENGTH

    # Descriptive strings regarding transport encryption
    ENCRYPTION_DESCRIPTION_AES = "AES-128"
    ENCRYPTION_DESCRIPTION_EC  = "Curve25519"
    ENCRYPTION_DESCRIPTION_UNENCRYPTED = "Unencrypted"

    def __str__(self):
        if self.hash != None:
            return "<LXMessage "+RNS.hexrep(self.hash, delimit=False)+">"
        else:
            return "<LXMessage>"

    def __init__(self, destination, source, content = "", title = "", fields = None, desired_method = None, destination_hash = None, source_hash = None):
        if isinstance(destination, RNS.Destination) or destination == None:
            self.__destination    = destination
            if destination != None:
                self.destination_hash = destination.hash
            else:
                self.destination_hash = destination_hash
        else:
            raise ValueError("LXMessage initialised with invalid destination")

        if isinstance(source, RNS.Destination) or source == None:
            self.__source    = source
            if source != None:
                self.source_hash = source.hash
            else:
                self.source_hash = source_hash
        else:
            raise ValueError("LXMessage initialised with invalid source")

        self.set_title_from_string(title)
        self.set_content_from_string(content)

        self.set_fields(fields)

        self.payload      = None
        self.timestamp    = None
        self.signature    = None
        self.hash         = None
        self.packed       = None
        self.progress     = None
        self.state        = LXMessage.DRAFT
        self.method       = LXMessage.UNKNOWN

        self.incoming                = False
        self.signature_validated     = False
        self.unverified_reason       = None

        self.representation          = LXMessage.UNKNOWN
        self.desired_method          = desired_method
        self.delivery_attempts       = 0
        self.transport_encrypted     = False
        self.transport_encryption    = None
        self.packet_representation   = None
        self.resource_representation = None
        self.__delivery_destination  = None
        self.__delivery_callback     = None
        self.failed_callback       = None

    def set_title_from_string(self, title_string):
        self.title = title_string.encode("utf-8")

    def set_title_from_bytes(self, title_bytes):
        self.title = title_bytes

    def title_as_string(self):
        return self.title.decode("utf-8")

    def set_content_from_string(self, content_string):
        self.content = content_string.encode("utf-8")

    def set_content_from_bytes(self, content_bytes):
        self.content = content_bytes

    def content_as_string(self):
        return self.content.decode("utf-8")

    def set_fields(self, fields):
        if isinstance(fields, dict) or fields == None:
            self.fields = fields
        else:
            raise ValueError("LXMessage property \"fields\" can only be dict or None")

    def get_fields(self):
        return self.__fields

    def set_destination(self, destination):
        if self.destination == None:
            if isinstance(destination, RNS.Destination):
                self.__destination = destination
            else:
                raise ValueError("Invalid destination set on LXMessage")
        else:
            raise ValueError("Cannot reassign destination on LXMessage")

    def get_destination(self):
        return self.__destination

    def set_source(self, source):
        if self.source == None:
            if isinstance(source, RNS.Destination):
                self.__source = source
            else:
                raise ValueError("Invalid source set on LXMessage")
        else:
            raise ValueError("Cannot reassign source on LXMessage")

    def get_source(self):
        return self.__source

    def set_delivery_destination(self, delivery_destination):
        self.__delivery_destination = delivery_destination

    def register_delivery_callback(self, callback):
        self.__delivery_callback = callback

    def register_failed_callback(self, callback):
        self.failed_callback = callback

    def pack(self):
        if not self.packed:
            if self.timestamp == None:
                self.timestamp = time.time()

            self.propagation_packed = None

            self.payload = [self.timestamp, self.title, self.content, self.fields]

            hashed_part      = b""
            hashed_part     += self.__destination.hash
            hashed_part     += self.__source.hash
            hashed_part     += msgpack.packb(self.payload)
            self.hash        = RNS.Identity.full_hash(hashed_part)
            self.message_id  = self.hash
            
            signed_part      = b""
            signed_part     += hashed_part
            signed_part     += self.hash
            self.signature   = self.__source.sign(signed_part)
            self.signature_validated = True

            self.packed      = b""
            self.packed     += self.__destination.hash
            self.packed     += self.__source.hash
            self.packed     += self.signature
            packed_payload   = msgpack.packb(self.payload)
            self.packed     += packed_payload
            self.packed_size = len(self.packed)
            content_size     = len(packed_payload)

            # If no desired delivery method has been defined,
            # one will be chosen according to these rules:
            if self.desired_method == None:
                self.desired_method == LXMessage.DIRECT
            # TODO: Expand rules to something more intelligent

            if self.desired_method == LXMessage.OPPORTUNISTIC:
                if self.__destination.type == RNS.Destination.SINGLE:
                    single_packet_content_limit = LXMessage.ENCRYPTED_PACKET_MAX_CONTENT
                elif self.__destination.type == RNS.Destination.PLAIN:
                    single_packet_content_limit = LXMessage.PLAIN_PACKET_MAX_CONTENT

                if content_size > single_packet_content_limit:
                    raise TypeError("LXMessage desired opportunistic delivery method, but content exceeds single-packet size.")
                else:
                    self.method = LXMessage.OPPORTUNISTIC
                    self.representation = LXMessage.PACKET
                    self.__delivery_destination = self.__destination

            elif self.desired_method == LXMessage.DIRECT:
                single_packet_content_limit = LXMessage.LINK_PACKET_MAX_CONTENT
                if content_size <= single_packet_content_limit:
                    self.method = self.desired_method
                    self.representation = LXMessage.PACKET
                else:
                    self.method = self.desired_method
                    self.representation = LXMessage.RESOURCE

            elif self.desired_method == LXMessage.PROPAGATED:
                single_packet_content_limit = LXMessage.LINK_PACKET_MAX_CONTENT

                encrypted_data = self.__destination.encrypt(self.packed[LXMessage.DESTINATION_LENGTH:])
                self.propagation_packed = msgpack.packb([time.time(), [self.packed[:LXMessage.DESTINATION_LENGTH]+encrypted_data]])

                content_size = len(self.propagation_packed)
                if content_size <= single_packet_content_limit:
                    self.method = self.desired_method
                    self.representation = LXMessage.PACKET
                else:
                    self.method = self.desired_method
                    self.representation = LXMessage.RESOURCE

        else:
            raise ValueError("Attempt to re-pack LXMessage "+str(self)+" that was already packed")

    def send(self):
        self.determine_transport_encryption()

        if self.method == LXMessage.OPPORTUNISTIC:
            self.__as_packet().send().set_delivery_callback(self.__mark_delivered)
            self.state = LXMessage.SENT
        
        elif self.method == LXMessage.DIRECT:
            self.state = LXMessage.SENDING

            if self.representation == LXMessage.PACKET:
                receipt = self.__as_packet().send()
                receipt.set_delivery_callback(self.__mark_delivered)
                receipt.set_timeout_callback(self.__link_packet_timed_out)

            elif self.representation == LXMessage.RESOURCE:
                self.resource_representation = self.__as_resource()

        elif self.method == LXMessage.PROPAGATED:
            self.state = LXMessage.SENDING

            if self.representation == LXMessage.PACKET:
                receipt = self.__as_packet().send()
                if receipt:
                    receipt.set_delivery_callback(self.__mark_propagated)
                    receipt.set_timeout_callback(self.__link_packet_timed_out)
                else:
                    self.__delivery_destination.teardown()

            elif self.representation == LXMessage.RESOURCE:
                self.resource_representation = self.__as_resource()


    def determine_transport_encryption(self):
        if self.method == LXMessage.OPPORTUNISTIC:
            if self.__destination.type == RNS.Destination.SINGLE:
                self.transport_encrypted = True
                self.transport_encryption = LXMessage.ENCRYPTION_DESCRIPTION_EC
            elif destination_type == RNS.Destination.GROUP:
                self.transport_encrypted = True
                self.transport_encryption = LXMessage.ENCRYPTION_DESCRIPTION_AES
            else:
                self.transport_encrypted = False
                self.transport_encryption = LXMessage.ENCRYPTION_DESCRIPTION_UNENCRYPTED
        elif self.method == LXMessage.DIRECT:
            self.transport_encrypted = True
            self.transport_encryption = LXMessage.ENCRYPTION_DESCRIPTION_EC
        elif self.method == LXMessage.PROPAGATED:
            if self.__destination.type == RNS.Destination.SINGLE:
                self.transport_encrypted = True
                self.transport_encryption = LXMessage.ENCRYPTION_DESCRIPTION_EC
            elif self.__destination.type == RNS.Destination.GROUP:
                self.transport_encrypted = True
                self.transport_encryption = LXMessage.ENCRYPTION_DESCRIPTION_AES
            else:
                self.transport_encrypted = False
                self.transport_encryption = LXMessage.ENCRYPTION_DESCRIPTION_UNENCRYPTED
        else:
            self.transport_encrypted = False
            self.transport_encryption = LXMessage.ENCRYPTION_DESCRIPTION_UNENCRYPTED

    def __mark_delivered(self, receipt = None):
        RNS.log("Received delivery notification for "+str(self), RNS.LOG_DEBUG)
        self.state = LXMessage.DELIVERED

        if self.__delivery_callback != None:
            self.__delivery_callback(self)

    def __mark_propagated(self, receipt = None):
        RNS.log("Received propagation success notification for "+str(self), RNS.LOG_DEBUG)
        self.state = LXMessage.SENT

        if self.__delivery_callback != None:
            self.__delivery_callback(self)

    def __resource_concluded(self, resource):
        if resource.status == RNS.Resource.COMPLETE:
            self.__mark_delivered()
        else:
            resource.link.teardown()
            self.state = LXMessage.OUTBOUND

    def __propagation_resource_concluded(self, resource):
        if resource.status == RNS.Resource.COMPLETE:
            self.__mark_propagated()
        else:
            resource.link.teardown()
            self.state = LXMessage.OUTBOUND

    def __link_packet_timed_out(self, packet_receipt):
        if packet_receipt:
            packet_receipt.destination.teardown()
    
        self.state = LXMessage.OUTBOUND


    def __update_transfer_progress(self, resource):
        self.progress = resource.get_progress()

    def __as_packet(self):
        if not self.packed:
            self.pack()

        if not self.__delivery_destination:
            raise ValueError("Can't synthesize packet for LXMF message before delivery destination is known")

        if self.method == LXMessage.OPPORTUNISTIC:
            return RNS.Packet(self.__delivery_destination, self.packed[LXMessage.DESTINATION_LENGTH:])
        elif self.method == LXMessage.DIRECT:
            return RNS.Packet(self.__delivery_destination, self.packed)
        elif self.method == LXMessage.PROPAGATED:
            return RNS.Packet(self.__delivery_destination, self.propagation_packed)

    def __as_resource(self):
        if not self.packed:
            self.pack()

        if not self.__delivery_destination:
            raise ValueError("Can't synthesize resource for LXMF message before delivery destination is known")

        if not self.__delivery_destination.type == RNS.Destination.LINK:
            raise TypeError("Tried to synthesize resource for LXMF message on a delivery destination that was not a link")

        if not self.__delivery_destination.status == RNS.Link.ACTIVE:
            raise ConnectionError("Tried to synthesize resource for LXMF message on a link that was not active")

        self.progress = 0.0

        if self.method == LXMessage.DIRECT:
            return RNS.Resource(self.packed, self.__delivery_destination, callback = self.__resource_concluded, progress_callback = self.__update_transfer_progress)
        elif self.method == LXMessage.PROPAGATED:
            return RNS.Resource(self.propagation_packed, self.__delivery_destination, callback = self.__propagation_resource_concluded, progress_callback = self.__update_transfer_progress)
        else:
            return None

    def write_to_directory(self, directory_path):
        file_name = RNS.hexrep(self.hash, delimit=False)
        file_path = directory_path+"/"+file_name

        try:
            if not self.packed:
                self.pack()

            container = {
                "state": self.state,
                "lxmf_bytes": self.packed,
                "transport_encrypted": self.transport_encrypted,
                "transport_encryption": self.transport_encryption,
                "method": self.method
            }

            packed_container = msgpack.packb(container)

            file = open(file_path, "wb")
            file.write(packed_container)
            file.close()

            return file_path

        except Exception as e:
            RNS.log("Error while writing LXMF message to file \""+str(file_path)+"\". The contained exception was: "+str(e), RNS.LOG_ERROR)
            return None


    @staticmethod
    def unpack_from_bytes(lxmf_bytes):
        destination_hash     = lxmf_bytes[:LXMessage.DESTINATION_LENGTH]
        source_hash          = lxmf_bytes[LXMessage.DESTINATION_LENGTH:2*LXMessage.DESTINATION_LENGTH]
        signature            = lxmf_bytes[2*LXMessage.DESTINATION_LENGTH:2*LXMessage.DESTINATION_LENGTH+LXMessage.SIGNATURE_LENGTH]
        packed_payload       = lxmf_bytes[2*LXMessage.DESTINATION_LENGTH+LXMessage.SIGNATURE_LENGTH:]
        hashed_part          = b"" + destination_hash + source_hash + packed_payload
        message_hash         = RNS.Identity.full_hash(hashed_part)
        signed_part          = b"" + hashed_part + message_hash
        unpacked_payload     = msgpack.unpackb(packed_payload)
        timestamp            = unpacked_payload[0]
        title_bytes          = unpacked_payload[1]
        content_bytes        = unpacked_payload[2]
        fields               = unpacked_payload[3]

        destination_identity = RNS.Identity.recall(destination_hash)
        if destination_identity != None:
            destination = RNS.Destination(destination_identity, RNS.Destination.OUT, RNS.Destination.SINGLE, APP_NAME, "delivery")
        else:
            destination = None
        
        source_identity = RNS.Identity.recall(source_hash)
        if source_identity != None:
            source = RNS.Destination(source_identity, RNS.Destination.OUT, RNS.Destination.SINGLE, APP_NAME, "delivery")
        else:
            source = None

        message = LXMessage(
            destination = destination,
            source = source,
            content = "",
            title = "",
            fields = fields,
            destination_hash = destination_hash,
            source_hash = source_hash)

        message.hash        = message_hash
        message.signature   = signature
        message.incoming    = True
        message.timestamp   = timestamp
        message.packed      = lxmf_bytes
        message.packed_size = len(lxmf_bytes)
        message.set_title_from_bytes(title_bytes)
        message.set_content_from_bytes(content_bytes)

        try:
            if source:
                if source.identity.validate(signature, signed_part):
                    message.signature_validated = True
                else:
                    message.signature_validated = False
                    message.unverified_reason = LXMessage.SIGNATURE_INVALID
            else:
                signature_validated = False
                message.unverified_reason = LXMessage.SOURCE_UNKNOWN
                RNS.log("Unpacked LXMF message signature could not be validated, since source identity is unknown", RNS.LOG_DEBUG)
        except Exception as e:
            message.signature_validated = False
            RNS.log("Error while validating LXMF message signature. The contained exception was: "+str(e), RNS.LOG_ERROR)

        return message
        
    @staticmethod
    def unpack_from_file(lxmf_file_handle):
        try:
            container = msgpack.unpackb(lxmf_file_handle.read())
            lxm = LXMessage.unpack_from_bytes(container["lxmf_bytes"])

            if "state" in container:
                lxm.state = container["state"]
            if "transport_encrypted" in container:
                lxm.transport_encrypted = container["transport_encrypted"]
            if "transport_encryption" in container:
                lxm.transport_encryption = container["transport_encryption"]
            if "method" in container:
                lxm.method = container["method"]

            return lxm
        except Exception as e:
            RNS.log("Could not unpack LXMessage from file. The contained exception was: "+str(e), RNS.LOG_ERROR)
            return None


class LXMFDeliveryAnnounceHandler:
    def __init__(self, lxmrouter):
        self.aspect_filter = APP_NAME+".delivery"
        self.lxmrouter = lxmrouter

    def received_announce(self, destination_hash, announced_identity, app_data):
        for lxmessage in self.lxmrouter.pending_outbound:
            if destination_hash == lxmessage.destination_hash:
                if lxmessage.method == LXMessage.DIRECT:
                    lxmessage.next_delivery_attempt = time.time()

                    while self.lxmrouter.processing_outbound:
                        time.sleep(0.1)

                    self.lxmrouter.process_outbound()


class LXMFPropagationAnnounceHandler:
    def __init__(self, lxmrouter):
        self.aspect_filter = APP_NAME+".propagation"
        self.lxmrouter = lxmrouter

    def received_announce(self, destination_hash, announced_identity, app_data):
        try:
            if type(app_data) == bytes:
                data = msgpack.unpackb(app_data)

                if self.lxmrouter.propagation_node and self.lxmrouter.autopeer:
                    if data[0] == True:
                        if RNS.Transport.hops_to(destination_hash) <= self.lxmrouter.autopeer_maxdepth:
                            self.lxmrouter.peer(destination_hash, data[1])
                    elif data[0] == False:
                        self.lxmrouter.unpeer(destination_hash, data[1])

        except Exception as e:
            RNS.log("Error while evaluating propagation node announce, ignoring announce.", RNS.LOG_DEBUG)
            RNS.log("The contained exception was: "+str(e), RNS.LOG_DEBUG)


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

    # Maximum amount of time a peer can
    # be unreachable before it is removed
    MAX_UNREACHABLE   = 4*24*60*60

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
        self.peering_timebase = 0

        self.link = None
        self.state = LXMPeer.IDLE

        self.unhandled_messages = {}
        self.handled_messages = {}
        
        self.router = router
        self.destination_hash = destination_hash
        self.identity = RNS.Identity.recall(destination_hash)
        self.destination = RNS.Destination(self.identity, RNS.Destination.OUT, RNS.Destination.SINGLE, APP_NAME, "propagation")

    def sync(self, initiator=True):
        RNS.log("Attempting sync to peer "+RNS.prettyhexrep(self.destination_hash), RNS.LOG_DEBUG)

        if not RNS.Transport.has_path(self.destination_hash):
            RNS.log("No path to peer "+RNS.prettyhexrep(self.destination_hash)+" exists, requesting...", RNS.LOG_DEBUG)
            RNS.Transport.request_path(self.destination_hash)
            RNS.log("Path requested, retrying sync later", RNS.LOG_DEBUG)
        else:
            RNS.log("Path to peer "+RNS.prettyhexrep(self.destination_hash)+" exist over "+str(RNS.Transport.hops_to(self.destination_hash))+" hops via "+str(RNS.Transport.next_hop_interface(self.destination_hash)), RNS.LOG_DEBUG)

            if self.identity == None:
                RNS.log("Attempting to recall identity for peer "+RNS.prettyhexrep(self.destination_hash), RNS.LOG_DEBUG)
                self.identity = RNS.Identity.recall(destination_hash)
                self.destination = RNS.Destination(self.identity, RNS.Destination.OUT, RNS.Destination.SINGLE, APP_NAME, "propagation")

            if self.identity != None:
                if len(self.unhandled_messages) > 0:
                    if self.state == LXMPeer.IDLE:
                        RNS.log("Establishing link for sync to peer "+RNS.prettyhexrep(self.destination_hash)+"...", RNS.LOG_DEBUG)
                        self.link = RNS.Link(self.destination, established_callback = self.link_established, closed_callback = self.link_closed)
                        self.state = LXMPeer.LINK_ESTABLISHING

                    else:
                        if self.state == LXMPeer.LINK_READY:
                            self.alive = True
                            self.last_heard = time.time()

                            RNS.log("Sync link to peer "+RNS.prettyhexrep(self.destination_hash)+" established, preparing request...", RNS.LOG_DEBUG)
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

class LXMRouter:
    MAX_DELIVERY_ATTEMPTS = 3
    PROCESSING_INTERVAL   = 5
    DELIVERY_RETRY_WAIT   = 15
    PATH_REQUEST_WAIT     = 5
    LINK_MAX_INACTIVITY   = 10*60

    MESSAGE_EXPIRY        = 30*24*60*60

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

    PR_ALL_MESSAGES      = 0x00

    def __init__(self, identity = None, storagepath = None, autopeer = AUTOPEER, autopeer_maxdepth = AUTOPEER_MAXDEPTH):
        random.seed(os.urandom(10))

        self.pending_inbound       = []
        self.pending_outbound      = []
        self.failed_outbound       = []
        self.direct_links          = {}
        self.delivery_destinations = {}

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

        self.wants_download_on_path_available_from = None
        self.wants_download_on_path_available_to = None
        self.propagation_transfer_state = LXMRouter.PR_IDLE
        self.propagation_transfer_progress = 0.0
        self.propagation_transfer_last_result = None
        self.propagation_transfer_max_messages = None
        self.locally_delivered_transient_ids = {}

        if identity == None:
            identity = RNS.Identity()

        self.identity = identity
        self.lxmf_query_destination  = RNS.Destination(None, RNS.Destination.IN, RNS.Destination.PLAIN, APP_NAME, "query")
        self.propagation_destination = RNS.Destination(self.identity, RNS.Destination.IN, RNS.Destination.SINGLE, APP_NAME, "propagation")

        self.autopeer          = autopeer
        self.autopeer_maxdepth = autopeer_maxdepth

        self.peers = {}
        self.propagation_entries = {}
        self.propagated_ids = {}

        RNS.Transport.register_announce_handler(LXMFDeliveryAnnounceHandler(self))
        RNS.Transport.register_announce_handler(LXMFPropagationAnnounceHandler(self))

        self.__delivery_callback = None

        try:
            if os.path.isfile(self.storagepath+"/local_deliveries"):
                locally_delivered_file = open(self.storagepath+"/local_deliveries", "rb")
                data = locally_delivered_file.read()
                self.locally_delivered_transient_ids = msgpack.unpackb(data)
                locally_delivered_file.close()
                self.clean_transient_id_cache()

        except Exception as e:
            RNS.log("Could not load locally delivered message ID cache from storage. The contained exception was: "+str(e), RNS.LOG_ERROR)

        atexit.register(self.exit_handler)

        job_thread = threading.Thread(target=self.jobloop)
        job_thread.setDaemon(True)
        job_thread.start()

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

        try:
            if not os.path.isdir(self.storagepath):
                    os.makedirs(self.storagepath)

            locally_delivered_file = open(self.storagepath+"/local_deliveries", "wb")
            locally_delivered_file.write(msgpack.packb(self.locally_delivered_transient_ids))
            locally_delivered_file.close()

        except Exception as e:
            RNS.log("Could not save locally delivered message ID cache to storage. The contained exception was: "+str(e), RNS.LOG_ERROR)


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

    def cancel_propagation_node_requests(self):
        if self.outbound_propagation_link != None:
            self.outbound_propagation_link.teardown()
            self.outbound_propagation_link = None

        self.acknowledge_sync_completion()

    def acknowledge_sync_completion(self):
        self.propagation_transfer_state = LXMRouter.PR_IDLE
        self.propagation_transfer_progress = 0.0
        self.propagation_transfer_last_result = None
        self.wants_download_on_path_available_from = None
        self.wants_download_on_path_available_to = None

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


    def has_message(self, transient_id):
        if transient_id in self.locally_delivered_transient_ids:
            return True
        else:
            return False
    
    def message_get_failed(self, request_receipt):
        RNS.log("Message list/get request failed", RNS.LOG_DEBUG)
        if self.outbound_propagation_link != None:
            self.outbound_propagation_link.teardown()

    def message_list_response(self, request_receipt):
        if request_receipt.response == LXMPeer.ERROR_NO_IDENTITY:
            RNS.log("Propagation node indicated missing identification on list request, tearing down link.", RNS.LOG_DEBUG)
            if self.outbound_propagation_link != None:
                self.outbound_propagation_link.teardown()
        else:
            if request_receipt.response != None:
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

    def message_get_progress(self, request_receipt):
        self.propagation_transfer_state = LXMRouter.PR_RECEIVING
        self.propagation_transfer_progress = request_receipt.get_progress()

    def message_get_response(self, request_receipt):
        if request_receipt.response == LXMPeer.ERROR_NO_IDENTITY:
            RNS.log("Propagation node indicated missing identification on get request, tearing down link.", RNS.LOG_DEBUG)
            if self.outbound_propagation_link != None:
                self.outbound_propagation_link.teardown()
        else:
            if request_receipt.response != None and len(request_receipt.response) > 0:
                haves = []
                for lxmf_data in request_receipt.response:
                    self.lxmf_propagation(lxmf_data)
                    haves.append(RNS.Identity.full_hash(lxmf_data))

                # Return a list of successfully received messages to the node
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

    def announce(self, destination_hash):
        if destination_hash in self.delivery_destinations:
            delivery_destination = self.delivery_destinations[destination_hash]
            delivery_destination.announce(delivery_destination.display_name.encode("utf-8"))

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

            if self.__delivery_callback != None:
                self.__delivery_callback(message)

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
        RNS.log("Transfer began for resource "+str(resource), RNS.LOG_DEBUG)

    def delivery_resource_concluded(self, resource):
        RNS.log("Transfer concluded for delivery resource "+str(resource), RNS.LOG_DEBUG)
        if resource.status == RNS.Resource.COMPLETE:
            self.lxmf_delivery(resource.data.read(), resource.link.type)

    
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
                            transient_id = bytes.fromhex(components[0])
                            received = components[1]

                            filepath = self.messagepath+"/"+filename
                            file = open(filepath, "rb")
                            destination_hash = file.read(LXMessage.DESTINATION_LENGTH)
                            file.close()

                            self.propagation_entries[transient_id] = [destination_hash, filepath]
            
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

            self.announce_propagation_node()

        except Exception as e:
            RNS.log("Could not enable propagation node. The contained exception was: "+str(e), RNS.LOG_ERROR)
            raise e
            RNS.panic()

    def disable_propagation(self):
        self.propagation_node = False
        self.announce_propagation_node()

    def announce_propagation_node(self):
        data = msgpack.packb([self.propagation_node, int(time.time())])
        self.propagation_destination.announce(app_data=data)

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

    def message_get_request(self, path, data, request_id, remote_identity, requested_at):
        if remote_identity == None:
            return LXMPeer.ERROR_NO_IDENTITY
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


    def lxmf_propagation(self, lxmf_data):
        try:
            if len(lxmf_data) >= LXMessage.LXMF_OVERHEAD:
                transient_id = RNS.Identity.full_hash(lxmf_data)
                if not transient_id in self.propagation_entries and not transient_id in self.propagated_ids:
                    received = time.time()
                    propagation_entry = [transient_id, received, lxmf_data]
                    destination_hash  = lxmf_data[:LXMessage.DESTINATION_LENGTH]

                    if destination_hash in self.delivery_destinations:
                        delivery_destination = self.delivery_destinations[destination_hash]
                        encrypted_lxmf_data = lxmf_data[LXMessage.DESTINATION_LENGTH:]
                        decrypted_lxmf_data = delivery_destination.decrypt(encrypted_lxmf_data)
                        delivery_data = lxmf_data[:LXMessage.DESTINATION_LENGTH]+decrypted_lxmf_data
                        self.lxmf_delivery(delivery_data, delivery_destination.type)
                        self.locally_delivered_transient_ids[transient_id] = time.time()

                    else:
                        if self.propagation_node:
                            file_path = self.messagepath+"/"+RNS.hexrep(transient_id, delimit=False)+"_"+str(received)
                            msg_file = open(file_path, "wb")
                            msg_file.write(lxmf_data)
                            msg_file.close()

                            self.propagation_entries[transient_id] = [destination_hash, file_path]

                            RNS.log("Received propagated LXMF message "+RNS.prettyhexrep(transient_id)+", adding to peer distribution queues...", RNS.LOG_DEBUG)
                            for peer_id in self.peers:
                                peer = self.peers[peer_id]
                                peer.handle_message(transient_id)

                    return True

            return False

        except Exception as e:
            RNS.log("Could not assemble propagated LXMF message from received data", RNS.LOG_DEBUG)
            RNS.log("The contained exception was: "+str(e), RNS.LOG_DEBUG)
            return False


    def peer(self, destination_hash, timestamp):
        if destination_hash in self.peers:
            peer = self.peers[destination_hash]
            peer.alive = True
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


    def jobloop(self):
        while (True):
            # TODO: Improve this to scheduling, so manual
            # triggers can delay next run
            self.jobs()
            time.sleep(LXMRouter.PROCESSING_INTERVAL)

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
            self.clean_transient_id_cache()

        if self.processing_count % LXMRouter.JOB_STORE_INTERVAL == 0:
            self.clean_message_store()

        if self.processing_count % LXMRouter.JOB_PEERSYNC_INTERVAL == 0:
            self.sync_peers()


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

    def clean_transient_id_cache(self):
        now = time.time()
        removed_entries = []
        for transient_id in self.locally_delivered_transient_ids:
            timestamp = self.locally_delivered_transient_ids[transient_id]
            if now > timestamp+LXMRouter.MESSAGE_EXPIRY*1.1:
                removed_entries.append(transient_id)

        for transient_id in removed_entries:
            self.locally_delivered_transient_ids.pop(transient_id)
            RNS.log("Cleaned "+RNS.prettyhexrep(transient_id)+" from local delivery cache", RNS.LOG_DEBUG)


    def clean_message_store(self):
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


    def sync_peers(self):
        culled_peers  = []
        waiting_peers = []
        for peer_id in self.peers:
            peer = self.peers[peer_id]
            if time.time() > peer.last_heard + LXMPeer.MAX_UNREACHABLE:
                culled_peers.append(peer_id)
            else:
                if peer.state == LXMPeer.IDLE and len(peer.unhandled_messages) > 0:
                    waiting_peers.append(peer)

        if len(waiting_peers) > 0:
            RNS.log("Randomly selecting peer to sync from "+str(len(waiting_peers))+" waiting peers.", RNS.LOG_DEBUG)
            selected_index = random.randint(0,len(waiting_peers)-1)
            selected_peer = waiting_peers[selected_index]
            RNS.log("Selected waiting peer "+str(selected_index)+": "+RNS.prettyhexrep(selected_peer.destination.hash), RNS.LOG_DEBUG)
            selected_peer.sync()

        for peer in culled_peers:
            RNS.log("Removing peer "+RNS.prettyhexrep(peer)+" due to excessive unreachability", RNS.LOG_WARNING)
            self.peers.pop(peer_id)


    def fail_message(self, lxmessage):
        RNS.log(str(lxmessage)+" failed to send", RNS.LOG_DEBUG)

        self.pending_outbound.remove(lxmessage)
        self.failed_outbound.append(lxmessage)

        lxmessage.state = LXMessage.FAILED
        if lxmessage.failed_callback != None:
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
                                RNS.log("The link to "+RNS.prettyhexrep(lxmessage.get_destination().hash)+" was closed", RNS.LOG_DEBUG)
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