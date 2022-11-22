import RNS
import RNS.vendor.umsgpack as msgpack

import time
import base64

from .LXMF import APP_NAME

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
    PAPER              = 0x05
    valid_methods      = [OPPORTUNISTIC, DIRECT, PROPAGATED, PAPER]

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

    # Constants for QR/URI encoding LXMs
    URI_SCHEMA = "lxm"
    QR_ERROR_CORRECTION = "ERROR_CORRECT_L"
    QR_MAX_STORAGE = 2953
    PAPER_MDU = ((QR_MAX_STORAGE-(len(URI_SCHEMA)+len("://")))*6)//8

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

        self.propagation_packed      = None
        self.paper_packed            = None

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
            self.paper_packed = None

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
                self.desired_method = LXMessage.DIRECT
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

            elif self.desired_method == LXMessage.PAPER:
                paper_content_limit = LXMessage.PAPER_MDU

                encrypted_data = self.__destination.encrypt(self.packed[LXMessage.DESTINATION_LENGTH:])
                self.paper_packed = self.packed[:LXMessage.DESTINATION_LENGTH]+encrypted_data

                content_size = len(self.paper_packed)
                if content_size <= paper_content_limit:
                    self.method = self.desired_method
                    self.representation = LXMessage.PAPER
                else:
                    raise TypeError("LXMessage desired paper delivery method, but content exceeds paper message maximum size.")

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
                if receipt:
                    receipt.set_delivery_callback(self.__mark_delivered)
                    receipt.set_timeout_callback(self.__link_packet_timed_out)
                else:
                    if self.__delivery_destination:
                        self.__delivery_destination.teardown()

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
            elif self.__destination.type == RNS.Destination.GROUP:
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
        elif self.method == LXMessage.PAPER:
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

        if self.__delivery_callback != None and callable(self.__delivery_callback):
            try:
                self.__delivery_callback(self)
            except Exception as e:
                    RNS.log("An error occurred in the external delivery callback for "+str(message), RNS.LOG_ERROR)

    def __mark_propagated(self, receipt = None):
        RNS.log("Received propagation success notification for "+str(self), RNS.LOG_DEBUG)
        self.state = LXMessage.SENT

        if self.__delivery_callback != None and callable(self.__delivery_callback):
            try:
                self.__delivery_callback(self)
            except Exception as e:
                    RNS.log("An error occurred in the external delivery callback for "+str(message), RNS.LOG_ERROR)

    def __mark_paper_generated(self, receipt = None):
        RNS.log("Paper message generation succeeded for "+str(self), RNS.LOG_DEBUG)
        self.state = LXMessage.PAPER

        if self.__delivery_callback != None and callable(self.__delivery_callback):
            try:
                self.__delivery_callback(self)
            except Exception as e:
                    RNS.log("An error occurred in the external delivery callback for "+str(message), RNS.LOG_ERROR)

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

    def packed_container(self):
        if not self.packed:
            self.pack()

        container = {
            "state": self.state,
            "lxmf_bytes": self.packed,
            "transport_encrypted": self.transport_encrypted,
            "transport_encryption": self.transport_encryption,
            "method": self.method
        }

        return msgpack.packb(container)


    def write_to_directory(self, directory_path):
        file_name = RNS.hexrep(self.hash, delimit=False)
        file_path = directory_path+"/"+file_name

        try:
            file = open(file_path, "wb")
            file.write(self.packed_container())
            file.close()

            return file_path

        except Exception as e:
            RNS.log("Error while writing LXMF message to file \""+str(file_path)+"\". The contained exception was: "+str(e), RNS.LOG_ERROR)
            return None

    def as_uri(self, finalise=True):
        self.determine_transport_encryption()
        if not self.packed:
            self.pack()

        if self.desired_method == LXMessage.PAPER and self.paper_packed != None:
            # Encode packed LXM with URL-safe base64 and remove padding
            encoded_bytes = base64.urlsafe_b64encode(self.paper_packed)

            # Add protocol specifier and return
            lxm_uri = LXMessage.URI_SCHEMA+"://"+encoded_bytes.decode("utf-8").replace("=","")

            if finalise:
                self.__mark_paper_generated()
            
            return lxm_uri

        else:
            raise TypeError("Attempt to represent LXM with non-paper delivery method as URI")

    def as_qr(self):
        self.determine_transport_encryption()
        if not self.packed:
            self.pack()

        if self.desired_method == LXMessage.PAPER and self.paper_packed != None:
            import importlib
            if importlib.util.find_spec('qrcode') != None:
                import qrcode

                qr = qrcode.make(
                    error_correction = qrcode.constants.__dict__[LXMessage.QR_ERROR_CORRECTION],
                    border = 1,
                    data = self.as_uri(finalise=False),
                )

                self.__mark_paper_generated()

                return qr

            else:
                RNS.log("Generating QR-code representanions of LXMs requires the \"qrcode\" module to be installed.", RNS.LOG_CRITICAL)
                RNS.log("You can install it with the command: python3 -m pip install qrcode", RNS.LOG_CRITICAL)
                return None

        else:
            raise TypeError("Attempt to represent LXM with non-paper delivery method as QR-code")

    @staticmethod
    def unpack_from_bytes(lxmf_bytes, original_method = None):
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
            source_hash = source_hash,
            desired_method = original_method)

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