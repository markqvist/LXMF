import RNS
import LXMF
import time

required_stamp_cost = 8
enforce_stamps = False

def delivery_callback(message):
  global my_lxmf_destination, router
  time_string      = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(message.timestamp))
  signature_string = "Signature is invalid, reason undetermined"
  if message.signature_validated:
    signature_string = "Validated"
  else:
    if message.unverified_reason == LXMF.LXMessage.SIGNATURE_INVALID:
      signature_string = "Invalid signature"
    if message.unverified_reason == LXMF.LXMessage.SOURCE_UNKNOWN:
      signature_string = "Cannot verify, source is unknown"

  if message.stamp_valid:
    stamp_string = "Validated"
  else:
    stamp_string = "Invalid"

  RNS.log("\t+--- LXMF Delivery ---------------------------------------------")
  RNS.log(f"\t| Source hash            : {RNS.prettyhexrep(message.source_hash)}")
  RNS.log(f"\t| Source instance        : {message.get_source()}")
  RNS.log(f"\t| Destination hash       : {RNS.prettyhexrep(message.destination_hash)}")
  RNS.log(f"\t| Destination instance   : {message.get_destination()}")
  RNS.log(f"\t| Transport Encryption   : {message.transport_encryption}")
  RNS.log(f"\t| Timestamp              : {time_string}")
  RNS.log(f"\t| Title                  : {message.title_as_string()}")
  RNS.log(f"\t| Content                : {message.content_as_string()}")
  RNS.log(f"\t| Fields                 : {message.fields}")
  if message.ratchet_id:
    RNS.log(f"\t| Ratchet                : {RNS.Identity._get_ratchet_id(message.ratchet_id)}")
  RNS.log(f"\t| Message signature      : {signature_string}")
  RNS.log(f"\t| Stamp                  : {stamp_string}")
  RNS.log("\t+---------------------------------------------------------------")

  # Optionally, send a reply
  # source = my_lxmf_destination
  # dest = message.source
  # lxm = LXMF.LXMessage(dest, source, "Reply", None, desired_method=LXMF.LXMessage.DIRECT, include_ticket=True)
  # router.handle_outbound(lxm)

r = RNS.Reticulum()

router = LXMF.LXMRouter(storagepath="./tmp1", enforce_stamps=enforce_stamps)
identity = RNS.Identity()
my_lxmf_destination = router.register_delivery_identity(identity, display_name="Anonymous Peer", stamp_cost=required_stamp_cost)
router.register_delivery_callback(delivery_callback)

RNS.log(f"Ready to receive on: {RNS.prettyhexrep(my_lxmf_destination.hash)}")


# You can set a propagation node address to test receiving
# messages from a propagation node, instead of directly

# router.set_outbound_propagation_node(bytes.fromhex("e75d9b6a69f82b48b6077cf2242d7499"))


# This loop allows you to execute various actions for testing
# and experimenting with the example scripts.
while True:
  input()
  RNS.log("Announcing lxmf.delivery destination...")
  router.announce(my_lxmf_destination.hash)

  # input()
  # RNS.log("Requesting messages from propagation node...")
  # router.request_messages_from_propagation_node(identity)