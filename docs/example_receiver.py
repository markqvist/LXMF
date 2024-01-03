import RNS
import LXMF
import time

def delivery_callback(message):
  time_string      = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(message.timestamp))
  signature_string = "Signature is invalid, reason undetermined"
  if message.signature_validated:
    signature_string = "Validated"
  else:
    if message.unverified_reason == LXMF.LXMessage.SIGNATURE_INVALID:
      signature_string = "Invalid signature"
    if message.unverified_reason == LXMF.LXMessage.SOURCE_UNKNOWN:
      signature_string = "Cannot verify, source is unknown"

  RNS.log("\t+--- LXMF Delivery ---------------------------------------------")
  RNS.log("\t| Source hash            : "+RNS.prettyhexrep(message.source_hash))
  RNS.log("\t| Source instance        : "+str(message.get_source()))
  RNS.log("\t| Destination hash       : "+RNS.prettyhexrep(message.destination_hash))
  RNS.log("\t| Destination instance   : "+str(message.get_destination()))
  RNS.log("\t| Transport Encryption   : "+str(message.transport_encryption))
  RNS.log("\t| Timestamp              : "+time_string)
  RNS.log("\t| Title                  : "+message.title_as_string())
  RNS.log("\t| Content                : "+message.content_as_string())
  RNS.log("\t| Fields                 : "+str(message.fields))
  RNS.log("\t| Message signature      : "+signature_string)
  RNS.log("\t+---------------------------------------------------------------")

r = RNS.Reticulum()

router = LXMF.LXMRouter(storagepath="./tmp1")
identity = RNS.Identity()
my_lxmf_destination = router.register_delivery_identity(identity)
router.register_delivery_callback(delivery_callback)

RNS.log("Ready to receive on: "+RNS.prettyhexrep(my_lxmf_destination.hash))
input()