import LXMF
import RNS
import time
import random

random_names = ["Tom", "Delilah", "Nancey", "Williams", "Neomi", "Curtis", "Alexa", "Theodora", "Ted", "Dinorah", "Nicol", "Drusilla", "Annalisa", "Verlene", "Latesha", "Tina", "Mia", "Brock", "Timothy", "Philip", "Willian", "Reyna", "Simona", "Mimi", "Stanford", "Ferne", "Catalina", "Lucie", "Jaye", "Natasha", "Willetta", "Isabel", "Esperanza", "Ciara", "Eusebio", "William", "Elma", "Angelica", "Coreen", "Melani", "Jonathan", "Maryland", "Caroline", "Gregg", "Ora", "Jacqui", "Letty", "Roselle", "Oralee", "Angla"]
random_titles = ["Long time", "Hi again", "Hi there", "Test message", "", "", "Something different"]
random_msgs = ["If wishes were horses then beggars might fly. Stuff like that. It's enough to drive you crazy.", "'My ident cards were stolen,' Jason said. 'That fivehundred-dollar bill is yours if you can get me to someone who can replace them. If you're going to do it, do it right now; I'm not going to wait.' Wait to be picked up by a pol or a nat, he thought. Caught here in this rundown dingy hotel.", "A six, no matter what the external circumstances, will always prevail. Because that's the way they genetically defined us.", "'Should be there in an hour,' he called back over his shoulder to Chuck. Then he added, in an afterthought, 'Wonder if the computer’s finished its run. It was due about now.'. Chuck didn’t reply, so George swung round in his saddle. He could just see Chuck’s face, a white oval turned toward the sky."]

def delivery_callback(message):
    pass

r = RNS.Reticulum()
router = LXMF.LXMRouter(storagepath="./tmp2")
router.register_delivery_callback(delivery_callback)
ident = RNS.Identity()
source = router.register_delivery_identity(ident, display_name=random_names[random.randint(0,len(random_names)-1)], stamp_cost=8)
router.announce(source.hash)
RNS.log("Source announced")

print("Recipient: ", end=" ")
recipient_hexhash = input()
recipient_hash = bytes.fromhex(recipient_hexhash)

if not RNS.Transport.has_path(recipient_hash):
    RNS.log("Destination is not yet known. Requesting path and waiting for announce to arrive...")
    RNS.Transport.request_path(recipient_hash)
    while not RNS.Transport.has_path(recipient_hash):
      time.sleep(0.1)

# Recall the server identity
recipient_identity = RNS.Identity.recall(recipient_hash)

dest = RNS.Destination(recipient_identity, RNS.Destination.OUT, RNS.Destination.SINGLE, "lxmf", "delivery")

# This loop allows you to execute various actions for testing
# and experimenting with the example scripts.
while True:

    # Create a message that will be sent directly to the
    # destination over a Reticulum link:

    lxm = LXMF.LXMessage(dest, source, random_msgs[random.randint(0,len(random_msgs)-1)],
                         random_titles[random.randint(0,len(random_titles)-1)],
                         desired_method=LXMF.LXMessage.DIRECT, include_ticket=True)

    # Or, create an oppertunistic, single-packet message
    # for sending without first establishing a link:

    # lxm = LXMF.LXMessage(dest, source, "This is a test",
    #                      random_titles[random.randint(0,len(random_titles)-1)],
    #                      desired_method=LXMF.LXMessage.OPPORTUNISTIC, include_ticket=True)


    # Or, try sending the message via a propagation node:

    # router.set_outbound_propagation_node(bytes.fromhex("e75d9b6a69f82b48b6077cf2242d7499"))
    # lxm = LXMF.LXMessage(dest, source, random_msgs[random.randint(0,len(random_msgs)-1)],
    #                      random_titles[random.randint(0,len(random_titles)-1)],
    #                      desired_method=LXMF.LXMessage.PROPAGATED)

    # Finally dispatch the message to the LXMF message
    # router, which will handle the delivery according
    # to the specified message parameters and options:
    
    router.handle_outbound(lxm)

    # Wait for user input before starting over
    input()