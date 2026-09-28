>Lightweight Extensible Message Format

LXMF is a simple and flexible messaging format and delivery protocol that allows a wide variety of implementations, while using as little bandwidth as possible. It is built on top of `_`!`[Reticulum`https://reticulum.network]`!`_ and offers zero-conf message routing, end-to-end encryption and Forward Secrecy, and can be transported over any kind of medium that Reticulum supports.

LXMF is efficient enough that it can deliver messages over extremely low-bandwidth systems such as packet radio or LoRa. Encrypted LXMF messages can also be encoded as QR-codes or text-based URIs, allowing completely analog `*paper message`* transport.

User-facing clients built on LXMF include:

 • `_`!`[Sideband`https://unsigned.io/sideband]`!`_
 • `_`!`[MeshChatX`https://meshchatx.com/]`!`_
 • `_`!`[Nomad Network`https://unsigned.io/nomadnet]`!`_
 • `_`!`[Columba`https://github.com/torlando-tech/columba]`!`_

Community-provided tools and utilities for LXMF include:

 • `_`!`[LXMFy`https://lxmfy.quad4.io/]`!`_
 • `_`!`[LXMF-Bot`https://github.com/randogoth/lxmf-bot]`!`_
 • `_`!`[LXMF Messageboard`https://github.com/chengtripp/lxmf_messageboard]`!`_
 • `_`!`[LXMEvent`https://github.com/faragher/LXMEvent]`!`_
 • `_`!`[RangeMap`https://github.com/faragher/RangeMap]`!`_
 • `_`!`[LXMF Tools`https://github.com/SebastianObi/LXMF-Tools]`!`_

>>Structure

LXMF messages are stored in a simple and efficient format, that's easy to parse and write.

>>>The format follows this general structure:

 • Destination
 • Source
 • Ed25519 Signature
 • Payload
     • Timestamp
     • Content
     • Title
     • Fields

>>>And these rules:

1. A LXMF message is identified by its `!message-id`!, which is a SHA-256 hash of the `!Destination`!, `!Source`! and `!Payload`!. The message-id is never included directly in the message, since it can always be inferred from the message itself.

   In some cases the actual message-id cannot be inferred, for example when a Propagation Node is storing an encrypted message for an offline user. In these cases a `*transient-id`* is used to identify the message while in storage or transit.

2. `!Destination`!, `!Source`!, `!Signature`! and `!Payload`! parts are mandatory, as is the `!Timestamp`! part of the payload.
     • The `!Destination`! and `!Source`! fields are 16-byte Reticulum destination hashes
     • The `!Signature`! field is a 64-byte Ed25519 signature of the `!Destination`!, `!Source`!, `!Payload`! and `!message-id`!
     • The `!Payload`! part is a `_`!`[msgpacked`https://msgpack.org]`!`_ list containing four items:
        1. The `!Timestamp`! is a double-precision floating point number representing the number of seconds since the UNIX epoch.
        2. The `!Content`! is the optional content or body of the message
        3. The `!Title`!  is an optional title for the message
        4. The `!Fields`! is an optional dictionary

3. The `!Content`!, `!Title`! and `!Fields`! parts must be included in the message structure, but can be left empty.

4. The `!Fields`! part can be left empty, or contain a dictionary of any structure or depth.

>>Usage Examples

LXMF offers flexibility to implement many different messaging schemes, ranging from human communication to machine control and sensor monitoring. Here are a few examples:

 • A messaging system for passing short, simple messages between human users, akin to SMS can be implemented using only the `!Content`! field, and leaving all other optional fields empty.

 • For sending full-size mail, an email-like system can be implemented using the `!Title`! and `!Content`! fields to store "subject" and "body" parts of the message, and optionally the `!Fields`! part can be used to store attachments or other metadata.

 • Machine-control messages or sensor readings can be implemented using command structures embedded in the `!Fields`! dictionary.

 • Distributed discussion or news-groups, akin to USENET or similar systems, can be implemented using the relevant fields and LXMF Propagation Nodes. Broadcast bulletins can be implemented in a similar fashion.

>>Propagation Nodes

LXM Propagation Nodes offer a way to store and forward messages to users or endpoints that are not directly reachable at the time of message emission. Propagation Nodes can also provide infrastructure for distributed bulletin, news or discussion boards.

When Propagation Nodes exist on a Reticulum network, they will by default peer with each other and synchronise messages, automatically creating an encrypted, distributed message store. Users and other endpoints can retrieve messages destined for them from any available Propagation Nodes on the network.

>>The LXM Router

The LXM Router handles transporting messages over a Reticulum network, managing delivery receipts, outbound and inbound queues, and is the point of API interaction for client programs. The LXM Router also implements functionality for acting as an LXMF Propagation Node.

Programatically, using the LXM Router to send a message is as simple as:

`BT282828`Fddd
`FTff7b72import`f `FT7ee787LXMF`f

`FTe6edf3lxm_router`f `FTff7b72=`f `FTe6edf3LXMF`f`FTff7b72.`f`FTd2a8ffLXMRouter`f`FTb4b4b4(`f`FTb4b4b4)`f

`FTe6edf3message`f `FTff7b72=`f `FTe6edf3LXMF`f`FTff7b72.`f`FTd2a8ffLXMessage`f`FTb4b4b4(`f`FTe6edf3destination`f`FTb4b4b4,`f `FTe6edf3source`f`FTb4b4b4,`f `FTa5d6ff"`f`FTa5d6ffThis is a short, simple message.`f`FTa5d6ff"`f`FTb4b4b4)`f

`FTe6edf3lxm_router`f`FTff7b72.`f`FTd2a8ffhandle_outbound`f`FTb4b4b4(`f`FTe6edf3message`f`FTb4b4b4)`f
`f`b

The LXM Router then handles the heavy lifting, such as message packing, encryption, delivery confirmation, path lookup, routing, retries and failure notifications.

>>Transport Encryption

LXMF uses encryption provided by `_`!`[Reticulum`https://reticulum.network]`!`_, and thus uses end-to-end encryption by default. The delivery method of a message will influence which transport encryption scheme is used.

 • If a message is delivered over a Reticulum link (which is the default method), the message will be encrypted with ephemeral AES-128 keys derived with ECDH on Curve25519. This mode offers forward secrecy.

 • A message can be delivered opportunistically, embedded in a single Reticulum packet. In this cases the message will be opportunistically routed through the network, and will be encrypted with per-packet AES-128 keys derived with ECDH on Curve25519.

 • If a message is delivered to the Reticulum GROUP destination type, the message will be encrypted using the symmetric AES-128 key of the GROUP destination.

>>Wire Format & Overhead

Assuming the default Reticulum configuration, the binary wire-format is as follows:

 • 16 bytes destination hash
 • 16 bytes source hash
 • 64 bytes Ed25519 signature
 • Remaining bytes of `_`!`[msgpack`https://msgpack.org]`!`_ payload data, in accordance with the structure defined above

The complete message overhead for LXMF is only 111 bytes, which in return gives you timestamped, digitally signed, infinitely extensible, end-to-end encrypted, zero-conf routed, minimal-infrastructure messaging that's easy to use and build applications with.

>>Code Examples

Before writing your own programs using LXMF, you need to have a basic understanding of how the `_`!`[Reticulum`https://reticulum.network]`!`_ protocol and API works. Please see the `_`!`[Reticulum Manual`https://reticulum.network/manual/]`!`_. For a few simple examples of how to send and receive messages with LXMF, please see the `_`!`[receiver example`:/page/blob.mu`g=reticulum|r=lxmf|ref=HEAD|path=./docs/example_receiver.py]`!`_ and the `_`!`[sender example`:/page/blob.mu`g=reticulum|r=lxmf|ref=HEAD|path=./docs/example_sender.py]`!`_ included in this repository.

>>Example Paper Message

You can try out the paper messaging functionality by using the following QR code. It is a paper message sent to the LXMF address `BT383838`Fddd6b3362bd2c1dbf87b66a85f79a8d8c75`f`b. To be able to decrypt and read the message, you will need to import the following Reticulum Identity to an LXMF messaging app:

`BT383838`Fddd3BPTDTQCRZPKJT3TXAJCMQFMOYWIM3OCLKPWMG4HCF2T4CH3YZHVNHNRDU6QAZWV2KBHMWBNT2C62TQEVC5GLFM4MN25VLZFSK3ADRQ=`f`b

The `_`!`[Sideband`https://unsigned.io/sideband]`!`_ application allows you to do this easily. After you have imported the identity into an app of your choice, you can scan the following QR code and open it in the app, where it will be decrypted and added as a message.

`_`!`[Paper message QR code`a8d24177d946de4f1f0a0fe1af9a1338:/page/blob.mu`g=reticulum|r=lxmf|ref=HEAD|path=docs/paper_msg_test.png]`!`_

You can also find the entire message in this link:

`BT282828`Fddd
`=
lxm://azNivSwdv4e2aoX3mo2MdTAozuI7BlzrLlHULmnVgpz3dNT9CMPVwgywzCJP8FVogj5j_kU7j7ywuvBNcr45kRTrd19c3iHenmnSDe4VEd6FuGsAiT0Khzl7T81YZHPTDhRNp0FdhDE9AJ7uphw7zKMyqhHHxOxqrYeBeKF66gpPxDceqjsOApvsSwggjcuHBx9OxOBy05XmnJxA1unCKgvNfOFYc1T47luxoY3c0dLOJnJPwZuFRytx2TXlQNZzOJ28yTEygIfkDqEO9mZi5lgev7XZJ0DvgioQxMIyoCm7lBUzfq66zW3SQj6vHHph7bhr36dLOCFgk4fZA6yia2MlTT9KV66Tn2l8mPNDlvuSAJhwDA_xx2PN9zKadCjo9sItkAp8r-Ss1CzoUWZUAyT1oDw7ly6RrzGBG-e3eM3CL6u1juIeFiHby7_3cON-6VTUuk4xR5nwKlFTu5vsYMVXe5H3VahiDSS4Q1aqX7I
`=
`f`b

On operating systems that allow for registering custom URI-handlers, you can click the link, and it will be decoded directly in your LXMF client. This works with Sideband on Android.

>>Installation

If you want to try out LXMF, you can install it with pip:

`BT282828`Fddd
pip install lxmf
`f`b

If you are using an operating system that blocks normal user package installation via `BT383838`Fdddpip`f`b,
you can return `BT383838`Fdddpip`f`b to normal behaviour by editing the `BT383838`Fddd~/.config/pip/pip.conf`f`b file,
and adding the following directive in the `BT383838`Fddd[global]`f`b section:

`BT282828`Fddd
[global]
break-system-packages = true
`f`b

Alternatively, you can use the `BT383838`Fdddpipx`f`b tool to install Reticulum in an isolated environment:

`BT282828`Fddd
pipx install lxmf
`f`b

>>Daemon Included

The `BT383838`Fdddlxmf`f`b package comes with the `BT383838`Fdddlxmd`f`b program, a fully functional (but lightweight) LXMF message router and propagation node daemon. After installing the `BT383838`Fdddlxmf`f`b package, you can run `BT383838`Fdddlxmd --help`f`b to learn more about the command-line options:

`BT282828`Fddd
$ lxmd --help

usage: lxmd [-h] [--config CONFIG] [--rnsconfig RNSCONFIG] [-p] [-i PATH] [-v] [-q] [-s] [--exampleconfig] [--version]

Lightweight Extensible Messaging Daemon

options:
  -h, --help            show this help message and exit
  --config CONFIG       path to alternative lxmd config directory
  --rnsconfig RNSCONFIG
                        path to alternative Reticulum config directory
  -p, --propagation-node
                        run an LXMF Propagation Node
  -i PATH, --on-inbound PATH
                        executable to run when a message is received
  -v, --verbose
  -q, --quiet
  -s, --service         lxmd is running as a service and should log to file
  --exampleconfig       print verbose configuration example to stdout and exit
  --version             show program's version number and exit
`f`b

Or run `BT383838`Fdddlxmd --exampleconfig`f`b to generate a commented example configuration documenting all the available configuration directives.

>>Support LXMF Development
You can help support the continued development of open, free and private communications systems by donating via one of the following channels:

 • Monero:
`BT282828`Fddd
`=
  84FpY1QbxHcgdseePYNmhTHcrgMX4nFfBYtz2GKYToqHVVhJp8Eaw1Z1EedRnKD19b3B8NiLCGVxzKV17UMmmeEsCrPyA5w
`=
`f`b
 • Bitcoin
`BT282828`Fddd
`=
  bc1pgqgu8h8xvj4jtafslq396v7ju7hkgymyrzyqft4llfslz5vp99psqfk3a6
`=
`f`b
 • Ethereum
`BT282828`Fddd
`=
  0x91C421DdfB8a30a49A71d63447ddb54cEBe3465E
`=
`f`b
 • Liberapay: https://liberapay.com/Reticulum/

 • Ko-Fi: https://ko-fi.com/markqvist


>>Caveat Emptor

LXMF is beta software, and should be considered experimental. While it has been built with cryptography best practices very foremost in mind, it `*has not`* been externally security audited, and there could very well be privacy-breaking bugs. If you want to help out, or help sponsor an audit, please do get in touch.

>>Development Roadmap

LXMF is actively being developed, and the following improvements and features are currently planned for implementation:

 • Sneakernet and physical transport functionality
 • Content Destinations, and easy to use API for group messaging and discussion threads 
 • Write and release full API and protocol documentation
 • Documenting and possibly expanding LXMF limits and priorities