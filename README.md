# Lightweight Extensible Message Format

LXMF is a simple and flexible messaging format and delivery protocol that allows a wide variety of implementations, while using as little bandwidth as possible. It is built on top of [Reticulum](https://reticulum.network) and offers zero-conf message routing, end-to-end encryption and Forward Secrecy, and can be transported over any kind of medium that Reticulum supports.

LXMF is efficient enough that it can deliver messages over extremely low-bandwidth systems such as packet radio or LoRa. Encrypted LXMF messages can also be encoded as QR-codes or text-based URIs, allowing completely analog *paper message* transport.

User-facing clients built on LXMF include:

- [Sideband](https://unsigned.io/sideband)
- [MeshChat](https://github.com/liamcottle/reticulum-meshchat)
- [Nomad Network](https://unsigned.io/nomadnet)

Community-provided tools and utilities for LXMF include:

- [LXMF-Bot](https://github.com/randogoth/lxmf-bot)
- [LXMF Messageboard](https://github.com/chengtripp/lxmf_messageboard)
- [LXMEvent](https://github.com/faragher/LXMEvent)
- [RangeMap](https://github.com/faragher/RangeMap)
- [LXMF Tools](https://github.com/SebastianObi/LXMF-Tools)

## Structure

LXMF messages are stored in a simple and efficient format, that's easy to parse and write.

### The format follows this general structure:

- Destination
- Source
- Ed25519 Signature
- Payload
    - Timestamp
    - Content
    - Title
    - Fields

### And these rules:

1. A LXMF message is identified by its __message-id__, which is a SHA-256 hash of the __Destination__, __Source__ and __Payload__. The message-id is never included directly in the message, since it can always be inferred from the message itself.

   In some cases the actual message-id cannot be inferred, for example when a Propagation Node is storing an encrypted message for an offline user. In these cases a _transient-id_ is used to identify the message while in storage or transit.

2. __Destination__, __Source__, __Signature__ and __Payload__ parts are mandatory, as is the __Timestamp__ part of the payload.
    - The __Destination__ and __Source__ fields are 16-byte Reticulum destination hashes
    - The __Signature__ field is a 64-byte Ed25519 signature of the __Destination__, __Source__, __Payload__ and __message-id__
    - The __Payload__ part is a [msgpacked](https://msgpack.org) list containing four items:
        1. The __Timestamp__ is a double-precision floating point number representing the number of seconds since the UNIX epoch.
        2. The __Content__ is the optional content or body of the message
        3. The __Title__  is an optional title for the message
        4. The __Fields__ is an optional dictionary

3. The __Content__, __Title__ and __Fields__ parts must be included in the message structure, but can be left empty.

4. The __Fields__ part can be left empty, or contain a dictionary of any structure or depth.

## Usage Examples

LXMF offers flexibility to implement many different messaging schemes, ranging from human communication to machine control and sensor monitoring. Here are a few examples:

- A messaging system for passing short, simple messages between human users, akin to SMS can be implemented using only the __Content__ field, and leaving all other optional fields empty.

- For sending full-size mail, an email-like system can be implemented using the __Title__ and __Content__ fields to store "subject" and "body" parts of the message, and optionally the __Fields__ part can be used to store attachments or other metadata.

- Machine-control messages or sensor readings can be implemented using command structures embedded in the __Fields__ dictionary.

- Distributed discussion or news-groups, akin to USENET or similar systems, can be implemented using the relevant fields and LXMF Propagation Nodes. Broadcast bulletins can be implemented in a similar fashion.

## Propagation Nodes

LXM Propagation Nodes offer a way to store and forward messages to users or endpoints that are not directly reachable at the time of message emission. Propagation Nodes can also provide infrastructure for distributed bulletin, news or discussion boards.

When Propagation Nodes exist on a Reticulum network, they will by default peer with each other and synchronise messages, automatically creating an encrypted, distributed message store. Users and other endpoints can retrieve messages destined for them from any available Propagation Nodes on the network.

## The LXM Router

The LXM Router handles transporting messages over a Reticulum network, managing delivery receipts, outbound and inbound queues, and is the point of API interaction for client programs. The LXM Router also implements functionality for acting as an LXMF Propagation Node.

Programatically, using the LXM Router to send a message is as simple as:

```python
import LXMF

lxm_router = LXMF.LXMRouter()

message = LXMF.LXMessage(destination, source, "This is a short, simple message.")

lxm_router.handle_outbound(message)

```

The LXM Router then handles the heavy lifting, such as message packing, encryption, delivery confirmation, path lookup, routing, retries and failure notifications.

## Transport Encryption

LXMF uses encryption provided by [Reticulum](https://reticulum.network), and thus uses end-to-end encryption by default. The delivery method of a message will influence which transport encryption scheme is used.

- If a message is delivered over a Reticulum link (which is the default method), the message will be encrypted with ephemeral AES-128 keys derived with ECDH on Curve25519. This mode offers forward secrecy.

- A message can be delivered opportunistically, embedded in a single Reticulum packet. In this cases the message will be opportunistically routed through the network, and will be encrypted with per-packet AES-128 keys derived with ECDH on Curve25519.

- If a message is delivered to the Reticulum GROUP destination type, the message will be encrypted using the symmetric AES-128 key of the GROUP destination.

## Wire Format & Overhead

Assuming the default Reticulum configuration, the binary wire-format is as follows:

- 16 bytes destination hash
- 16 bytes source hash
- 64 bytes Ed25519 signature
- Remaining bytes of [msgpack](https://msgpack.org) payload data, in accordance with the structure defined above

The complete message overhead for LXMF is only 111 bytes, which in return gives you timestamped, digitally signed, infinitely extensible, end-to-end encrypted, zero-conf routed, minimal-infrastructure messaging that's easy to use and build applications with.

## Code Examples

Before writing your own programs using LXMF, you need to have a basic understanding of how the [Reticulum](https://reticulum.network) protocol and API works. Please see the [Reticulum Manual](https://reticulum.network/manual/). For a few simple examples of how to send and receive messages with LXMF, please see the [receiver example](./docs/example_receiver.py) and the [sender example](./docs/example_sender.py) included in this repository.

## Example Paper Message

You can try out the paper messaging functionality by using the following QR code. It is a paper message sent to the LXMF address `6b3362bd2c1dbf87b66a85f79a8d8c75`. To be able to decrypt and read the message, you will need to import the following Reticulum Identity to an LXMF messaging app:

`3BPTDTQCRZPKJT3TXAJCMQFMOYWIM3OCLKPWMG4HCF2T4CH3YZHVNHNRDU6QAZWV2KBHMWBNT2C62TQEVC5GLFM4MN25VLZFSK3ADRQ=`

The [Sideband](https://unsigned.io/sideband) application allows you to do this easily. After you have imported the identity into an app of your choice, you can scan the following QR code and open it in the app, where it will be decrypted and added as a message.

<p align="center"><img width="50%" src="./docs/paper_msg_test.png"/></p>

You can also find the entire message in <a href="lxm://azNivSwdv4e2aoX3mo2MdTAozuI7BlzrLlHULmnVgpz3dNT9CMPVwgywzCJP8FVogj5j_kU7j7ywuvBNcr45kRTrd19c3iHenmnSDe4VEd6FuGsAiT0Khzl7T81YZHPTDhRNp0FdhDE9AJ7uphw7zKMyqhHHxOxqrYeBeKF66gpPxDceqjsOApvsSwggjcuHBx9OxOBy05XmnJxA1unCKgvNfOFYc1T47luxoY3c0dLOJnJPwZuFRytx2TXlQNZzOJ28yTEygIfkDqEO9mZi5lgev7XZJ0DvgioQxMIyoCm7lBUzfq66zW3SQj6vHHph7bhr36dLOCFgk4fZA6yia2MlTT9KV66Tn2l8mPNDlvuSAJhwDA_xx2PN9zKadCjo9sItkAp8r-Ss1CzoUWZUAyT1oDw7ly6RrzGBG-e3eM3CL6u1juIeFiHby7_3cON-6VTUuk4xR5nwKlFTu5vsYMVXe5H3VahiDSS4Q1aqX7I">this link</a>:

`lxm://azNivSwdv4e2aoX3mo2MdTAozuI7BlzrLlHULmnVgpz3dNT9CMPVwgywzCJP8FVogj5j_kU7j7ywuvBNcr45kRTrd19c3iHenmnSDe4VEd6FuGsAiT0Khzl7T81YZHPTDhRNp0FdhDE9AJ7uphw7zKMyqhHHxOxqrYeBeKF66gpPxDceqjsOApvsSwggjcuHBx9OxOBy05XmnJxA1unCKgvNfOFYc1T47luxoY3c0dLOJnJPwZuFRytx2TXlQNZzOJ28yTEygIfkDqEO9mZi5lgev7XZJ0DvgioQxMIyoCm7lBUzfq66zW3SQj6vHHph7bhr36dLOCFgk4fZA6yia2MlTT9KV66Tn2l8mPNDlvuSAJhwDA_xx2PN9zKadCjo9sItkAp8r-Ss1CzoUWZUAyT1oDw7ly6RrzGBG-e3eM3CL6u1juIeFiHby7_3cON-6VTUuk4xR5nwKlFTu5vsYMVXe5H3VahiDSS4Q1aqX7I`

On operating systems that allow for registering custom URI-handlers, you can click the link, and it will be decoded directly in your LXMF client. This works with Sideband on Android.

## Installation

If you want to try out LXMF, you can install it with pip:

```bash
pip install lxmf
```

If you are using an operating system that blocks normal user package installation via `pip`,
you can return `pip` to normal behaviour by editing the `~/.config/pip/pip.conf` file,
and adding the following directive in the `[global]` section:

```text
[global]
break-system-packages = true
```

Alternatively, you can use the `pipx` tool to install Reticulum in an isolated environment:

```bash
pipx install lxmf
```

## Daemon Included

The `lxmf` package comes with the `lxmd` program, a fully functional (but lightweight) LXMF message router and propagation node daemon. After installing the `lxmf` package, you can run `lxmd --help` to learn more about the command-line options:

```text
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
```

Or run `lxmd --exampleconfig` to generate a commented example configuration documenting all the available configuration directives.

## Caveat Emptor

LXMF is beta software, and should be considered experimental. While it has been built with cryptography best practices very foremost in mind, it _has not_ been externally security audited, and there could very well be privacy-breaking bugs. If you want to help out, or help sponsor an audit, please do get in touch.

## Development Roadmap

LXMF is actively being developed, and the following improvements and features are currently planned for implementation:

- ~~Update examples in readme to actually work~~
- ~~Sync affinity based on link speeds and distances, for more intelligently choosing peer sync order~~
- Sneakernet and physical transport functionality
- Content Destinations, and easy to use API for group messaging and discussion threads 
- Write and release full API and protocol documentation
- Documenting and possibly expanding LXMF limits and priorities
