Lightweight Extensible Message Format
==========

LXMF is a simple and flexible messaging format that allows a wide variety of implementations, while using as little bandwidth as possible. It is built on top of [Reticulum](https://github.com/markqvist/reticulum) and offers zero-conf message routing, end-to-end encryption and Perfect Forward Secrecy by default.

## Structure

LXMF messages are stored in a simple and efficient format, that's easy to parse and write.

##### The format follows this general structure:

- Destination
- Source
- RSA Signature
- Payload
    - Timestamp
    - Content
    - Title
    - Fields

##### And these rules:

1. A LXMF message is identified by it's __message-id__, which is a SHA-256 hash of the __Destination__, __Source__ and __Payload__. The message-id is never included directly in the message, since it can always be inferred from the message itself.

   In some cases the actual message-id cannot be inferred, for example when a Propagation Node is storing an encrypted message for an offline user. In theses cases a _transient-id_ is used to identify the message while in storage or transit.

2. __Destination__, __Source__, __Signature__ and __Payload__ parts are mandatory, as is the __Timestamp__ part of the payload.
    - The __Destination__ and __Source__ fields are Reticulum destination hashes
    - The __Signature__ field is a RSA signature of the __Destination__, __Source__, __Payload__ and __message-id__
    - The __Payload__ part is a list containing four items:
        1. The __Timestamp__ is a double-precision floating point number representing the number of seconds since the UNIX epoch.
        2. The __Content__ is the optional content or body of the message
        3. The __Title__  is an optional title for the message
        4. The __Fields__ is an optional dictionary

3. The __Content__, __Title__ and __Fields__ parts must be included in the message structure, but can be left empty.

4. The __Fields__ part can be left empty, or contain a dictionary of any structure or depth.

## Usage Examples

LXMF offers flexibility to implement many different messaging schemes, ranging from human communication to machine control and sensor monitoring. Here's a few examples:

- A messaging system for passing short, simple messages between human users, akin to SMS can be implemented using only the __Content__ field, and leaving all other optional fields empty.

- For sending full-size mail, an email-like system can be implemented using the __Title__ and __Content__ fields to store "subject" and "body" parts of the message, and optionally the __Fields__ part can be used to store attachments or other metadata.

- Machine-control messages or sensor readings can be implemented using command structures embedded in the __Fields__ dictionary.

- Distributed discussion or news-groups, akin to USENET or similar systems, can be implemented using the relevant fields and LXMF Propagation Nodes. Broadcast bulletins can be implemented in a similar fashion.

## Propagation Nodes

LXM Propagation Nodes offer a way to store and forward messages to users or endpoints that are not directly reachable at the time of message emission. Propagation Nodes can also provide infrastructure for distributed bulletin, news or discussion boards.

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

LXMF uses encryption provided by [Reticulum](https://github.com/markqvist/reticulum), and thus uses end-to-end encryption by default. The delivery method of a message will influence which transport encryption scheme is used.

- A message can be delivered opportunistically, embedded in a single Reticulum packet. In this cases the message will be opportunistically routed through the network, and use _RSA-1024_ asymmetric encryption.

- If a message is delivered to the Reticulum GROUP destination type, the message will be transported using _AES-128_ encryption.

- If a message is delivered over a Reticulum link (which is the default method), the message will be encrypted with _ephemeral_ keys derived with _ECDH_ on the _SECP256R1_ curve. This mode offers Perfect Forward Secrecy.

## Wire Format & Overhead

Assuming the default Reticulum configuration, the binary wire-format is as follows:

- 10 bytes destination hash
- 10 bytes source hash
- 128 bytes RSA signature
- Remaining bytes of [msgpack](https://msgpack.org) payload data, in accordance with the structure defined above

The complete message overhead for LXMF is only 163 bytes, which in return gives you timestamped, digitally signed, infinitely extensible, end-to-end encrypted, zero-conf routed, minimal-infrastructure messaging that's easy to use and build applications with.

## Caveat Emptor

As with Reticulum, LXMF is alpha software, and should be considered experimental. While it has been built with cryptography best-practices very foremost in mind, it _has not_ been externally security audited, and there could very well be privacy-breaking bugs. If you want to help out, or help sponsor an audit, please do get in touch.

## Installation

If you want to try out LXMF, you can install it with pip:

```bash
pip3 install lxmf
```
