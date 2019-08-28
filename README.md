# USBAnywhere

Several issues in the way that BMCs on Supermicro X9, X10 and X11 platforms implement virtual media, an ability to remotely connect a disk image as a virtual USB CD-ROM or floppy drive, can allow an attacker to easily connect to a server and virtually mount any USB device of their choosing to the server, remotely over any network including the Internet.

Our analysis of the authentication revealed the following issues:

* Plaintext Authentication

    While the Java application uses a unique session ID for authentication, the service also allows the client to use a plaintext username and password.

* Unencrypted network traffic

    Encryption is available but must be requested by the client. The Java application provided with the affected systems use this encryption for the initial authentication packet but then use unencrypted packets for all other traffic.

* Weak encryption

    When encryption is used, the payload is encrypted with RC4 using a fixed key compiled into the BMC firmware. This key is shared across all Supermicro BMCs. RC4 has multiple published cryptographic weaknesses and has been prohibited from use in TLS (RFC7465).

* Authentication Bypass (X10 and X11 platforms only)

    After a client has properly authenticated to the virtual media service and then disconnected, some of the service's internal state about that client is incorrectly left intact.  As the internal state is linked to the client's socket file descriptor number, a new client that happens to be assigned the same socket file descriptor number by the BMC's OS inherits this internal state.  In practice, this allows the new client to inherit the previous client's authorization even when the new client attempts to authenticate with incorrect credentials.

## Tools

* [wireshark-plugin](wireshark-plugin/)

  Wireshark Lua plugin that decodes the virtual media protocol

* [virt_media_tool](virt_media_tool/)

  Early Python tool for sending unauthenticated requests.

## Packet Captures

* [virtual_media_iso_attach_detach.pcapng](packet-captures/virtual_media_iso_attach_detach.pcapng)

  Capture of TCP/623 between Supermicro X10SLM-F and Java application served by its BMC.  Includes initial opening of Virtual Media window, attaching an ISO, detaching an ISO, and quitting the application.