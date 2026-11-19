# Build Status

[![build-and-test](https://github.com/idaholab/icsnpp-mpls/actions/workflows/build.yml/badge.svg)](https://github.com/idaholab/icsnpp-mpls/actions/workflows/build.yml)

# ICSNPP-MPLS

ICSNPP-MPLS adds MPLS label-stack parsing and logging to Zeek's suite of
Industrial Control Systems network protocol parsers. It improves network
visibility by decoding MPLS headers that would otherwise remain unlogged.

## Overview

This Zeek plugin adds logging for MPLS label stacks. It registers a packet
analyzer for MPLS unicast traffic (EtherType `0x8847`) carried directly over
Ethernet or inside a VLAN, extracts every label in the MPLS stack, and writes
the decoded fields to `mpls_header.log`.

After processing the label stack, the plugin works out what the payload is and
forwards it so that normal connection and protocol analysis can continue. See
[Payload detection](#payload-detection).

## Payload detection

RFC 3032 doesn't encode the protocol that follows the bottom label, so the
plugin checks these in order:

| What follows the bottom label | Logged as | Forwarded to |
| --- | --- | --- |
| Bottom label 0 or 2 (IPv4/IPv6 explicit NULL) | `ipv4` / `ipv6` | IP |
| First nibble `0001`: associated channel header (RFC 4385, RFC 5586), channel type 0x0021 or 0x0057 | `ach-ipv4` / `ach-ipv6` | IP, after the 4-byte header |
| Associated channel header with any other channel type (BFD, MPLS-TP OAM) | `ach` | Nothing |
| A self-consistent IPv4 or IPv6 header | `ipv4` / `ipv6` | IP |
| First nibble `0000` and an Ethernet frame after a 4-byte control word (RFC 4385) | `ethernet+cw` | Ethernet, after the control word |
| An Ethernet frame | `ethernet` | Ethernet |
| None of the above | `unknown` | `PacketAnalyzer::MPLSLOGGER::default_analyzer` (IP) |

When a payload starting with `0000` could be either a control word followed by
Ethernet or an Ethernet frame whose destination MAC starts with a zero nibble
(IEC 61850 GOOSE and SV multicast addresses start with `01:0c:cd`), the plugin
checks the EtherType or 802.3 length field under both readings and picks the
one that fits. A tie goes to the control word.

Forwarding uses the dispatch identifiers `0x0800` and `0x86DD` (IP) and
`0x6558` (Ethernet), registered against `PacketAnalyzer::ANALYZER_MPLSLOGGER`
in `scripts/analyzer.zeek`. A site can remap them with
`PacketAnalyzer::register_packet_analyzer`.

Redef `MPLSLogger::detect_payload` to `F` to send every payload to
`PacketAnalyzer::MPLSLOGGER::default_analyzer`, which is how stock Zeek
handles MPLS. Pseudowire traffic then raises `unknown_ip_version` weirds and is
not analyzed.

When an Ethernet pseudowire's payload produces a connection, that connection's
`orig_l2_addr` and `resp_l2_addr` in `conn.log` are the customer MACs from the
inner frame, while `mpls_header.log` keeps the provider routers' MACs from the
outer frame.

## Installation (via zkg)

Install the package directly from GitHub:

```console
zkg install https://github.com/idaholab/icsnpp-mpls
```

If Zeek and `zkg` use a system-wide installation prefix, the command may need
to be run with the permissions required by that installation. Restart any
running Zeek processes after installation.

Confirm that Zeek can find the native plugin:

```console
zeek -NN ICSNPP::MPLS
```

From a repository checkout, process the included MPLS capture and inspect the
decoded label stack:

```console
zeek -C -r testing/Traces/mpls_large_label_vlan.pcap local
zeek-cut labels traffic_class time_to_live packets < mpls_header.log
```

The capture contains one MPLS packet and produces:

```text
299776,16    0,5 64,255    1
```

To update or remove it later:

```console
zkg upgrade icsnpp-mpls
zkg uninstall icsnpp-mpls
```

## Installation (via git clone)

The manual build requires Zeek development files, `zeek-config`, a C++
compiler, and CMake 3.15 or newer. Ensure that the `zeek-config` belonging to
the Zeek installation you intend to use is available on `PATH`.

```console
git clone https://github.com/idaholab/icsnpp-mpls.git
cd icsnpp-mpls
./configure
cmake --build build
cmake --build build --target install
```

The final installation command may require `sudo` when installing into a
system-owned Zeek prefix:

```console
sudo cmake --build build --target install
```

Confirm the installation with:

```console
zeek -NN ICSNPP::MPLS
```

## Log files

The plugin creates `mpls_header.log`. By default, packets that share the same
carried connection, direction, link-layer addresses, VLANs, label stack, and
payload type are summarized into one record per `MPLSLogger::summary_interval`
(default one minute). Redef `MPLSLogger::log_every_packet` to `T` to write one record per
packet instead.

| Field | Type | Description |
| --- | --- | --- |
| `ts` | `time` | Timestamp of the first packet in the record. |
| `uid` | `string` | UID of the connection carried in the MPLS payload, when the payload produced one. |
| `id` | `conn_id` | 4-tuple of that connection. |
| `is_orig` | `bool` | `T` if the packet(s) traveled from that connection's originator. |
| `src_l2_addr` | `string` | Source MAC of the frame carrying the label stack. |
| `dst_l2_addr` | `string` | Destination MAC of the frame carrying the label stack. |
| `vlan` | `int` | Outer 802.1Q VLAN ID, if present. |
| `inner_vlan` | `int` | Inner 802.1Q VLAN ID (QinQ), if present. |
| `labels` | `vector[count]` | MPLS labels, in their order in the label stack. |
| `traffic_class` | `vector[count]` | Three-bit Traffic Class value for each label (the EXP field before RFC 5462). |
| `time_to_live` | `vector[count]` | TTL value for each label. |
| `payload` | `string` | What followed the bottom label (see [Payload detection](#payload-detection)). Unset when `MPLSLogger::detect_payload` is `F`. |
| `packets` | `count` | Number of packets summarized by the record. |
| `last_ts` | `time` | Timestamp of the last packet in the record. |

The values at the same position in each vector belong to the same MPLS label.
For example, index zero in all three vectors describes the outermost label.
The last label in each record is the bottom of the stack. Stacks that end
before a bottom-of-stack entry raise a `truncated_link_header` weird and are
not logged.

The MAC addresses belong to the label-switching routers on the monitored link,
not to the end hosts of the carried connection.

Only the first `MPLSLogger::max_label_stack_depth` (default 16) label stack
entries are recorded. Deeper stacks still get parsed so the payload is found,
and they raise an `excessive_mpls_label_stack` weird.

## ICSNPP Packages

Additional ICSNPP protocol parsers are available from the
[ICSNPP project](https://github.com/cisagov/icsnpp).

## License

See [`LICENSE`](LICENSE) and [`NOTICE.txt`](NOTICE.txt).
