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

After processing the label stack, the plugin forwards the remaining payload to
Zeek's IP analyzer so that normal connection and protocol analysis can
continue. The plugin assumes that the payload following the MPLS stack is an IP
packet.

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
zeek -NN Zeek::MPLSLogging
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
zeek -NN Zeek::MPLSLogging
```

## Log files

The plugin creates `mpls_header.log` and writes one record for every MPLS
packet it processes.

| Field | Type | Description |
| --- | --- | --- |
| `ts` | `time` | Packet timestamp. |
| `labels` | `vector[count]` | MPLS labels, in their order in the label stack. |
| `experimentals` | `vector[count]` | Three-bit Traffic Class/Experimental value for each label. |
| `bottom_of_stack` | `vector[bool]` | Bottom-of-stack flag for each label; the final label is normally `T`. |
| `time_to_live` | `vector[count]` | TTL value for each label. |

The values at the same position in each vector belong to the same MPLS label.
For example, index zero in all four vectors describes the outermost label.
After MPLS processing, logs such as `conn.log` may also contain records for the
encapsulated IP traffic.

## ICSNPP Packages

Additional ICSNPP protocol parsers are available from the
[ICSNPP project](https://github.com/cisagov/icsnpp).

## License

See [`LICENSE`](LICENSE) and [`NOTICE.txt`](NOTICE.txt).
