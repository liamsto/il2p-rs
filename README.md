# il2p-rs

**Current compatible IL2P version: v0.6**

A simple, dependency-free Rust implementation of IL2P for packet radio. Layer 2 only.

- Type 0 transparent and typed Type 1 frames
- Scrambling
- GF(256) Reed–Solomon encoding and correction
- 16-symbol payload parity
- Optional CRC-16/X-25 with Hamming (7,4)
- MSB streaming receive and one-bit sync tolerance

Please see the [IL2P specification](https://tarpn.net/t/il2p/il2p-specification_draft_v0-6.pdf) for technical information.

## Framing

```rust
use il2p::{Call, Control, Crc, Frame, Pid, UKind, decode, encode};

let frame = Frame::Translated {
    dst: Call::new("CQ", 0)?,
    src: Call::new("KK4HEJ", 15)?,
    control: Control::U {
        poll: false,
        command: false,
        kind: UKind::Ui(Pid::NONE),
    },
    data: Vec::new(),
};

let radio = encode(&frame, Crc::Hamming)?;
let recovered = decode(&radio, Crc::Hamming)?;
assert_eq!(recovered.frame, frame);
# Ok::<(), il2p::Error>(())
```

`encode` includes the three byte sync with no preamble. `encode_burst` tacks on any requested number of `0x55` alternating-bit bytes. `Receiver` accepts individual demodulated bits if byte alignment isn't known.

`Frame::Transparent` carries an opaque encapsulated frame (Type 0). Type 1 supports the modulo 8 control forms defined by the IL2P header.

Physical-layer implementations can feed into `Receiver` one bit at a time. Modulation, sample processing, synchronization, and any other Layer 1 things are outside the scope of this crate.

## Verification

A handful of tests are included for checking compatibility with the spec:

- checks the lib's packets against the draft v0.6 example packets
- Type 0 and Type 1 round trips
- validation of typed callsigns, protocol IDs, and controls
- correction of one header symbol and eight payload symbols
- rejection through the trailing CRC when a bad RS correction is possible
- one bit tolerant sync acquisition at arbitrary bit alignment
- Hamming bit correction and the standard CRC check value

Run it with:

```text
cargo test
```
