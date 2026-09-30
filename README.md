# il2p-rs

**Compatible with IL2P v0.6**

A dependency-free Rust implementation of [IL2P](https://en.wikipedia.org/wiki/Improved_Layer_2_Protocol) for packet radio.

See the [IL2P specification](https://tarpn.net/t/il2p/il2p-specification_draft_v0-6.pdf) for technical information.

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

A handful of tests exist to check spec compatibility:

- Checks the lib's packets against the draft v0.6 example packets
- Type 0 and Type 1 round trips
- Typed callsigns, protocol IDs, and controls
- Correction of one header symbol and eight payload symbols
- Rejection through the trailing CRC when a bad RS correction is possible
- Sync acquisition w/ tolerance
- Hamming bit correction and the standard CRC check value

Run it with:

```text
cargo test
```
