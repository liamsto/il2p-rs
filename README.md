# il2p-rs

A dependency-free, pure Rust implementation of [IL2P draft v0.6](https://tarpn.net/t/il2p/il2p-specification_draft_v0-6.pdf) for packet radio.

Supports both transparent and translated AX.25 frames, RS correction, optional Hamming CRC, and bit stream reception.

The crate is `no_std` with `alloc`. The codec can run without per-packet allocations. Examples and details are mainly in the API documentation (`cargo doc --open`).

Run `cargo test` to check the implementation against the spec along with correction and other paths.
