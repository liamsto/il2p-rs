// Copyright 2026 Liam Storgaard <liam-git@aqrx.net>

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use alloc::{vec, vec::Vec};

use crate::{Error, Frame, ax25, crc, rs, scramble};

pub const PREAMBLE: u8 = 0x55;
pub const SYNC_WORD: u32 = 0xf15e48;
pub const SYNC: [u8; 3] = [0xf1, 0x5e, 0x48];
pub const MAX_PAYLOAD: usize = 1023;
pub const MAX_PACKET: usize = 3 + 15 + MAX_PAYLOAD + 5 * 16 + 4;
const HEADER_LEN: usize = 13;
const HEADER_CODED: usize = 15;
const PARITY: usize = 16;

/// Trailing CRC mode. Both stations must use the same mode, and must figure this out before transmitting. IL2P does not indicate which is used.
///
/// The default, [`Crc::None`], does not check a trailing CRC even if one is present. [`Crc::Hamming`] requires and checks all four bytes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Crc {
    /// Original IL2P framing without the four trailing codewords.
    #[default]
    None,
    /// CRC-16/X-25 as four Hamming (7,4) codewords.
    Hamming,
}

impl Crc {
    const fn len(self) -> usize {
        match self {
            Self::None => 0,
            Self::Hamming => 4,
        }
    }
}

/// A recovered IL2P frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Decoded<B = Vec<u8>> {
    pub frame: Frame<B>,
    /// Number of RS symbols repaired across all blocks.
    pub corrected: usize,
    /// Bytes through the end of the packet, including sync and any bytes skipped
    /// by the byte decoder. With [`Receiver`], this will just be the byte length
    /// since bits preceding sync are excluded.
    pub consumed: usize,
}

#[derive(Clone, Copy)]
enum Kind {
    Transparent,
    Translated,
}

const fn plan(size: usize) -> (usize, usize, usize) {
    if size == 0 {
        return (0, 0, 0);
    }
    let blocks = size.div_ceil(239);
    let small = size / blocks;
    let large = size - blocks * small;
    (blocks, small, large)
}

const fn coded_payload_len(size: usize) -> usize {
    if size == 0 {
        0
    } else {
        size + size.div_ceil(239) * PARITY
    }
}

fn payload_count(header: &[u8; HEADER_LEN]) -> usize {
    let mut count = 0;
    for byte in &header[2..12] {
        count = count << 1 | usize::from(byte >> 7);
    }
    count
}

fn set_payload_count(header: &mut [u8; HEADER_LEN], count: usize) {
    for bit in 0..10 {
        if count & (1 << bit) != 0 {
            header[11 - bit] |= 0x80;
        }
    }
}

fn frame_crc<B: AsRef<[u8]>>(frame: &Frame<B>) -> Result<u16, Error> {
    match frame {
        Frame::Transparent(data) => Ok(crc::crc16(data.as_ref())),
        Frame::Translated { .. } => {
            let mut value = 0xffff;
            ax25::gen_frame(frame, |byte| crc::update(&mut value, byte))?;
            Ok(!value)
        }
    }
}

fn encode_parts(
    header: &[u8; HEADER_LEN],
    payload: &[u8],
    checksum: Option<u16>,
    output: &mut [u8],
) {
    output[..3].copy_from_slice(&SYNC);
    let (data, output) = output[3..].split_at_mut(HEADER_LEN);
    scramble::scramble(header, data);
    let (parity, mut output) = output.split_at_mut(2);
    rs::encode(data, parity);

    let (blocks, small, large) = plan(payload.len());
    let mut offset = 0;
    for block in 0..blocks {
        let size = small + usize::from(block < large);
        let (coded, rest) = output.split_at_mut(size + PARITY);
        let (data, parity) = coded.split_at_mut(size);
        scramble::scramble(&payload[offset..offset + size], data);
        rs::encode(data, parity);
        output = rest;
        offset += size;
    }
    if let Some(checksum) = checksum {
        output[..4].copy_from_slice(&crc::encode(checksum));
    }
}

fn packet_len(size: usize, mode: Crc) -> Result<usize, Error> {
    if size > MAX_PAYLOAD {
        return Err(Error::TooLong);
    }
    Ok(3 + HEADER_CODED + coded_payload_len(size) + mode.len())
}

/// Encode an IL2P frame into a buffer. Returns number of bytes written.
///
/// The result starts with sync and has no preamble. Transmit each byte MSB first.
/// [`MAX_PACKET`] bytes is enough for any frame. Alloc free, errors will leave output alone.
///
/// ```
/// use il2p::{Crc, Frame, MAX_PACKET, PREAMBLE, encode_into};
/// let frame = Frame::Transparent(b"example packet".as_slice());
/// // Don't forget space for eight preamble bytes.
/// let mut burst = [0; 8 + MAX_PACKET];
/// burst[..8].fill(PREAMBLE);
/// let len = 8 + encode_into(&frame, Crc::Hamming, &mut burst[8..])?;
/// let tx = &burst[..len];
/// assert_eq!(&tx[..8], &[PREAMBLE; 8]);
/// # Ok::<(), il2p::Error>(())
/// ```
pub fn encode_into<B: AsRef<[u8]>>(
    frame: &Frame<B>,
    mode: Crc,
    output: &mut [u8],
) -> Result<usize, Error> {
    let len = packet_len(frame.data().len(), mode)?;
    let mut header = [0; HEADER_LEN];
    let payload = match frame {
        Frame::Transparent(data) => {
            let data = data.as_ref();
            if data.len() < 14 {
                return Err(Error::Frame);
            }
            set_payload_count(&mut header, data.len());
            data
        }
        Frame::Translated { data, .. } => {
            ax25::encode(frame, &mut header)?;
            data.as_ref()
        }
    };
    let checksum = match mode {
        Crc::None => None,
        Crc::Hamming => Some(frame_crc(frame)?),
    };
    let output = output.get_mut(..len).ok_or(Error::Buffer)?;
    encode_parts(&header, payload, checksum, output);
    Ok(len)
}

/// Encodes an IL2P frame into an owned buffer, starting with sync and no preamble.
/// See [`encode_into`] for alloc free encoding.
///
/// ```
/// use il2p::{Call, Control, Crc, Frame, Pid, UKind, decode, encode};
/// let frame = Frame::Translated {
///     dst: Call::new("CQ", 0)?,
///     src: Call::new("KK4HEJ", 15)?,
///     control: Control::U {
///         poll: false,
///         command: false,
///         kind: UKind::Ui(Pid::NONE),
///     },
///     data: Vec::new(),
/// };
/// let radio = encode(&frame, Crc::Hamming)?;
/// assert_eq!(decode(&radio, Crc::Hamming)?.frame, frame);
/// # Ok::<(), il2p::Error>(())
/// ```
pub fn encode<B: AsRef<[u8]>>(frame: &Frame<B>, mode: Crc) -> Result<Vec<u8>, Error> {
    let mut output = vec![0; packet_len(frame.data().len(), mode)?];
    encode_into(frame, mode, &mut output)?;
    Ok(output)
}

/// Encode a transmit burst with `preamble` alternating-bit (`0x55`) bytes.
/// Requires alloc for one buffer each for the preamble and packet. Later packets in the same burst can use zero preamble.
pub fn encode_burst<B: AsRef<[u8]>>(
    frame: &Frame<B>,
    mode: Crc,
    preamble: usize,
) -> Result<Vec<u8>, Error> {
    let len = preamble
        .checked_add(packet_len(frame.data().len(), mode)?)
        .filter(|&len| len <= isize::MAX as usize)
        .ok_or(Error::TooLong)?;
    let mut burst = vec![0; len];
    encode_into(frame, mode, &mut burst[preamble..])?;
    burst[..preamble].fill(PREAMBLE);
    Ok(burst)
}

fn read_header(input: &[u8]) -> Result<([u8; HEADER_LEN], usize, Kind, usize), Error> {
    if input.len() < HEADER_CODED {
        return Err(Error::Truncated);
    }

    let mut coded = [0u8; HEADER_CODED];
    coded.copy_from_slice(&input[..HEADER_CODED]);
    let corrected = rs::decode(&mut coded, HEADER_LEN, 2).ok_or(Error::Header)?;

    let mut header = [0u8; HEADER_LEN];
    scramble::descramble(&coded[..HEADER_LEN], &mut header);
    if header[0] & 0x80 != 0 {
        return Err(Error::Header);
    }

    let count = payload_count(&header);
    let kind = if header[1] & 0x80 != 0 {
        Kind::Translated
    } else {
        if header[..12].iter().any(|byte| byte & 0x7f != 0) || header[12] != 0 || count < 14 {
            return Err(Error::Header);
        }
        Kind::Transparent
    };
    Ok((header, corrected, kind, count))
}

fn decode_payload(
    input: &[u8],
    mut payload: &mut [u8],
    corrected: &mut usize,
) -> Result<(), Error> {
    let (blocks, small, large) = plan(payload.len());
    let mut offset = 0;

    for block in 0..blocks {
        let data_len = small + usize::from(block < large);
        let coded_len = data_len + PARITY;
        let end = offset + coded_len;
        let source = input.get(offset..end).ok_or(Error::Truncated)?;

        let mut coded = [0u8; 255];
        coded[..coded_len].copy_from_slice(source);
        *corrected +=
            rs::decode(&mut coded[..coded_len], data_len, PARITY).ok_or(Error::Payload)?;

        let (data, rest) = payload.split_at_mut(data_len);
        scramble::descramble(&coded[..data_len], data);
        payload = rest;
        offset = end;
    }
    Ok(())
}

// Obtain exactly the declared payload space after checking the input length.
// Owned and borrowed callers share the decoder without an intermediate copy.
fn cdecode<B: AsRef<[u8]> + AsMut<[u8]>>(
    input: &[u8],
    mode: Crc,
    buf: impl FnOnce(usize) -> Result<B, Error>,
) -> Result<Decoded<B>, Error> {
    let (header, mut corrected, kind, count) = read_header(input)?;

    let payload_len = coded_payload_len(count);
    let packet_len = HEADER_CODED + payload_len + mode.len();
    if input.len() < packet_len {
        return Err(Error::Truncated);
    }

    let mut payload = buf(count)?;
    decode_payload(
        &input[HEADER_CODED..HEADER_CODED + payload_len],
        payload.as_mut(),
        &mut corrected,
    )?;
    let frame = match kind {
        Kind::Transparent => Frame::Transparent(payload),
        Kind::Translated => ax25::decode(&header, payload).ok_or(Error::Header)?,
    };

    if mode == Crc::Hamming {
        let received = crc::decode(&input[HEADER_CODED + payload_len..packet_len])?;
        if received != frame_crc(&frame)? {
            return Err(Error::Crc);
        }
    }

    Ok(Decoded {
        frame,
        corrected,
        consumed: 3 + packet_len,
    })
}

/// Decode the first byte-aligned IL2P packet into an owned payload.
///
/// Leading bytes are skipped until the first exact sync word. A bad packet at
/// that sync returns an error; this function does not scan past it. On success,
/// [`Decoded::consumed`] includes the skipped bytes and packet, so the next call
/// can start at `&input[decoded.consumed..]`. Trailing bytes are left unexamined.
/// For arbitrary bit alignment and one-bit sync tolerance, use [`Receiver`].
/// The CRC mode must match the transmitter; see [`Crc`].
///
/// ```
/// use il2p::{Crc, Frame, decode, encode_burst};
/// let frame = Frame::Transparent(b"example packet".as_slice());
/// let first = encode_burst(&frame, Crc::Hamming, 8)?;
/// let second = encode_burst(&frame, Crc::Hamming, 0)?;
/// let mut stream = first.clone();
/// stream.extend_from_slice(&second);
/// let a = decode(&stream, Crc::Hamming)?;
/// assert_eq!(a.consumed, first.len());
/// let b = decode(&stream[a.consumed..], Crc::Hamming)?;
/// assert_eq!(b.consumed, second.len());
/// # Ok::<(), il2p::Error>(())
/// ```
pub fn decode(input: &[u8], mode: Crc) -> Result<Decoded, Error> {
    let start = input
        .windows(SYNC.len())
        .position(|word| word == SYNC)
        .ok_or(Error::Sync)?;
    let mut decoded = cdecode(&input[start + SYNC.len()..], mode, |len| Ok(vec![0; len]))?;
    decoded.consumed += start;
    Ok(decoded)
}

/// Decode into caller-owned payload storage, without allocating.
///
/// Uses the same sync search and consumed-byte accounting as [`decode`]. The
/// returned frame borrows the used portion of `output`; [`MAX_PAYLOAD`] bytes
/// suffice. A short buffer returns [`Error::Buffer`] before decoding payload
/// blocks. Other decoding errors may leave partial data in `output`.
///
/// ```
/// use il2p::{Crc, Frame, MAX_PACKET, MAX_PAYLOAD, decode_into, encode_into};
/// let frame = Frame::Transparent(b"example packet".as_slice());
/// let mut packet = [0; MAX_PACKET];
/// let len = encode_into(&frame, Crc::Hamming, &mut packet)?;
/// let mut data = [0; MAX_PAYLOAD];
/// let decoded = decode_into(&packet[..len], Crc::Hamming, &mut data)?;
/// assert_eq!(decoded.frame.data(), frame.data());
/// assert_eq!(decoded.consumed, len);
/// # Ok::<(), il2p::Error>(())
/// ```
pub fn decode_into<'a>(
    input: &[u8],
    mode: Crc,
    output: &'a mut [u8],
) -> Result<Decoded<&'a mut [u8]>, Error> {
    let start = input
        .windows(SYNC.len())
        .position(|word| word == SYNC)
        .ok_or(Error::Sync)?;
    let mut decoded = cdecode(&input[start + SYNC.len()..], mode, |len| {
        output.get_mut(..len).ok_or(Error::Buffer)
    })?;
    decoded.consumed += start;
    Ok(decoded)
}

/// Streaming MSB-first packet receiver with one-bit sync-word tolerance.
/// Stores the coded packet in a fixed buffer of about 1.1 KiB. Construction and
/// [`Self::push_into`] do not allocate. [`Self::push`] allocates a recovered payload.
/// The default disables CRC checking; use [`Self::new`] to select a mode explicitly.
pub struct Receiver {
    mode: Crc,
    shift: u32,
    seen: u8,
    collecting: bool,
    byte: u8,
    bits: u8,
    need: usize,
    len: usize,
    data: [u8; MAX_PACKET - 3],
}

impl Receiver {
    /// Create a receiver with the same CRC mode as the transmitting station.
    pub const fn new(mode: Crc) -> Self {
        Self {
            mode,
            shift: 0,
            seen: 0,
            collecting: false,
            byte: 0,
            bits: 0,
            need: 0,
            len: 0,
            data: [0; MAX_PACKET - 3],
        }
    }

    /// Discard any partial packet and restart sync acquisition. Call on a
    /// sample/bit-stream discontinuity; use [`Self::finish`] to report truncation.
    pub fn reset(&mut self) {
        self.shift = 0;
        self.seen = 0;
        self.collecting = false;
        self.byte = 0;
        self.bits = 0;
        self.need = 0;
        self.len = 0;
    }

    /// Whether sync has been acquired and a header or payload is incomplete.
    pub const fn pending(&self) -> bool {
        self.collecting
    }

    /// End a burst or interrupted stream and restart sync acquisition.
    /// Returns [`Error::Truncated`] if a packet was pending, otherwise `Ok(())`.
    /// Call at a known carrier/burst boundary, not between chunks of a continuous
    /// stream. Without this, the next burst could be consumed as a missing payload.
    pub fn finish(&mut self) -> Result<(), Error> {
        let pending = self.collecting;
        self.reset();
        if pending {
            Err(Error::Truncated)
        } else {
            Ok(())
        }
    }

    /// Supply one demodulated bit, returning an owned frame on completion.
    /// Header rejection returns `Some(Err(Error::Header))`; payload/CRC errors
    /// are also reported. Every result restarts sync acquisition automatically.
    /// Header errors can represent false sync matches in noise.
    /// See [`Self::push_into`] for bit order, polarity, and burst handling.
    pub fn push(&mut self, bit: bool) -> Option<Result<Decoded, Error>> {
        self.collect(bit).map(|result| {
            result.and_then(|len| cdecode(&self.data[..len], self.mode, |len| Ok(vec![0; len])))
        })
    }

    /// Supply one demodulated bit and decode into caller-owned payload storage.
    ///
    /// Return and error semantics match [`Self::push`]. The result borrows only
    /// `output`; use [`MAX_PAYLOAD`] bytes to accommodate any packet. A short
    /// buffer reports [`Error::Buffer`] at packet completion and the packet is
    /// discarded. Payload/CRC errors may leave partial output.
    ///
    /// Input bits must be MSB first, before any AX.25 NRZI decoding or bit
    /// unstuffing. `true` is an IL2P one (Bell 202 mark for AFSK). Correct an
    /// inverted demodulator's polarity in the caller; inversion is not detected.
    ///
    /// ```
    /// use il2p::{Crc, Frame, MAX_PACKET, MAX_PAYLOAD, Receiver, encode_into};
    /// let frame = Frame::Transparent(b"example packet".as_slice());
    /// let mut packet = [0; MAX_PACKET];
    /// let len = encode_into(&frame, Crc::Hamming, &mut packet)?;
    /// let mut rx = Receiver::new(Crc::Hamming);
    /// let mut payload = [0; MAX_PAYLOAD];
    /// let inverted = false; // Set for an inverted demodulator output.
    /// let mut received = 0;
    /// let mut rejected = 0;
    /// for &byte in &packet[..len] {
    ///     for bit in (0..8).rev() {
    ///         let demod = byte & (1 << bit) != 0;
    ///         match rx.push_into(demod ^ inverted, &mut payload) {
    ///             Some(Ok(decoded)) => {
    ///                 assert_eq!(decoded.frame.data(), frame.data());
    ///                 received += 1;
    ///             }
    ///             Some(Err(_)) => rejected += 1,
    ///             None => {}
    ///         }
    ///     }
    /// }
    /// // At carrier/burst end; a partial packet would return Error::Truncated.
    /// rx.finish()?;
    /// assert_eq!((received, rejected), (1, 0));
    /// # Ok::<(), il2p::Error>(())
    /// ```
    pub fn push_into<'a>(
        &mut self,
        bit: bool,
        output: &'a mut [u8],
    ) -> Option<Result<Decoded<&'a mut [u8]>, Error>> {
        self.collect(bit).map(|result| {
            result.and_then(|len| {
                cdecode(&self.data[..len], self.mode, |len| {
                    output.get_mut(..len).ok_or(Error::Buffer)
                })
            })
        })
    }

    fn collect(&mut self, bit: bool) -> Option<Result<usize, Error>> {
        if !self.collecting {
            self.shift = (self.shift << 1 | u32::from(bit)) & 0x00ff_ffff;
            self.seen = self.seen.saturating_add(1);
            if self.seen >= 24 && (self.shift ^ SYNC_WORD).count_ones() <= 1 {
                self.collecting = true;
                self.byte = 0;
                self.bits = 0;
                self.need = 0;
                self.len = 0;
            }
            return None;
        }

        self.byte = self.byte << 1 | u8::from(bit);
        self.bits += 1;
        if self.bits != 8 {
            return None;
        }

        self.data[self.len] = self.byte;
        self.len += 1;
        self.byte = 0;
        self.bits = 0;

        if self.len == HEADER_CODED {
            let count = match read_header(&self.data[..self.len]) {
                Ok((_, _, _, count)) => count,
                Err(err) => {
                    self.reset();
                    return Some(Err(err));
                }
            };
            self.need = HEADER_CODED + coded_payload_len(count) + self.mode.len();
        }

        if self.need != 0 && self.len == self.need {
            let len = self.len;
            self.reset();
            return Some(Ok(len));
        }
        None
    }
}

impl Default for Receiver {
    fn default() -> Self {
        Self::new(Crc::None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Call, Control, Pid, SKind, UKind};

    const S_RAW: &[u8] = &[
        0x96, 0x82, 0x64, 0x88, 0x8a, 0xae, 0xe4, 0x96, 0x96, 0x68, 0x90, 0x8a, 0x94, 0x6f, 0x81,
    ];
    const S_CODED: &[u8] = &[
        0x26, 0x57, 0x4d, 0x57, 0xf1, 0xd2, 0xa8, 0xf0, 0x6a, 0xf2, 0x7b, 0xad, 0x23, 0xbd, 0xc0,
        0x7f, 0x00, 0x1d, 0x2b,
    ];

    const U_RAW: &[u8] = &[
        0x86, 0xa2, 0x40, 0x40, 0x40, 0x40, 0x60, 0x96, 0x96, 0x68, 0x90, 0x8a, 0x94, 0xff, 0x03,
        0xf0,
    ];
    const U_CODED: &[u8] = &[
        0x6a, 0xea, 0x9c, 0xc2, 0x01, 0x11, 0xfc, 0x14, 0x1f, 0xda, 0x6e, 0xf2, 0x53, 0x91, 0xbd,
        0x47, 0x6c, 0x54, 0x54,
    ];

    const I_RAW: &[u8] = &[
        0x96, 0x82, 0x64, 0x88, 0x8a, 0xae, 0xe4, 0x96, 0x96, 0x68, 0x90, 0x8a, 0x94, 0x65, 0xb8,
        0xcf, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    ];
    const I_CODED: &[u8] = &[
        0x26, 0x13, 0x6d, 0x02, 0x8c, 0xfe, 0xfb, 0xe8, 0xaa, 0x94, 0x2d, 0x6a, 0x34, 0x43, 0x35,
        0x3c, 0x69, 0x9f, 0x0c, 0x75, 0x5a, 0x38, 0xa1, 0x7f, 0xa5, 0xda, 0xd8, 0xf6, 0xea, 0x57,
        0x37, 0x3d, 0xb1, 0x2a, 0xb0, 0xde, 0x44, 0xa8, 0x20, 0xd0, 0x1d, 0x5a, 0x2b, 0x38,
    ];

    fn call(name: &str, ssid: u8) -> Call {
        Call::new(name, ssid).unwrap()
    }

    fn s_frame() -> Frame {
        Frame::Translated {
            dst: call("KA2DEW", 2),
            src: call("KK4HEJ", 7),
            control: Control::S {
                nr: 4,
                poll: false,
                command: true,
                kind: SKind::Rr,
            },
            data: Vec::new(),
        }
    }

    fn u_frame() -> Frame {
        Frame::Translated {
            dst: call("CQ", 0),
            src: call("KK4HEJ", 15),
            control: Control::U {
                poll: false,
                command: false,
                kind: UKind::Ui(Pid::NONE),
            },
            data: Vec::new(),
        }
    }

    fn i_frame() -> Frame {
        Frame::Translated {
            dst: call("KA2DEW", 2),
            src: call("KK4HEJ", 2),
            control: Control::I {
                nr: 5,
                ns: 4,
                poll: true,
                pid: Pid::THENET,
            },
            data: (b'0'..=b'8').collect(),
        }
    }

    fn check_vector(frame: Frame, raw: &[u8], coded: &[u8]) {
        let packet = encode(&frame, Crc::Hamming).unwrap();
        assert_eq!(&packet[3..], coded);
        assert_eq!(decode(&packet, Crc::None).unwrap().frame, frame);
        assert_eq!(crc::decode(&coded[coded.len() - 4..]), Ok(crc::crc16(raw)));
        assert_eq!(decode(&packet, Crc::Hamming).unwrap().frame, frame);

        let borrowed = Frame::from_ax25(raw, false).unwrap();
        assert!(matches!(borrowed, Frame::Translated { .. }));
        let mut output = [0; MAX_PACKET];
        let len = encode_into(&borrowed, Crc::Hamming, &mut output).unwrap();
        assert_eq!(&output[..len], packet);
        let mut payload = [0; MAX_PAYLOAD];
        let decoded = decode_into(&output[..len], Crc::Hamming, &mut payload).unwrap();
        assert_eq!(decoded.consumed, len);
        let mut ax25 = [0; MAX_PAYLOAD + 16];
        let len = decoded.frame.write_ax25(&mut ax25).unwrap();
        assert_eq!(&ax25[..len], raw);
    }

    #[test]
    fn spec_vecs() {
        check_vector(s_frame(), S_RAW, S_CODED);
        check_vector(u_frame(), U_RAW, U_CODED);
        check_vector(i_frame(), I_RAW, I_CODED);
    }

    #[test]
    fn transparent_round_trip() {
        let frame = Frame::Transparent(I_RAW.to_vec());
        let packet = encode(&frame, Crc::Hamming).unwrap();
        assert_eq!(decode(&packet, Crc::Hamming).unwrap().frame, frame);
    }

    #[test]
    fn payload_boundary() {
        for size in [0, 1, 238, 239, 240, 478, 479, 1023] {
            let mut frame = u_frame();
            let Frame::Translated { data, .. } = &mut frame else {
                unreachable!()
            };
            data.extend((0..size).map(|index| (index * 43 + 7) as u8));
            let packet = encode(&frame, Crc::Hamming).unwrap();
            assert_eq!(decode(&packet, Crc::Hamming).unwrap().frame, frame);

            for mode in [Crc::None, Crc::Hamming] {
                let packet = encode(&frame, mode).unwrap();
                let mut coded = [0xa5; MAX_PACKET + 1];
                let len = encode_into(&frame, mode, &mut coded[..packet.len()]).unwrap();
                assert_eq!(&coded[..len], packet);
                assert_eq!(coded[len], 0xa5);
                let mut output = [0xa5; MAX_PAYLOAD + 1];
                let decoded = decode_into(&coded[..len], mode, &mut output[..size]).unwrap();
                assert_eq!(decoded.frame.data(), frame.data());
                assert_eq!(decoded.consumed, len);
                assert_eq!(output[size], 0xa5);
                if size != 0 {
                    assert_eq!(
                        decode_into(&coded[..len], mode, &mut output[..size - 1]),
                        Err(Error::Buffer)
                    );
                }
                coded.fill(0xa5);
                assert_eq!(
                    encode_into(&frame, mode, &mut coded[..len - 1]),
                    Err(Error::Buffer)
                );
                assert!(coded.iter().all(|&byte| byte == 0xa5));
            }
        }
    }

    #[test]
    fn ax25_round_trip() {
        let mut raw = I_RAW.to_vec();
        let mut coded = [0; MAX_PACKET];
        let mut payload = [0; MAX_PAYLOAD];
        let mut output = [0; MAX_PAYLOAD + 16];
        // Exercise address flags/SSIDs, controls, and PIDs, including fallbacks.
        for field in [6, 13, 14, 15] {
            for code in 0..=255 {
                raw.copy_from_slice(I_RAW);
                raw[field] = code;
                for extended in [false, true] {
                    let frame = Frame::from_ax25(&raw, extended).unwrap();
                    let len = encode_into(&frame, Crc::Hamming, &mut coded).unwrap();
                    let decoded = decode_into(&coded[..len], Crc::Hamming, &mut payload).unwrap();
                    let len = decoded.frame.write_ax25(&mut output).unwrap();
                    assert_eq!(&output[..len], raw);
                }
            }
        }
    }

    #[test]
    fn ax25_fallback() {
        let mut cases = Vec::new();
        for (index, byte) in [
            (0, 0xc0),
            (0, 0x87),
            (6, 0x20),
            (6, 0xe0),
            (14, 0x6f),
            (15, 0xff),
            (15, 0x10),
        ] {
            let mut raw = U_RAW.to_vec();
            raw[index] = byte;
            cases.push(raw);
        }
        // Repeater address between source and control.
        let mut routed = U_RAW[..14].to_vec();
        routed[13] &= !1;
        routed.extend_from_slice(&U_RAW[7..14]);
        routed.extend_from_slice(&U_RAW[14..]);
        cases.push(routed);
        let mut response = I_RAW.to_vec();
        response[6] ^= 0x80;
        response[13] ^= 0x80;
        cases.push(response);
        for raw in cases {
            let frame = Frame::from_ax25(&raw, false).unwrap();
            assert_eq!(frame, Frame::Transparent(raw.as_slice()));
            let mut output = [0; MAX_PAYLOAD];
            let len = frame.write_ax25(&mut output).unwrap();
            assert_eq!(&output[..len], raw);
        }
        assert!(matches!(
            Frame::from_ax25(I_RAW, true),
            Ok(Frame::Transparent(_))
        ));
        assert!(matches!(
            Frame::from_ax25(S_RAW, true),
            Ok(Frame::Transparent(_))
        ));
        assert!(matches!(
            Frame::from_ax25(U_RAW, true),
            Ok(Frame::Translated { .. })
        ));
    }

    #[test]
    fn ax25_limits() {
        let mut raw = U_RAW.to_vec();
        raw.resize(16 + MAX_PAYLOAD, 0x42);
        let frame = Frame::from_ax25(&raw, false).unwrap();
        assert_eq!(frame.data().len(), MAX_PAYLOAD);
        let mut output = [0xa5; MAX_PAYLOAD + 16];
        assert_eq!(
            frame.write_ax25(&mut output[..raw.len() - 1]),
            Err(Error::Buffer)
        );
        assert!(output.iter().all(|&byte| byte == 0xa5));
        assert_eq!(frame.write_ax25(&mut output), Ok(raw.len()));
        assert_eq!(output.as_slice(), raw);
        raw.push(0);
        assert_eq!(Frame::from_ax25(&raw, false), Err(Error::TooLong));
        assert_eq!(Frame::from_ax25(&raw[..14], false), Err(Error::Truncated));
        raw[15] = 0xff; // Unsupported PID requires Type 0, whose limit includes the header.
        assert!(Frame::from_ax25(&raw[..MAX_PAYLOAD], false).is_ok());
        assert_eq!(
            Frame::from_ax25(&raw[..MAX_PAYLOAD + 1], false),
            Err(Error::TooLong)
        );
        assert_eq!(
            encode_burst(&u_frame(), Crc::None, usize::MAX),
            Err(Error::TooLong)
        );
    }

    #[test]
    fn consumed_bytes() {
        for mode in [Crc::None, Crc::Hamming] {
            let a = encode_burst(&i_frame(), mode, 8).unwrap();
            let b = encode_burst(&u_frame(), mode, 0).unwrap();
            let mut stream = vec![0, 0xff];
            stream.extend_from_slice(&a);
            stream.extend_from_slice(&b);
            stream.push(0xaa);
            let first = decode(&stream, mode).unwrap();
            assert_eq!(first.frame, i_frame());
            assert_eq!(first.consumed, 2 + a.len());
            let mut output = [0; MAX_PAYLOAD];
            let borrowed = decode_into(&stream, mode, &mut output).unwrap();
            assert_eq!(borrowed.consumed, first.consumed);
            assert_eq!(borrowed.frame.data(), first.frame.data());
            let second = decode(&stream[first.consumed..], mode).unwrap();
            assert_eq!(second.frame, u_frame());
            assert_eq!(second.consumed, b.len());
            assert_eq!(stream[first.consumed + second.consumed..], [0xaa]);
        }
    }

    fn bits(bytes: &[u8]) -> impl Iterator<Item = bool> + '_ {
        bytes
            .iter()
            .flat_map(|byte| (0..8).rev().map(move |bit| byte & (1 << bit) != 0))
    }

    #[test]
    fn receiver_boundaries() {
        for mode in [Crc::None, Crc::Hamming] {
            let packet = encode(&i_frame(), mode).unwrap();
            let mut rx = Receiver::new(mode);
            for cut in [
                0,
                1,
                23,
                24,
                25,
                143,
                144,
                145,
                packet.len() * 8 - 1,
                packet.len() * 8,
            ] {
                for bit in bits(&packet).take(cut) {
                    if let Some(result) = rx.push(bit) {
                        assert_eq!(result.unwrap().frame, i_frame());
                    }
                }
                let pending = cut >= 24 && cut < packet.len() * 8;
                assert_eq!(rx.pending(), pending);
                assert_eq!(
                    rx.finish(),
                    if pending {
                        Err(Error::Truncated)
                    } else {
                        Ok(())
                    }
                );
                assert!(!rx.pending());
                let frames: Vec<_> = bits(&packet).filter_map(|bit| rx.push(bit)).collect();
                assert_eq!(frames.len(), 1);
                assert_eq!(frames[0].as_ref().unwrap().frame, i_frame());
                assert_eq!(frames[0].as_ref().unwrap().consumed, packet.len());
                assert_eq!(rx.finish(), Ok(()));
            }
        }
    }

    #[test]
    fn receiver_errors() {
        let packet = encode(&i_frame(), Crc::Hamming).unwrap();
        let mut bad = packet[..18].to_vec();
        bad[3] ^= 0x80;
        bad[4] ^= 0x40;
        let mut rx = Receiver::new(Crc::Hamming);
        let errors: Vec<_> = bits(&bad).filter_map(|bit| rx.push(bit)).collect();
        assert_eq!(errors, [Err(Error::Header)]);
        assert!(!rx.pending());

        let mut output = [0; MAX_PAYLOAD];
        let mut results = 0;
        for bit in bits(&packet) {
            if let Some(result) = rx.push_into(bit, &mut []) {
                assert_eq!(result, Err(Error::Buffer));
                results += 1;
            }
        }
        assert_eq!(results, 1);
        for bit in bits(&packet) {
            if let Some(result) = rx.push_into(bit, &mut output) {
                let decoded = result.unwrap();
                assert_eq!(decoded.frame.data(), i_frame().data());
                assert_eq!(decoded.consumed, packet.len());
                results += 1;
            }
        }
        assert_eq!(results, 2);

        let mut bad = packet;
        *bad.last_mut().unwrap() |= 0x80;
        let errors: Vec<_> = bits(&bad).filter_map(|bit| rx.push(bit)).collect();
        assert_eq!(errors, [Err(Error::Crc)]);
        assert_eq!(rx.finish(), Ok(()));
        let mut unchecked = Receiver::default();
        let frames: Vec<_> = bits(&bad).filter_map(|bit| unchecked.push(bit)).collect();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].as_ref().unwrap().frame, i_frame());
    }

    #[test]
    fn fec_works() {
        let frame = i_frame();
        let mut packet = encode(&frame, Crc::Hamming).unwrap();
        packet[5] ^= 0x40;
        for index in [19, 22, 25, 28, 31, 34, 38, 42] {
            packet[index] ^= index as u8;
        }
        let decoded = decode(&packet, Crc::Hamming).unwrap();
        assert_eq!(decoded.frame, frame);
        assert_eq!(decoded.corrected, 9);
    }

    #[test]
    fn crc_no_excess() {
        let mut packet = encode(&i_frame(), Crc::Hamming).unwrap();
        for (n, index) in [18, 20, 22, 24, 26, 28, 30, 32, 34].into_iter().enumerate() {
            packet[index] ^= 0x81 + n as u8;
        }
        assert!(matches!(
            decode(&packet, Crc::Hamming),
            Err(Error::Payload | Error::Crc)
        ));
    }

    #[test]
    fn max_transparent_pkt() {
        let data: Vec<_> = (0..MAX_PAYLOAD)
            .map(|index| (index * 71 + 29) as u8)
            .collect();
        let frame = Frame::Transparent(data);
        let packet = encode(&frame, Crc::Hamming).unwrap();
        assert_eq!(packet.len(), MAX_PACKET);
        assert_eq!(decode(&packet, Crc::Hamming).unwrap().frame, frame);

        let mut damaged = packet;
        let mut offset = 3 + HEADER_CODED;
        for (block, size) in [205, 205, 205, 204, 204].into_iter().enumerate() {
            for error in 0..8 {
                damaged[offset + error * 27] ^= 0x31 + block as u8 + error as u8;
            }
            offset += size + PARITY;
        }
        let decoded = decode(&damaged, Crc::Hamming).unwrap();
        assert_eq!(decoded.frame, frame);
        assert_eq!(decoded.corrected, 40);

        let mut rx = Receiver::new(Crc::Hamming);
        let mut payload = [0; MAX_PAYLOAD];
        let mut received = 0;
        for bit in bits(&damaged) {
            if let Some(result) = rx.push_into(bit, &mut payload) {
                let decoded = result.unwrap();
                assert_eq!(decoded.frame.data(), frame.data());
                assert_eq!(decoded.corrected, 40);
                assert_eq!(decoded.consumed, MAX_PACKET);
                received += 1;
            }
        }
        assert_eq!(received, 1);
        assert_eq!(rx.finish(), Ok(()));
    }

    #[test]
    fn invalid_fields() {
        assert_eq!(Call::new("", 0), Err(Error::Frame));
        assert_eq!(Call::new("TOO-LONG", 0), Err(Error::Frame));
        assert_eq!(Pid::new(1), Err(Error::Frame));
        assert_eq!(
            encode(&Frame::Transparent(vec![0; 13]), Crc::None),
            Err(Error::Frame)
        );

        let mut frame = i_frame();
        let Frame::Translated { control, .. } = &mut frame else {
            unreachable!()
        };
        *control = Control::I {
            nr: 8,
            ns: 0,
            poll: false,
            pid: Pid::NONE,
        };
        assert_eq!(encode(&frame, Crc::None), Err(Error::Frame));
    }

    #[test]
    fn translated_controls() {
        let mut controls = Vec::new();
        for code in 2..=0x0f {
            let pid = Pid::new(code).unwrap();
            controls.push(Control::I {
                nr: code & 7,
                ns: code >> 1 & 7,
                poll: code & 1 != 0,
                pid,
            });
            controls.push(Control::U {
                poll: code & 1 != 0,
                command: code & 2 != 0,
                kind: UKind::Ui(pid),
            });
        }
        for kind in [SKind::Rr, SKind::Rnr, SKind::Rej, SKind::Srej] {
            controls.push(Control::S {
                nr: 6,
                poll: true,
                command: false,
                kind,
            });
        }
        for kind in [
            UKind::Sabm,
            UKind::Disc,
            UKind::Dm,
            UKind::Ua,
            UKind::Frmr,
            UKind::Xid,
            UKind::Test,
        ] {
            controls.push(Control::U {
                poll: true,
                command: true,
                kind,
            });
        }

        for control in controls {
            let frame = Frame::Translated {
                dst: call("N0CALL", 1),
                src: call("KK4HEJ", 2),
                control,
                data: vec![0x12, 0x34, 0x56],
            };
            let packet = encode(&frame, Crc::Hamming).unwrap();
            assert_eq!(decode(&packet, Crc::Hamming).unwrap().frame, frame);
        }
    }

    #[test]
    fn sync_tolerance() {
        let frame = u_frame();
        let mut packet = encode(&frame, Crc::Hamming).unwrap();
        packet[1] ^= 0x08;

        let mut receiver = Receiver::new(Crc::Hamming);
        let mut result = None;
        for bit in [true, false, true] {
            assert!(receiver.push(bit).is_none());
        }
        for byte in packet {
            for bit in (0..8).rev() {
                if let Some(packet) = receiver.push(byte & (1 << bit) != 0) {
                    result = Some(packet);
                }
            }
        }
        assert_eq!(result.unwrap().unwrap().frame, frame);
    }
}
