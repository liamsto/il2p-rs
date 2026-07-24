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

use crate::{Error, Frame, ax25, crc, rs, scramble};

pub const PREAMBLE: u8 = 0x55;
pub const SYNC_WORD: u32 = 0xf15e48;
pub const SYNC: [u8; 3] = [0xf1, 0x5e, 0x48];
pub const MAX_PAYLOAD: usize = 1023;
pub const MAX_PACKET: usize = 3 + 15 + MAX_PAYLOAD + 5 * 16 + 4;
const HEADER_LEN: usize = 13;
const HEADER_CODED: usize = 15;
const PARITY: usize = 16;

/// Trailing CRC mode.
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
pub struct Decoded {
    pub frame: Frame,
    /// Number of Reed-Solomon symbols repaired across all blocks.
    pub corrected: usize,
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

fn append_block(data: &[u8], output: &mut Vec<u8>) {
    let mut scrambled = [0u8; 239];
    scramble::scramble(data, &mut scrambled[..data.len()]);
    output.extend_from_slice(&scrambled[..data.len()]);

    let mut parity = [0u8; PARITY];
    rs::encode(&scrambled[..data.len()], &mut parity);
    output.extend_from_slice(&parity);
}

fn append_payload(payload: &[u8], output: &mut Vec<u8>) {
    let (blocks, small, large) = plan(payload.len());
    let mut offset = 0;
    for block in 0..blocks {
        let size = small + usize::from(block < large);
        append_block(&payload[offset..offset + size], output);
        offset += size;
    }
}

fn frame_crc(frame: &Frame) -> Result<u16, Error> {
    match frame {
        Frame::Transparent(data) => Ok(crc::crc16(data)),
        Frame::Translated { .. } => {
            let mut value = 0xffff;
            ax25::gen_frame(frame, |byte| crc::update(&mut value, byte))?;
            Ok(!value)
        }
    }
}

fn encode_parts(header: &[u8; HEADER_LEN], payload: &[u8], checksum: Option<u16>) -> Vec<u8> {
    let mut output = Vec::with_capacity(3 + HEADER_CODED + coded_payload_len(payload.len()) + 4);
    output.extend_from_slice(&SYNC);

    let mut scrambled = [0u8; HEADER_LEN];
    scramble::scramble(header, &mut scrambled);
    output.extend_from_slice(&scrambled);
    let mut parity = [0u8; 2];
    rs::encode(&scrambled, &mut parity);
    output.extend_from_slice(&parity);

    append_payload(payload, &mut output);
    if let Some(checksum) = checksum {
        output.extend_from_slice(&crc::encode(checksum));
    }
    output
}

/// Encode a IL2P frame.
///
/// The result starts with the three-byte sync word and has no preamble.
pub fn encode(frame: &Frame, mode: Crc) -> Result<Vec<u8>, Error> {
    let mut header = [0; HEADER_LEN];
    let payload = match frame {
        Frame::Transparent(data) => {
            if data.len() < 14 {
                return Err(Error::Frame);
            }
            if data.len() > MAX_PAYLOAD {
                return Err(Error::TooLong);
            }
            set_payload_count(&mut header, data.len());
            data.as_slice()
        }
        Frame::Translated { data, .. } => {
            ax25::encode(frame, &mut header)?;
            data.as_slice()
        }
    };
    let checksum = match mode {
        Crc::None => None,
        Crc::Hamming => Some(frame_crc(frame)?),
    };
    Ok(encode_parts(&header, payload, checksum))
}

/// Encode a transmit burst with `preamble` alternating-bit bytes.
pub fn encode_burst(frame: &Frame, mode: Crc, preamble: usize) -> Result<Vec<u8>, Error> {
    let packet = encode(frame, mode)?;
    let mut burst = Vec::with_capacity(preamble + packet.len());
    burst.resize(preamble, PREAMBLE);
    burst.extend_from_slice(&packet);
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
    if header[0] & 0x80 != 0 || header[12] & 0xc0 != 0 {
        return Err(Error::Header);
    }

    let count = payload_count(&header);
    let kind = if header[1] & 0x80 != 0 {
        Kind::Translated
    } else {
        if header.iter().any(|byte| byte & 0x7f != 0) || count < 14 {
            return Err(Error::Header);
        }
        Kind::Transparent
    };
    Ok((header, corrected, kind, count))
}

fn decode_payload(input: &[u8], size: usize, corrected: &mut usize) -> Result<Vec<u8>, Error> {
    let (blocks, small, large) = plan(size);
    let mut payload = Vec::with_capacity(size);
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

        let start = payload.len();
        payload.resize(start + data_len, 0);
        scramble::descramble(&coded[..data_len], &mut payload[start..]);
        offset = end;
    }
    Ok(payload)
}

fn cdecode(input: &[u8], mode: Crc) -> Result<Decoded, Error> {
    let (header, mut corrected, kind, count) = read_header(input)?;
    if count > MAX_PAYLOAD {
        return Err(Error::Header);
    }

    let payload_len = coded_payload_len(count);
    let packet_len = HEADER_CODED + payload_len + mode.len();
    if input.len() < packet_len {
        return Err(Error::Truncated);
    }

    let payload = decode_payload(
        &input[HEADER_CODED..HEADER_CODED + payload_len],
        count,
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

    Ok(Decoded { frame, corrected })
}

/// Decode the first byte-aligned IL2P packet in `input`.
///
/// Leading preamble bytes are accepted. For arbitrary bit alignment and the
/// specification's one-bit sync tolerance, use [`Receiver`].
pub fn decode(input: &[u8], mode: Crc) -> Result<Decoded, Error> {
    let start = input
        .windows(SYNC.len())
        .position(|word| word == SYNC)
        .ok_or(Error::Sync)?;
    cdecode(&input[start + SYNC.len()..], mode)
}

/// Streaming MSB-first packet receiver with one-bit sync-word tolerance.
pub struct Receiver {
    mode: Crc,
    shift: u32,
    seen: u8,
    collecting: bool,
    byte: u8,
    bits: u8,
    need: usize,
    data: Vec<u8>,
}

impl Receiver {
    pub fn new(mode: Crc) -> Self {
        Self {
            mode,
            shift: 0,
            seen: 0,
            collecting: false,
            byte: 0,
            bits: 0,
            need: 0,
            data: Vec::with_capacity(MAX_PACKET - 3),
        }
    }

    pub fn reset(&mut self) {
        self.shift = 0;
        self.seen = 0;
        self.collecting = false;
        self.byte = 0;
        self.bits = 0;
        self.need = 0;
        self.data.clear();
    }

    /// Supply one demodulated bit. A result is returned at packet completion.
    pub fn push(&mut self, bit: bool) -> Option<Result<Decoded, Error>> {
        if !self.collecting {
            self.shift = (self.shift << 1 | u32::from(bit)) & 0x00ff_ffff;
            self.seen = self.seen.saturating_add(1);
            if self.seen >= 24 && (self.shift ^ SYNC_WORD).count_ones() <= 1 {
                self.collecting = true;
                self.byte = 0;
                self.bits = 0;
                self.need = 0;
                self.data.clear();
            }
            return None;
        }

        self.byte = self.byte << 1 | u8::from(bit);
        self.bits += 1;
        if self.bits != 8 {
            return None;
        }

        self.data.push(self.byte);
        self.byte = 0;
        self.bits = 0;

        if self.data.len() == HEADER_CODED {
            let count = match read_header(&self.data) {
                Ok((_, _, _, count)) => count,
                Err(_) => {
                    self.reset();
                    return None;
                }
            };
            self.need = HEADER_CODED + coded_payload_len(count) + self.mode.len();
        }

        if self.need != 0 && self.data.len() == self.need {
            let result = cdecode(&self.data, self.mode);
            self.reset();
            return Some(result);
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
        }
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
