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

use crate::Error;

const HAMMING: [u8; 16] = [
    0x00, 0x71, 0x62, 0x13, 0x54, 0x25, 0x36, 0x47, 0x38, 0x49, 0x5a, 0x2b, 0x6c, 0x1d, 0x0e, 0x7f,
];

/// CRC-16/X-25, returns complement.
pub fn crc16(data: &[u8]) -> u16 {
    let mut crc = 0xffffu16;
    for &byte in data {
        update(&mut crc, byte);
    }
    !crc
}

pub fn update(crc: &mut u16, byte: u8) {
    *crc ^= u16::from(byte);
    for _ in 0..8 {
        *crc = if *crc & 1 != 0 {
            (*crc >> 1) ^ 0x8408
        } else {
            *crc >> 1
        };
    }
}

pub fn encode(crc: u16) -> [u8; 4] {
    [
        HAMMING[usize::from((crc >> 12) & 0xf)],
        HAMMING[usize::from((crc >> 8) & 0xf)],
        HAMMING[usize::from((crc >> 4) & 0xf)],
        HAMMING[usize::from(crc & 0xf)],
    ]
}

pub fn decode(data: &[u8]) -> Result<u16, Error> {
    if data.len() < 4 {
        return Err(Error::Truncated);
    }

    let mut crc = 0u16;
    for &code in &data[..4] {
        if code & 0x80 != 0 {
            return Err(Error::Crc);
        }
        let mut nibble = 0;
        let mut distance = u32::MAX;
        for (i, &valid) in HAMMING.iter().enumerate() {
            let d = (code ^ valid).count_ones();
            if d < distance {
                distance = d;
                nibble = i as u16;
            }
        }
        crc = (crc << 4) | nibble;
    }
    Ok(crc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_value() {
        assert_eq!(crc16(b"123456789"), 0x906e);
    }

    #[test]
    fn hamming_fix() {
        let raw = b"packet";
        let mut encoded = encode(crc16(raw));
        encoded[0] ^= 0x20;
        encoded[1] ^= 0x01;
        encoded[2] ^= 0x40;
        encoded[3] ^= 0x08;
        assert_eq!(decode(&encoded), Ok(crc16(raw)));
    }
}
