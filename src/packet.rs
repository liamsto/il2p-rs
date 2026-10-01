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

use alloc::vec::Vec;

use crate::Error;

/// A callsign and four-bit secondary station identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Call {
    name: [u8; 6],
    ssid: u8,
}

impl Call {
    /// Create a callsign, padding names shorter than six characters with spaces.
    pub fn new(name: &str, ssid: u8) -> Result<Self, Error> {
        let bytes = name.as_bytes();
        if bytes.is_empty()
            || bytes.len() > 6
            || ssid > 0x0f
            || bytes.iter().any(|byte| !(0x20..=0x5f).contains(byte))
        {
            return Err(Error::Frame);
        }

        let mut padded = [b' '; 6];
        padded[..bytes.len()].copy_from_slice(bytes);
        Ok(Self { name: padded, ssid })
    }

    /// Return the six-byte, space-padded name.
    pub const fn name(&self) -> &[u8; 6] {
        &self.name
    }

    /// Return the secondary station identifier.
    pub const fn ssid(&self) -> u8 {
        self.ssid
    }

    pub(crate) const fn from_parts(name: [u8; 6], ssid: u8) -> Self {
        Self { name, ssid }
    }
}

/// Four-bit protocol identifier used in a translated IL2P header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pid(u8);

impl Pid {
    pub const LAYER3: Self = Self(0x2);
    pub const ISO_8208: Self = Self(0x3);
    pub const TCP_COMPRESSED: Self = Self(0x4);
    pub const TCP: Self = Self(0x5);
    pub const SEGMENT: Self = Self(0x6);
    pub const FUTURE_7: Self = Self(0x7);
    pub const FUTURE_8: Self = Self(0x8);
    pub const FUTURE_9: Self = Self(0x9);
    pub const FUTURE_A: Self = Self(0xa);
    pub const IP: Self = Self(0xb);
    pub const ARP: Self = Self(0xc);
    pub const FLEXNET: Self = Self(0xd);
    pub const THENET: Self = Self(0xe);
    pub const NONE: Self = Self(0xf);

    /// Create an identifier from its four-bit IL2P code.
    /// Use [`Self::from_ax25`] for an AX.25 PID byte such as `0xf0`.
    pub const fn new(code: u8) -> Result<Self, Error> {
        if code >= 2 && code <= 0x0f {
            Ok(Self(code))
        } else {
            Err(Error::Frame)
        }
    }

    /// Get the four bit code.
    pub const fn code(self) -> u8 {
        self.0
    }

    /// Translates AX.25 PID byte to an IL2P identifier.
    ///
    /// Layer 3 PIDs matching `yy01yyyy` or `yy10yyyy` become [`Self::LAYER3`].
    /// Their original bits can't be retained by a Type 1 header, so you must use transparent
    /// encapsulation when required.
    ///
    /// ```
    /// use il2p::Pid;
    /// assert_eq!(Pid::from_ax25(0xf0)?, Pid::NONE);
    /// assert_eq!(Pid::IP.to_ax25(), 0xcc);
    /// # Ok::<(), il2p::Error>(())
    /// ```
    pub const fn from_ax25(code: u8) -> Result<Self, Error> {
        match code {
            0x01 => Ok(Self::ISO_8208),
            0x06 => Ok(Self::TCP_COMPRESSED),
            0x07 => Ok(Self::TCP),
            0x08 => Ok(Self::SEGMENT),
            0xcc => Ok(Self::IP),
            0xcd => Ok(Self::ARP),
            0xce => Ok(Self::FLEXNET),
            0xcf => Ok(Self::THENET),
            0xf0 => Ok(Self::NONE),
            _ if code & 0x30 == 0x10 || code & 0x30 == 0x20 => Ok(Self::LAYER3),
            _ => Err(Error::Frame),
        }
    }

    /// Return the AX.25 PID byte. Layer 3 -> `0x20`, future -> `0xf0`.
    pub const fn to_ax25(self) -> u8 {
        const PID: [u8; 16] = [
            0xf0, 0xf0, 0x20, 0x01, 0x06, 0x07, 0x08, 0xf0, 0xf0, 0xf0, 0xf0, 0xcc, 0xcd, 0xce,
            0xcf, 0xf0,
        ];
        PID[self.0 as usize]
    }
}

/// Supervisory control opcode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SKind {
    Rr,
    Rnr,
    Rej,
    Srej,
}

/// Unnumbered control opcode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UKind {
    Sabm,
    Disc,
    Dm,
    Ua,
    Frmr,
    Ui(Pid),
    Xid,
    Test,
}

/// Control fields represented by a Type 1 header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Control {
    /// Information frame. Type 1 info frames are commands.
    I {
        nr: u8,
        ns: u8,
        poll: bool,
        pid: Pid,
    },
    /// Supervisory frame.
    S {
        nr: u8,
        poll: bool,
        command: bool,
        kind: SKind,
    },
    /// Unnumbered frame.
    U {
        poll: bool,
        command: bool,
        kind: UKind,
    },
}

/// Data carried by a packet. Can be owned (`Vec<u8>`) or borrowed
/// (`&[u8]` or `&mut [u8]`) since the codec accepts anything implementing `AsRef<[u8]>`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Frame<B = Vec<u8>> {
    /// Type 0 opaque encapsulation, containing 14–1023 bytes.
    Transparent(B),
    /// Type 1 translated control, addressing, and information.
    Translated {
        dst: Call,
        src: Call,
        control: Control,
        data: B,
    },
}

impl<B: AsRef<[u8]>> Frame<B> {
    /// Borrow the payload (the entire encapsulated frame for Type 0).
    pub fn data(&self) -> &[u8] {
        match self {
            Self::Transparent(data) | Self::Translated { data, .. } => data.as_ref(),
        }
    }
}
