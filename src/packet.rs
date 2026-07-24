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

    /// Create an identifier from its four-bit code.
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
    /// Information frame. Type 1 info frames are always commands.
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

/// Data carried by a packet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Frame {
    /// Type 0 opaque encapsulation.
    Transparent(Vec<u8>),
    /// Type 1 translated control, addressing, and information.
    Translated {
        dst: Call,
        src: Call,
        control: Control,
        data: Vec<u8>,
    },
}
