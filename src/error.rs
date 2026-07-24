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

use core::fmt;

/// Error from coding or decoding a packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The supplied IL2P frame fields are invalid.
    Frame,
    /// The IL2P payload exceeds 1023 bytes.
    TooLong,
    /// The input ends before the declared packet length.
    Truncated,
    /// The sync word is missing or invalid.
    Sync,
    /// The protected header can't be recovered or is invalid.
    Header,
    /// A payload RS block can't be recovered.
    Payload,
    /// The optional trailing CRC is missing, malformed, or doesn't match.
    Crc,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Frame => "invalid IL2P frame",
            Self::TooLong => "IL2P payload exceeds 1023 bytes",
            Self::Truncated => "truncated IL2P packet",
            Self::Sync => "IL2P sync word not found",
            Self::Header => "invalid IL2P header",
            Self::Payload => "unrecoverable IL2P payload",
            Self::Crc => "IL2P trailing CRC failed",
        })
    }
}

impl std::error::Error for Error {}
