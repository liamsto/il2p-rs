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

use crate::{
    Error, MAX_PAYLOAD,
    packet::{Call, Control, Frame, Pid, SKind, UKind},
};

const HEADER_LEN: usize = 13;
const U_CONTROL: [u8; 8] = [0x2f, 0x43, 0x0f, 0x63, 0x87, 0x03, 0xaf, 0xe3];

const fn set_lane(header: &mut [u8; HEADER_LEN], bit: u8, end: usize, width: usize, value: u16) {
    let mut i = 0;
    while i < width {
        if value & (1 << i) != 0 {
            header[end - i] |= bit;
        }

        i += 1;
    }
}

fn get_lane(header: &[u8; HEADER_LEN], bit: u8, end: usize, width: usize) -> u16 {
    let mut value = 0;
    for &byte in &header[end + 1 - width..=end] {
        value = value << 1 | u16::from(byte & bit != 0);
    }
    value
}

const fn s_code(kind: SKind) -> u8 {
    match kind {
        SKind::Rr => 0,
        SKind::Rnr => 1,
        SKind::Rej => 2,
        SKind::Srej => 3,
    }
}

const fn s_kind(code: u8) -> SKind {
    match code {
        0 => SKind::Rr,
        1 => SKind::Rnr,
        2 => SKind::Rej,
        _ => SKind::Srej,
    }
}

const fn u_code(kind: UKind) -> u8 {
    match kind {
        UKind::Sabm => 0,
        UKind::Disc => 1,
        UKind::Dm => 2,
        UKind::Ua => 3,
        UKind::Frmr => 4,
        UKind::Ui(_) => 5,
        UKind::Xid => 6,
        UKind::Test => 7,
    }
}

const fn u_kind(code: u8, pid: Pid) -> UKind {
    match code {
        0 => UKind::Sabm,
        1 => UKind::Disc,
        2 => UKind::Dm,
        3 => UKind::Ua,
        4 => UKind::Frmr,
        5 => UKind::Ui(pid),
        6 => UKind::Xid,
        _ => UKind::Test,
    }
}

fn set_calls(header: &mut [u8; HEADER_LEN], dst: Call, src: Call) {
    for (byte, &ch) in header[..6].iter_mut().zip(dst.name()) {
        *byte = ch - 0x20;
    }
    for (byte, &ch) in header[6..12].iter_mut().zip(src.name()) {
        *byte = ch - 0x20;
    }
    header[12] = dst.ssid() << 4 | src.ssid();
}

fn get_call(data: &[u8]) -> [u8; 6] {
    let mut name = [0; 6];
    for (ch, &sixbit) in name.iter_mut().zip(data) {
        *ch = (sixbit & 0x3f) + 0x20;
    }
    name
}

pub(crate) fn encode<B: AsRef<[u8]>>(
    frame: &Frame<B>,
    header: &mut [u8; HEADER_LEN],
) -> Result<(), Error> {
    let Frame::Translated {
        dst,
        src,
        control,
        data,
    } = frame
    else {
        return Err(Error::Frame);
    };
    let data = data.as_ref();
    if data.len() > MAX_PAYLOAD {
        return Err(Error::TooLong);
    }

    *header = [0; HEADER_LEN];
    set_calls(header, *dst, *src);

    let (ui, pid, compact) = match *control {
        Control::I { nr, ns, poll, pid } => {
            if nr > 7 || ns > 7 {
                return Err(Error::Frame);
            }
            (false, pid.code(), u8::from(poll) << 6 | nr << 3 | ns)
        }
        Control::S {
            nr,
            poll,
            command,
            kind,
        } => {
            if nr > 7 {
                return Err(Error::Frame);
            }
            (
                false,
                0,
                u8::from(poll) << 6 | nr << 3 | u8::from(command) << 2 | s_code(kind),
            )
        }
        Control::U {
            poll,
            command,
            kind,
        } => {
            let opcode = u_code(kind);
            let pid = match kind {
                UKind::Ui(pid) => pid.code(),
                _ => 1,
            };
            (
                opcode == 5,
                pid,
                u8::from(poll) << 6 | opcode << 3 | u8::from(command) << 2,
            )
        }
    };

    if ui {
        header[0] |= 0x40;
    }
    set_lane(header, 0x40, 4, 4, u16::from(pid));
    set_lane(header, 0x40, 11, 7, u16::from(compact));
    header[1] |= 0x80;
    set_lane(header, 0x80, 11, 10, data.len() as u16);
    Ok(())
}

pub(crate) fn decode<B>(header: &[u8; HEADER_LEN], data: B) -> Option<Frame<B>> {
    let ui = header[0] & 0x40 != 0;
    let pid = get_lane(header, 0x40, 4, 4) as u8;
    let compact = get_lane(header, 0x40, 11, 7) as u8;
    let dst = Call::from_parts(get_call(&header[..6]), header[12] >> 4);
    let src = Call::from_parts(get_call(&header[6..12]), header[12] & 0x0f);

    let control = if pid == 0 {
        if ui {
            return None;
        }
        Control::S {
            nr: compact >> 3 & 7,
            poll: compact & 0x40 != 0,
            command: compact & 0x04 != 0,
            kind: s_kind(compact & 3),
        }
    } else if pid == 1 {
        if ui {
            return None;
        }
        let opcode = compact >> 3 & 7;
        if opcode == 5 {
            return None;
        }
        Control::U {
            poll: compact & 0x40 != 0,
            command: compact & 0x04 != 0,
            kind: u_kind(opcode, Pid::NONE),
        }
    } else {
        let pid = Pid::new(pid).ok()?;
        if ui {
            if compact >> 3 & 7 != 5 {
                return None;
            }
            Control::U {
                poll: compact & 0x40 != 0,
                command: compact & 0x04 != 0,
                kind: UKind::Ui(pid),
            }
        } else {
            Control::I {
                nr: compact >> 3 & 7,
                ns: compact & 7,
                poll: compact & 0x40 != 0,
                pid,
            }
        }
    };

    Some(Frame::Translated {
        dst,
        src,
        control,
        data,
    })
}

fn cmd(control: Control) -> bool {
    match control {
        Control::I { .. } => true,
        Control::S { command, .. } | Control::U { command, .. } => command,
    }
}

fn control_bytes(control: Control) -> Result<(u8, Option<u8>), Error> {
    Ok(match control {
        Control::I { nr, ns, poll, pid } => {
            if nr > 7 || ns > 7 {
                return Err(Error::Frame);
            }
            (nr << 5 | u8::from(poll) << 4 | ns << 1, Some(pid.to_ax25()))
        }
        Control::S { nr, poll, kind, .. } => {
            if nr > 7 {
                return Err(Error::Frame);
            }
            (nr << 5 | u8::from(poll) << 4 | s_code(kind) << 2 | 1, None)
        }
        Control::U { poll, kind, .. } => {
            let pid = match kind {
                UKind::Ui(pid) => Some(pid.to_ax25()),
                _ => None,
            };
            (U_CONTROL[u_code(kind) as usize] | u8::from(poll) << 4, pid)
        }
    })
}

pub(crate) fn gen_frame<B: AsRef<[u8]>>(
    frame: &Frame<B>,
    mut push: impl FnMut(u8),
) -> Result<(), Error> {
    let Frame::Translated {
        dst,
        src,
        control,
        data,
    } = frame
    else {
        return Err(Error::Frame);
    };
    let (ctl, pid) = control_bytes(*control)?;
    let command = cmd(*control);

    for &ch in dst.name() {
        push(ch << 1);
    }
    push(0x60 | dst.ssid() << 1 | u8::from(command) << 7);
    for &ch in src.name() {
        push(ch << 1);
    }
    push(0x61 | src.ssid() << 1 | u8::from(!command) << 7);

    push(ctl);
    if let Some(pid) = pid {
        push(pid);
    }
    for &byte in data.as_ref() {
        push(byte);
    }
    Ok(())
}

impl<'a> Frame<&'a [u8]> {
    /// Borrows an AX.25 frame, translating the header if all byte can
    /// be preserved. Repeater paths, unknown controls or PIDs, and other
    /// fields will use transparent encapsulation.
    ///
    /// Pass AX.25 bytes with no KISS command byte, HDLC flags, or
    /// FCS. Set `extended` for modulo-128 links (or when the link mode is unknown)
    /// to keep I/S frames transparent since control width can't be determined just
    /// by using the packet.
    ///
    /// U frames have the same layout in both modes.
    ///
    /// The caller is responsible for AX.25 validity, but checks are done for length and
    /// to see if it can be represented losslessly. Allocation/copy free..
    ///
    /// ```
    /// use il2p::Frame;
    /// // UI frame from KK4HEJ-15 to CQ, PID 0xf0.
    /// let raw = [0x86, 0xa2, 0x40, 0x40, 0x40, 0x40, 0x60,
    ///            0x96, 0x96, 0x68, 0x90, 0x8a, 0x94, 0xff, 0x03, 0xf0];
    /// let frame = Frame::from_ax25(&raw, false)?;
    /// assert!(matches!(frame, Frame::Translated { .. }));
    /// let mut out = [0; 16];
    /// assert_eq!(frame.write_ax25(&mut out)?, raw.len());
    /// assert_eq!(out, raw);
    /// # Ok::<(), il2p::Error>(())
    /// ```
    pub fn from_ax25(input: &'a [u8], extended: bool) -> Result<Self, Error> {
        if input.len() < 15 {
            return Err(Error::Truncated);
        }
        let frame = translate(input, extended).unwrap_or(Self::Transparent(input));
        if frame.data().len() > MAX_PAYLOAD {
            return Err(Error::TooLong);
        }
        Ok(frame)
    }
}

impl<B: AsRef<[u8]>> Frame<B> {
    /// Write AX.25 bytes.
    /// Returns the number of bytes written. `MAX_PAYLOAD + 16` bytes will be enough for any frame.
    /// Alloc free, a short buffer will return [`Error::Buffer`] and will not write.
    pub fn write_ax25(&self, output: &mut [u8]) -> Result<usize, Error> {
        let data = self.data();
        if data.len() > MAX_PAYLOAD {
            return Err(Error::TooLong);
        }
        let len = match self {
            Self::Transparent(_) => {
                if data.len() < 14 {
                    return Err(Error::Frame);
                }
                data.len()
            }
            Self::Translated { control, .. } => {
                let (_, pid) = control_bytes(*control)?;
                15 + usize::from(pid.is_some()) + data.len()
            }
        };
        let output = output.get_mut(..len).ok_or(Error::Buffer)?;
        if let Self::Transparent(_) = self {
            output.copy_from_slice(data);
        } else {
            let mut pos = 0;
            gen_frame(self, |byte| {
                output[pos] = byte;
                pos += 1;
            })?;
        }
        Ok(len)
    }
}

// Only translate if we can reconstruct byte for byte.
fn translate(input: &[u8], extended: bool) -> Option<Frame<&[u8]>> {
    if input[6] & 0x61 != 0x60
        || input[13] & 0x61 != 0x61
        || (input[6] ^ input[13]) & 0x80 == 0
        || input[..6]
            .iter()
            .chain(&input[7..13])
            .any(|&ch| ch & 1 != 0 || !(0x40..=0xbe).contains(&ch))
    {
        return None;
    }
    let mut dst = [0; 6];
    let mut src = [0; 6];
    for i in 0..6 {
        dst[i] = input[i] >> 1;
        src[i] = input[i + 7] >> 1;
    }
    let dst = Call::from_parts(dst, input[6] >> 1 & 0x0f);
    let src = Call::from_parts(src, input[13] >> 1 & 0x0f);
    let ctl = input[14];
    if extended && ctl & 3 != 3 {
        return None;
    }
    let poll = ctl & 0x10 != 0;
    let command = input[6] & 0x80 != 0;
    let has_pid = ctl & 1 == 0 || ctl & !0x10 == 0x03;
    let pid = if has_pid {
        let code = *input.get(15)?;
        let pid = Pid::from_ax25(code).ok()?;
        if pid.to_ax25() != code {
            return None;
        }
        pid
    } else {
        Pid::NONE
    };
    let control = if ctl & 1 == 0 {
        if !command {
            return None;
        }
        Control::I {
            nr: ctl >> 5,
            ns: ctl >> 1 & 7,
            poll,
            pid,
        }
    } else if ctl & 3 == 1 {
        Control::S {
            nr: ctl >> 5,
            poll,
            command,
            kind: s_kind(ctl >> 2 & 3),
        }
    } else {
        let opcode = U_CONTROL.iter().position(|&code| code == ctl & !0x10)?;
        Control::U {
            poll,
            command,
            kind: u_kind(opcode as u8, pid),
        }
    };
    Some(Frame::Translated {
        dst,
        src,
        control,
        data: &input[15 + usize::from(has_pid)..],
    })
}
