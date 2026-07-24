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
    Error,
    packet::{Call, Control, Frame, Pid, SKind, UKind},
};

const HEADER_LEN: usize = 13;

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

const fn ax_pid(pid: Pid) -> u8 {
    const PID: [u8; 16] = [
        0xf0, 0xf0, 0x20, 0x01, 0x06, 0x07, 0x08, 0xf0, 0xf0, 0xf0, 0xf0, 0xcc, 0xcd, 0xce, 0xcf,
        0xf0,
    ];
    PID[pid.code() as usize]
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

pub(crate) fn encode(frame: &Frame, header: &mut [u8; HEADER_LEN]) -> Result<(), Error> {
    let Frame::Translated {
        dst,
        src,
        control,
        data,
    } = frame
    else {
        return Err(Error::Frame);
    };
    if data.len() > 1023 {
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

pub(crate) fn decode(header: &[u8; HEADER_LEN], data: Vec<u8>) -> Option<Frame> {
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

fn command(control: Control) -> bool {
    match control {
        Control::I { .. } => true,
        Control::S { command, .. } | Control::U { command, .. } => command,
    }
}

fn control_bytes(control: Control) -> (u8, Option<u8>) {
    match control {
        Control::I { nr, ns, poll, pid } => {
            (nr << 5 | u8::from(poll) << 4 | ns << 1, Some(ax_pid(pid)))
        }
        Control::S { nr, poll, kind, .. } => {
            (nr << 5 | u8::from(poll) << 4 | s_code(kind) << 2 | 1, None)
        }
        Control::U { poll, kind, .. } => {
            const CONTROL: [u8; 8] = [0x2f, 0x43, 0x0f, 0x63, 0x87, 0x03, 0xaf, 0xe3];
            let pid = match kind {
                UKind::Ui(pid) => Some(ax_pid(pid)),
                _ => None,
            };
            (CONTROL[u_code(kind) as usize] | u8::from(poll) << 4, pid)
        }
    }
}

pub(crate) fn gen_frame(frame: &Frame, mut push: impl FnMut(u8)) -> Result<(), Error> {
    let Frame::Translated {
        dst,
        src,
        control,
        data,
    } = frame
    else {
        return Err(Error::Frame);
    };
    let command = command(*control);

    for &ch in dst.name() {
        push(ch << 1);
    }
    push(0x60 | dst.ssid() << 1 | u8::from(command) << 7);
    for &ch in src.name() {
        push(ch << 1);
    }
    push(0x61 | src.ssid() << 1 | u8::from(!command) << 7);

    let (control, pid) = control_bytes(*control);
    push(control);
    if let Some(pid) = pid {
        push(pid);
    }
    for &byte in data {
        push(byte);
    }
    Ok(())
}
