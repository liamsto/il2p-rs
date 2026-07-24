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

const A0: u8 = 255;

const fn exp_table() -> [u8; 510] {
    let mut table = [0; 510];
    let mut value = 1u16;
    let mut i = 0;
    while i < 255 {
        table[i] = value as u8;
        value <<= 1;
        if value & 0x100 != 0 {
            value ^= 0x11d;
        }
        i += 1;
    }
    while i < 510 {
        table[i] = table[i - 255];
        i += 1;
    }
    table
}

const EXP: [u8; 510] = exp_table();

const fn log_table() -> [u8; 256] {
    let mut table = [A0; 256];
    let mut i = 0;
    while i < 255 {
        table[EXP[i] as usize] = i as u8;
        i += 1;
    }
    table
}

const LOG: [u8; 256] = log_table();

fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        0
    } else {
        EXP[usize::from(LOG[usize::from(a)]) + usize::from(LOG[usize::from(b)])]
    }
}

fn div(a: u8, b: u8) -> u8 {
    debug_assert_ne!(b, 0);
    if a == 0 {
        0
    } else {
        let n = i16::from(LOG[usize::from(a)]) - i16::from(LOG[usize::from(b)]);
        EXP[usize::from(n.rem_euclid(255) as u16)]
    }
}

const fn alpha(power: usize) -> u8 {
    EXP[power % 255]
}

fn generator(nsym: usize) -> [u8; 17] {
    let mut poly = [0; 17];
    poly[0] = 1;
    for root in 0..nsym {
        let len = root + 1;
        let a = alpha(root);
        for i in (0..len).rev() {
            poly[i + 1] ^= mul(poly[i], a);
        }
    }
    poly
}

pub fn encode(data: &[u8], parity: &mut [u8]) {
    debug_assert!(matches!(parity.len(), 2 | 4 | 6 | 8 | 16));
    debug_assert!(data.len() + parity.len() <= 255);

    parity.fill(0);
    let polynomial = generator(parity.len());
    for &byte in data {
        let feedback = byte ^ parity[0];
        parity.rotate_left(1);
        let last = parity.len() - 1;
        parity[last] = 0;
        if feedback != 0 {
            for i in 0..parity.len() {
                parity[i] ^= mul(polynomial[i + 1], feedback);
            }
        }
    }
}

fn syndromes(code: &[u8], nsym: usize) -> [u8; 16] {
    let mut out = [0; 16];
    for (root, syndrome) in out[..nsym].iter_mut().enumerate() {
        let a = alpha(root);
        for &byte in code {
            *syndrome = mul(*syndrome, a) ^ byte;
        }
    }
    out
}

fn locator(synd: &[u8], nsym: usize) -> ([u8; 17], usize) {
    let mut c = [0; 17];
    let mut b = [0; 17];
    c[0] = 1;
    b[0] = 1;

    let mut degree = 0;
    let mut shift = 1;
    let mut last = 1;

    for n in 0..nsym {
        let mut delta = synd[n];
        for i in 1..=degree {
            delta ^= mul(c[i], synd[n - i]);
        }

        if delta == 0 {
            shift += 1;
            continue;
        }

        let old = c;
        let scale = div(delta, last);
        for i in 0..=nsym - shift {
            c[i + shift] ^= mul(scale, b[i]);
        }

        if 2 * degree <= n {
            degree = n + 1 - degree;
            b = old;
            last = delta;
            shift = 1;
        } else {
            shift += 1;
        }
    }
    (c, degree)
}

fn eval_low(poly: &[u8], degree: usize, x: u8) -> u8 {
    let mut value = poly[degree];
    for i in (0..degree).rev() {
        value = mul(value, x) ^ poly[i];
    }
    value
}

fn positions(locator: &[u8], degree: usize, len: usize) -> ([usize; 8], usize) {
    let mut positions = [0; 8];
    let mut count = 0;
    for pos in 0..len {
        let power = len - 1 - pos;
        let inverse = alpha((255 - power % 255) % 255);
        if eval_low(locator, degree, inverse) == 0 {
            if count < positions.len() {
                positions[count] = pos;
            }
            count += 1;
        }
    }
    (positions, count)
}

fn magnitudes(synd: &[u8], positions: &[usize], count: usize, len: usize) -> Option<[u8; 8]> {
    let mut matrix = [[0u8; 9]; 8];
    for row in 0..count {
        for col in 0..count {
            let power = (len - 1 - positions[col]) * row;
            matrix[row][col] = alpha(power);
        }
        matrix[row][count] = synd[row];
    }

    for col in 0..count {
        let pivot = (col..count).find(|&row| matrix[row][col] != 0)?;
        matrix.swap(col, pivot);

        let scale = matrix[col][col];
        for item in &mut matrix[col][col..=count] {
            *item = div(*item, scale);
        }

        for row in 0..count {
            if row == col || matrix[row][col] == 0 {
                continue;
            }
            let scale = matrix[row][col];
            let pivot = matrix[col];
            for (value, &factor) in matrix[row][col..=count].iter_mut().zip(&pivot[col..=count]) {
                *value ^= mul(scale, factor);
            }
        }
    }

    let mut values = [0; 8];
    for i in 0..count {
        values[i] = matrix[i][count];
    }
    Some(values)
}

pub fn decode(code: &mut [u8], data_len: usize, nsym: usize) -> Option<usize> {
    debug_assert!(matches!(nsym, 2 | 4 | 6 | 8 | 16));
    debug_assert_eq!(code.len(), data_len + nsym);
    debug_assert!(code.len() <= 255);

    let synd = syndromes(code, nsym);
    if synd[..nsym].iter().all(|&value| value == 0) {
        return Some(0);
    }

    let (locator, degree) = locator(&synd, nsym);
    if degree == 0 || degree > nsym / 2 || degree > 8 {
        return None;
    }

    let (positions, count) = positions(&locator, degree, code.len());
    if count != degree || count > 8 {
        return None;
    }
    let values = magnitudes(&synd, &positions, count, code.len())?;
    for i in 0..count {
        code[positions[i]] ^= values[i];
    }

    let check = syndromes(code, nsym);
    check[..nsym]
        .iter()
        .all(|&value| value == 0)
        .then_some(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn codeword(nsym: usize) -> Vec<u8> {
        let data: Vec<_> = (0..239).map(|n| (n * 73 + 19) as u8).collect();
        let mut code = data;
        code.resize(code.len() + nsym, 0);
        let split = code.len() - nsym;
        let (data, parity) = code.split_at_mut(split);
        encode(data, parity);
        code
    }

    #[test]
    fn clean_codeword() {
        for nsym in [2, 4, 6, 8, 16] {
            let mut code = codeword(nsym);
            assert_eq!(decode(&mut code, 239, nsym), Some(0));
        }
    }

    #[test]
    fn corrects_capacity() {
        for nsym in [2, 4, 6, 8, 16] {
            let mut code = codeword(nsym);
            let original = code.clone();
            for n in 0..nsym / 2 {
                let pos = n * 29 + 3;
                code[pos] ^= 0xa5 ^ n as u8;
            }
            assert_eq!(decode(&mut code, 239, nsym), Some(nsym / 2));
            assert_eq!(code, original);
        }
    }

    #[test]
    fn excess_err() {
        let mut code = codeword(4);
        let original = code.clone();
        code[1] ^= 1;
        code[70] ^= 2;
        code[170] ^= 4;
        let result = decode(&mut code, 239, 4);
        assert!(result.is_none() || code != original);
    }
}
