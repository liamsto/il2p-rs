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

const fn tx_bit(input: u16, state: &mut u16) -> u8 {
    let output = ((*state >> 4) ^ *state) & 1;
    *state = ((((input ^ *state) & 1) << 9) | (*state ^ ((*state & 1) << 4))) >> 1;
    output as u8
}

const fn rx_bit(input: u16, state: &mut u16) -> u8 {
    let output = (input ^ *state) & 1;
    *state = ((*state >> 1) | (input << 8)) ^ (input << 3);
    output as u8
}

pub fn scramble(input: &[u8], output: &mut [u8]) {
    debug_assert!(output.len() >= input.len());
    output[..input.len()].fill(0);

    let bits = input.len() * 8;
    let mut state = 0x00f;
    for i in 0..bits + 5 {
        let bit = if i < bits {
            u16::from((input[i / 8] >> (7 - i % 8)) & 1)
        } else {
            0
        };
        let bit = tx_bit(bit, &mut state);
        if i >= 5 && bit != 0 {
            let n = i - 5;
            output[n / 8] |= 1 << (7 - n % 8);
        }
    }
}

pub fn descramble(input: &[u8], output: &mut [u8]) {
    debug_assert!(output.len() >= input.len());
    output[..input.len()].fill(0);

    let mut state = 0x1f0;
    for i in 0..input.len() * 8 {
        let bit = u16::from((input[i / 8] >> (7 - i % 8)) & 1);
        if rx_bit(bit, &mut state) != 0 {
            output[i / 8] |= 1 << (7 - i % 8);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rt() {
        let input = [
            0x00, 0xff, 0x55, 0xaa, 0xf1, 0x5e, 0x48, 0x12, 0x34, 0x56, 0x78,
        ];
        let mut scrambled = [0; 11];
        let mut output = [0; 11];
        scramble(&input, &mut scrambled);
        descramble(&scrambled, &mut output);
        assert_eq!(output, input);
    }
}
