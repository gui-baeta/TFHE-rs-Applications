mod keys;
mod min;

fn extract_digits(num: u64) -> Vec<u8> {
    let mut digits = Vec::<u8>::new();
    let mut n = num;
    while n > 0 {
        digits.push((n % 10) as u8);
        n /= 10;
    }
    digits.reverse();
    digits
}

pub const NUM_BLOCKS: usize = 2;

fn main() {
    min::operate()
}
