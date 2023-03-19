mod cardio_application;
mod keys;

fn _extract_digits(num: u64) -> Vec<u8> {
    let mut digits = Vec::<u8>::new();
    let mut n = num;
    while n > 0 {
        digits.push((n % 10) as u8);
        n /= 10;
    }
    digits.reverse();
    digits
}

fn main() {
    // lt::operate()
    cardio_application::operate()
}
