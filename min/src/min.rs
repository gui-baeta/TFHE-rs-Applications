use tfhe::integer::public_key::standard::PublicKey;
use tfhe::integer::{IntegerCiphertext, ServerKey};
use tfhe::integer::{RadixCiphertext, RadixClientKey};
use tfhe::prelude::*;

use crate::keys;
use crate::keys::keys_gen;

struct MIN {}
impl MIN {
    fn operate(
        number_a: Vec<RadixCiphertext>,
        number_b: Vec<RadixCiphertext>,
        _client_key: &RadixClientKey,
        server_keys: &ServerKey,
    ) -> RadixCiphertext {
        let mut order: RadixCiphertext =
            server_keys.unchecked_small_scalar_mul_parallelized(&number_a[0], 0u64);
        let mut zero: RadixCiphertext = order.clone();
        let mut one: RadixCiphertext = server_keys.smart_scalar_add_parallelized(&mut zero, 1u64);
        // let compare_acc = server_keys.generate_accumulator_bivariate(LT::_compare);
        // let set_order_acc = server_keys.generate_accumulator_bivariate(LT::_set_lowest);
        for (digit_a, digit_b) in number_a.iter().zip(number_b.iter()) {
            let mut digit_a = digit_a.clone();
            let mut digit_b = digit_b.clone();
            let mut _order = server_keys.unchecked_add(
                &server_keys.unchecked_small_scalar_mul_parallelized(
                    &server_keys.smart_gt_parallelized(&mut digit_a, &mut digit_b),
                    2,
                ),
                &server_keys.unchecked_small_scalar_mul_parallelized(
                    &server_keys.smart_lt_parallelized(&mut digit_a, &mut digit_b),
                    1,
                ),
            );
            // TODO try with parameters for shortints of 4 bits message and 4 bits carry
            //  -> this is so each of the RadixCiphertext blocks (shortint) can be split
            //     and worked on using the below bivariate functions directly
            // let _order = server_keys.keyswitch_programmable_bootstrap_bivariate(
            //     &digit_a,
            //     digit_b,
            //     &compare_acc,
            // );
            println!(
                "//\nOrder: {}, Comparing ({},{}), _order: {}",
                _client_key.decrypt(&order),
                _client_key.decrypt(&digit_a),
                _client_key.decrypt(&digit_b),
                _client_key.decrypt(&_order)
            );
            let mut equal = server_keys.smart_eq_parallelized(&mut order, &mut zero);
            let mut not_equal_to_zero = server_keys.smart_bitxor_parallelized(&mut equal, &mut one);
            order = server_keys.smart_add_parallelized(
                &mut server_keys.unchecked_mul_parallelized(&mut not_equal_to_zero, &mut order),
                &mut server_keys.unchecked_mul_parallelized(&mut equal, &mut _order),
            );
            // TODO try with parameters for shortints of 4 bits message and 4 bits carry
            //  -> this is so each of the RadixCiphertext blocks (shortint) can be split
            //     and worked on using the below bivariate functions directly
            // order = server_keys.keyswitch_programmable_bootstrap_bivariate(
            //     &order,
            //     &_order,
            //     &set_order_acc,
            // );
            println!("Order: {}\n", _client_key.decrypt(&order));
        }
        order
    }

    fn _compare(a: u64, b: u64) -> u64 {
        if a > b {
            2
        } else if a < b {
            1
        } else {
            0
        }
    }

    fn _set_lowest(order: u64, _order: u64) -> u64 {
        if order != 0 {
            order
        } else {
            _order
        }
    }
}

pub fn operate() {
    let (client_key, server_keys) = keys_gen().unwrap();
    let public_key = PublicKey::new(client_key.as_ref());
    println!("Keys generated");

    let clear_a = vec![2, 5, 2, 0, 0, 0, 0, 1, 1];
    let clear_b = vec![2, 5, 2, 1, 0, 0, 0, 0, 0];

    let number_a = clear_a
        .iter()
        .copied()
        .map(|n| client_key.encrypt(n))
        .collect();

    let number_b = clear_b
        .iter()
        .copied()
        .map(|n| client_key.encrypt(n))
        .collect();

    let now = std::time::Instant::now();
    let result = client_key.decrypt(&MIN::operate(number_a, number_b, &client_key, &server_keys));
    let then = now.elapsed().as_secs_f32();

    println!("Operation duration: {then}, Result: {result}");
}
