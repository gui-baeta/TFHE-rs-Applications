use std::fmt::format;
use std::fs::OpenOptions;
use std::io::{Cursor, Write};
use std::time::Instant;

use tfhe::core_crypto::prelude::CastInto;
use tfhe::integer::public_key::standard::PublicKey;
use tfhe::integer::{IntegerCiphertext, ServerKey};
use tfhe::integer::{RadixCiphertext, RadixClientKey};
use tfhe::shortint::prelude::*;

use crate::keys::keys_gen;

pub fn operate() {
    // We generate a set of client/server keys, using the default parameters:
    let t_keygen = Instant::now();
    let (client_key, server_key) = keys_gen(false).unwrap();
    let t_keygen = t_keygen.elapsed().as_millis();
    let public_key = PublicKey::new(client_key.as_ref());
    println!("Keys generated");

    let man = 1;
    let woman = 0;
    let antecedent = 0;
    let smoking = 1;
    let diabetic = 0;
    let high_blood_pressure = 1;
    let age = 60;
    let hdl_cholesterol = 24;
    let weight = 76;
    let height = 180;
    let daily_physical_activity = 10;
    let alcohol_consumption = 3;

    let data = vec![
        man,
        woman,
        antecedent,
        smoking,
        diabetic,
        high_blood_pressure,
        age,
        hdl_cholesterol,
        weight,
        height,
        daily_physical_activity,
        alcohol_consumption,
    ];
    let clear_output = clear_compute(data);

    let t_encrypt = Instant::now();
    let man = client_key.encrypt(man);
    let woman = client_key.encrypt(woman);
    let antecedent = client_key.encrypt(antecedent);
    let smoking = client_key.encrypt(smoking);
    let diabetic = client_key.encrypt(diabetic);
    let high_blood_pressure = client_key.encrypt(high_blood_pressure);
    let age = client_key.encrypt(age);
    let hdl_cholesterol = client_key.encrypt(hdl_cholesterol);
    let weight = client_key.encrypt(weight);
    let height = client_key.encrypt(height);
    let daily_physical_activity = client_key.encrypt(daily_physical_activity);
    let alcohol_consumption = client_key.encrypt(alcohol_consumption);
    let t_encrypt = t_encrypt.elapsed().as_millis();

    let mut serialized_data = Vec::new();
    bincode::serialize_into(&mut serialized_data, &man).unwrap();
    bincode::serialize_into(&mut serialized_data, &woman).unwrap();
    bincode::serialize_into(&mut serialized_data, &antecedent).unwrap();
    bincode::serialize_into(&mut serialized_data, &smoking).unwrap();
    bincode::serialize_into(&mut serialized_data, &diabetic).unwrap();
    bincode::serialize_into(&mut serialized_data, &high_blood_pressure).unwrap();
    bincode::serialize_into(&mut serialized_data, &age).unwrap();
    bincode::serialize_into(&mut serialized_data, &hdl_cholesterol).unwrap();
    bincode::serialize_into(&mut serialized_data, &weight).unwrap();
    bincode::serialize_into(&mut serialized_data, &height).unwrap();
    bincode::serialize_into(&mut serialized_data, &daily_physical_activity).unwrap();
    bincode::serialize_into(&mut serialized_data, &alcohol_consumption).unwrap();

    let t_computation = std::time::Instant::now();
    let result = naive_compute(&serialized_data, &client_key, public_key, server_key);
    let t_computation = t_computation.elapsed().as_millis();

    // We use the client key to decrypt the output of the operation:
    let t_decrypt = Instant::now();
    let output = client_key.decrypt(&result);
    let t_decrypt = t_decrypt.elapsed().as_millis();
    let mut file = OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)
        .open("times.txt").unwrap();

    file.write_all(format!("{t_keygen},{t_encrypt},{t_computation},{t_decrypt}\n").as_bytes()).unwrap();
    assert_eq!(clear_output, output);
    println!("Result: {output}");
}

fn naive_compute(
    serialized_data: &[u8],
    _client_key: &RadixClientKey,
    public_key: PublicKey,
    server_key: ServerKey,
) -> RadixCiphertext {
    let mut serialized_data = Cursor::new(serialized_data);
    let mut man: RadixCiphertext = bincode::deserialize_from(&mut serialized_data).unwrap();
    let mut woman: RadixCiphertext = bincode::deserialize_from(&mut serialized_data).unwrap();
    let antecedent: RadixCiphertext = bincode::deserialize_from(&mut serialized_data).unwrap();
    let smoking: RadixCiphertext = bincode::deserialize_from(&mut serialized_data).unwrap();
    let diabetic: RadixCiphertext = bincode::deserialize_from(&mut serialized_data).unwrap();
    let high_blood_pressure: RadixCiphertext =
        bincode::deserialize_from(&mut serialized_data).unwrap();
    let age = bincode::deserialize_from(&mut serialized_data).unwrap();
    let hdl_cholesterol: RadixCiphertext = bincode::deserialize_from(&mut serialized_data).unwrap();
    let mut weight: RadixCiphertext = bincode::deserialize_from(&mut serialized_data).unwrap();
    let mut height: RadixCiphertext = bincode::deserialize_from(&mut serialized_data).unwrap();
    let daily_physical_activity: RadixCiphertext =
        bincode::deserialize_from(&mut serialized_data).unwrap();
    let alcohol_consumption: RadixCiphertext =
        bincode::deserialize_from(&mut serialized_data).unwrap();

    let mut cardio_risk = server_key.unchecked_small_scalar_mul(&man, 0u64);
    // let one = public_key.encrypt_radix(1u64, NUM_BLOCKS);
    // let fifty = public_key.encrypt_radix(50u64, NUM_BLOCKS);
    let zero = server_key.unchecked_small_scalar_mul(&man, 0u64);
    let one = server_key.unchecked_scalar_add(&zero, 1u64);
    let two = server_key.unchecked_scalar_add(&zero, 2u64);
    let three = server_key.unchecked_scalar_add(&zero, 3u64);
    let thirty = server_key.unchecked_scalar_add(&zero, 30u64);
    let forty = server_key.unchecked_scalar_add(&zero, 40u64);
    let fifty = server_key.unchecked_scalar_add(&zero, 50u64);
    let sixty = server_key.unchecked_scalar_add(&zero, 60u64);
    let mut ninety = server_key.unchecked_scalar_add(&zero, 90u64);

    // +1: if man && age > 50 years <=> man * (age > 50)
    server_key.unchecked_add_assign(
        &mut cardio_risk,
        &server_key.unchecked_mul_parallelized(
            &mut man,
            &server_key.unchecked_gt_parallelized(&age, &fifty),
        ),
    );

    // +1: if woman && age > 60 years <=> woman * age > 60
    server_key.unchecked_add_assign(
        &mut cardio_risk,
        &server_key.unchecked_mul_parallelized(
            &mut woman,
            &server_key.unchecked_gt_parallelized(&age, &sixty),
        ),
    );

    // +1: if antecedent
    server_key.unchecked_add_assign(&mut cardio_risk, &antecedent);

    // +1: if smoking
    server_key.unchecked_add_assign(&mut cardio_risk, &smoking);

    // +1: if diabetic
    server_key.unchecked_add_assign(&mut cardio_risk, &diabetic);

    // +1: if high blood pressure
    server_key.unchecked_add_assign(&mut cardio_risk, &high_blood_pressure);

    // +1: if HDL cholesterol < 40
    server_key.unchecked_add_assign(
        &mut cardio_risk,
        &server_key.unchecked_lt_parallelized(&hdl_cholesterol, &forty),
    );

    // +1: if weight > height - 90 <=> if weight + 90 > height
    // println!(
    //     "{},{}",
    //     _client_key.decrypt(&weight),
    //     _client_key.decrypt(&server_key.unchecked_scalar_sub(&height, 90u64))
    // );
    // println!(
    //     "{} {} {} {}",
    //     _client_key.decrypt_one_block(&height.blocks()[0]),
    //     _client_key.decrypt_one_block(&height.blocks()[1]),
    //     _client_key.decrypt_one_block(&height.blocks()[2]),
    //     _client_key.decrypt_one_block(&height.blocks()[3])
    // );
    // TODO See this here: (smart_gt_parallelized)
    server_key.unchecked_add_assign(
        &mut cardio_risk,
        &server_key.smart_gt_parallelized(
            &mut server_key.unchecked_scalar_add(&weight, 90),
            &mut height,
        ),
    );

    // +1: if daily physical activity < 30
    server_key.unchecked_add_assign(
        &mut cardio_risk,
        &server_key.unchecked_lt_parallelized(&daily_physical_activity, &thirty),
    );

    // +1: if man && alcohol cons. > 3 glasses/day
    server_key.unchecked_add_assign(
        &mut cardio_risk,
        &server_key.unchecked_mul_parallelized(
            &mut man,
            &server_key.unchecked_gt_parallelized(&alcohol_consumption, &three),
        ),
    );

    // if !man && alcohol cons. > 2 glasses/day
    server_key.unchecked_add_assign(
        &mut cardio_risk,
        &server_key.unchecked_mul_parallelized(
            &mut server_key.unchecked_eq_parallelized(&man, &zero),
            &server_key.unchecked_gt_parallelized(&alcohol_consumption, &two),
        ),
    );

    cardio_risk
}

fn clear_compute(data: Vec<u64>) -> u64 {
    let man = data[0];
    let woman = data[1];
    let antecedent = data[2];
    let smoking = data[3];
    let diabetic = data[4];
    let high_blood_pressure = data[5];
    let age = data[6];
    let hdl_cholesterol = data[7];
    let weight = data[8];
    let height = data[9];
    let daily_physical_activity = data[10];
    let alcohol_consumption = data[11];

    // +1: if man && age > 50 years
    let mut cardio_risk: u64 = if man == 1 && age > 50 { 1 } else { 0 };

    // +1: if woman && age > 60 years
    cardio_risk += if woman == 1 && age > 60 { 1 } else { 0 };

    // +1: if antecedent
    cardio_risk += if antecedent == 1 { 1 } else { 0 };

    // +1: if smoking
    cardio_risk += if smoking == 1 { 1 } else { 0 };

    // +1: if diabetic
    cardio_risk += if diabetic == 1 { 1 } else { 0 };

    // +1: if high blood pressure
    cardio_risk += if high_blood_pressure == 1 { 1 } else { 0 };

    // +1: if HDL cholesterol < 40
    cardio_risk += if hdl_cholesterol < 40 { 1 } else { 0 };

    // +1: if weight > height-90
    cardio_risk += if weight as i64 > (height as i64 - 90) {
        1
    } else {
        0
    };

    // +1: if daily physical activity < 30
    cardio_risk += if daily_physical_activity < 30 { 1 } else { 0 };

    // +1: if man && alcohol cons. > 3 glasses/day
    cardio_risk += if man == 1 && alcohol_consumption > 3 {
        1
    } else {
        0
    };

    // if !man && alcohol cons. > 2 glasses/day
    cardio_risk += if man == 0 && alcohol_consumption > 2 {
        1
    } else {
        0
    };

    cardio_risk
}
