use crate::keys::keys_gen;
use std::io::Cursor;
use tfhe::shortint::parameters::{PARAM_MESSAGE_8_CARRY_0};
use tfhe::shortint::prelude::*;

pub fn operate() {
    // We generate a set of client/server keys, using the default parameters:
    let (client_key, server_key) = keys_gen(PARAM_MESSAGE_8_CARRY_0).unwrap();
    println!("Keys generated");

    let man = 1;
    let woman = 0;
    let antecedent = 0;
    let smoking = 1;
    let diabetic = 0;
    let high_blood_pressure = 1;
    let age = 60;
    let hdl_cholesterol = 24;
    let weight = 70;
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

    let now = std::time::Instant::now();
    let result = naive_compute(&serialized_data, server_key);
    let then = now.elapsed().as_secs_f32();

    // We use the client key to decrypt the output of the operation:
    let output = client_key.decrypt(&result);
    println!("time: {then}, clear output: {clear_output}, fhe output: {output}");
}

fn naive_compute(serialized_data: &[u8], server_key: ServerKey) -> Ciphertext {
    let mut serialized_data = Cursor::new(serialized_data);
    let man: Ciphertext = bincode::deserialize_from(&mut serialized_data).unwrap();
    let woman: Ciphertext = bincode::deserialize_from(&mut serialized_data).unwrap();
    let antecedent: Ciphertext = bincode::deserialize_from(&mut serialized_data).unwrap();
    let smoking: Ciphertext = bincode::deserialize_from(&mut serialized_data).unwrap();
    let diabetic: Ciphertext = bincode::deserialize_from(&mut serialized_data).unwrap();
    let high_blood_pressure: Ciphertext =
        bincode::deserialize_from(&mut serialized_data).unwrap();
    let age = bincode::deserialize_from(&mut serialized_data).unwrap();
    let hdl_cholesterol: Ciphertext = bincode::deserialize_from(&mut serialized_data).unwrap();
    let weight: Ciphertext = bincode::deserialize_from(&mut serialized_data).unwrap();
    let height: Ciphertext = bincode::deserialize_from(&mut serialized_data).unwrap();
    let daily_physical_activity: Ciphertext =
        bincode::deserialize_from(&mut serialized_data).unwrap();
    let alcohol_consumption: Ciphertext =
        bincode::deserialize_from(&mut serialized_data).unwrap();

    let mut cardio_risk = server_key.unchecked_scalar_mul(&man, 0u8);

    // +1: if man && age > 50 years
    let acc = server_key
        .generate_accumulator_bivariate(|man, age| if man == 1 && age > 50 { 1 } else { 0 });
    cardio_risk = server_key.unchecked_add(
        &server_key.keyswitch_programmable_bootstrap_bivariate(&man, &age, &acc),
        &cardio_risk,
    );

    // +1: if woman && age > 60 years
    let acc = server_key
        .generate_accumulator_bivariate(|woman, age| if woman == 1 && age > 60 { 1 } else { 0 });
    cardio_risk = server_key.unchecked_add(
        &server_key.keyswitch_programmable_bootstrap_bivariate(&woman, &age, &acc),
        &cardio_risk,
    );

    // +1: if antecedent
    cardio_risk = server_key.unchecked_add(&antecedent, &cardio_risk);

    // +1: if smoking
    cardio_risk = server_key.unchecked_add(&smoking, &cardio_risk);

    // +1: if diabetic
    cardio_risk = server_key.unchecked_add(&diabetic, &cardio_risk);

    // +1: if high blood pressure
    cardio_risk = server_key.unchecked_add(&high_blood_pressure, &cardio_risk);

    // +1: if HDL cholesterol < 40
    let acc =
        server_key.generate_accumulator(|hdl_cholesterol| if hdl_cholesterol < 40 { 1 } else { 0 });
    cardio_risk = server_key.unchecked_add(
        &server_key.keyswitch_programmable_bootstrap(&hdl_cholesterol, &acc),
        &cardio_risk,
    );

    // +1: if weight > height-90
    let acc = server_key.generate_accumulator_bivariate(|weight, height| {
        if weight as i64 > (height as i64 - 90) {
            1
        } else {
            0
        }
    });
    cardio_risk = server_key.unchecked_add(
        &server_key.keyswitch_programmable_bootstrap_bivariate(&weight, &height, &acc),
        &cardio_risk,
    );

    // +1: if daily physical activity < 30
    let acc = server_key
        .generate_accumulator(|daily_physical_act| if daily_physical_act < 30 { 1 } else { 0 });
    cardio_risk = server_key.unchecked_add(
        &server_key.keyswitch_programmable_bootstrap(&daily_physical_activity, &acc),
        &cardio_risk,
    );

    // +1: if man && alcohol cons. > 3 glasses/day
    let acc =
        server_key.generate_accumulator_bivariate(
            |man, alcohol_cons| if man == 1 && alcohol_cons > 3 { 1 } else { 0 },
        );
    cardio_risk = server_key.unchecked_add(
        &server_key.keyswitch_programmable_bootstrap_bivariate(
            &man,
            &alcohol_consumption,
            &acc,
        ),
        &cardio_risk,
    );

    // if !man && alcohol cons. > 2 glasses/day
    let acc =
        server_key.generate_accumulator_bivariate(
            |man, alcohol_cons| if man == 0 && alcohol_cons > 2 { 1 } else { 0 },
        );
    cardio_risk = server_key.unchecked_add(
        &server_key.keyswitch_programmable_bootstrap_bivariate(
            &man,
            &alcohol_consumption,
            &acc,
        ),
        &cardio_risk,
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
    cardio_risk += if antecedent == 1 {1} else {0};

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
