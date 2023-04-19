use std::error::Error;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::Path;

use tfhe::integer::{gen_keys_radix, RadixClientKey, ServerKey};
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
use tfhe::shortint::{gen_keys, Parameters};

use crate::NUM_BLOCKS;

pub const CLIENT_KEY_FILE_PATH: &'static str = "cardio_application/assets/client_key.bin";
pub const SERVER_KEY_FILE_PATH: &'static str = "cardio_application/assets/server_key.bin";

pub fn keys_gen(save: bool) -> Result<(RadixClientKey, ServerKey), Box<dyn Error>> {
    if save {
        return Ok(gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, NUM_BLOCKS))
    }

    let client_key_path = Path::new(CLIENT_KEY_FILE_PATH);
    let server_key_path = Path::new(SERVER_KEY_FILE_PATH);

    let (client_key, server_keys): (RadixClientKey, ServerKey) = if client_key_path.exists() {
        println!("Reading client keys from {CLIENT_KEY_FILE_PATH}",);
        println!("Reading server keys from {SERVER_KEY_FILE_PATH}",);
        let file = BufReader::new(File::open(client_key_path).unwrap());
        let client_key = bincode::deserialize_from(file).unwrap();
        let file = BufReader::new(File::open(server_key_path).unwrap());
        let server_keys = bincode::deserialize_from(file).unwrap();

        (client_key, server_keys)
    } else {
        println!("No {CLIENT_KEY_FILE_PATH} found, generating new keys and saving them",);
        let (client_key, server_keys) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, NUM_BLOCKS);
        let file = BufWriter::new(File::create(client_key_path)?);
        bincode::serialize_into(file, &client_key)?;

        println!("No {SERVER_KEY_FILE_PATH} found, generating new keys and saving them",);
        let file = BufWriter::new(File::create(server_key_path)?);
        bincode::serialize_into(file, &server_keys).unwrap();

        (client_key, server_keys)
    };

    println!("Done acquiring keys");

    Ok((client_key, server_keys))
}
