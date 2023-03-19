use std::error::Error;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::Path;

use tfhe::shortint::{gen_keys, ClientKey, Parameters, ServerKey};

pub const CLIENT_KEY_FILE_PATH: &'static str = "assets/client_key.bin";
pub const SERVER_KEY_FILE_PATH: &'static str = "assets/server_key.bin";

pub fn keys_gen(params: Parameters) -> Result<(ClientKey, ServerKey), Box<dyn Error>> {
    let client_key_path = Path::new(CLIENT_KEY_FILE_PATH);
    let server_key_path = Path::new(SERVER_KEY_FILE_PATH);

    let (client_key, server_keys): (ClientKey, ServerKey) = if client_key_path.exists() {
        println!("Reading client keys from {CLIENT_KEY_FILE_PATH}",);
        println!("Reading server keys from {SERVER_KEY_FILE_PATH}",);
        let file = BufReader::new(File::open(client_key_path).unwrap());
        let client_key = bincode::deserialize_from(file).unwrap();
        let file = BufReader::new(File::open(server_key_path).unwrap());
        let server_keys = bincode::deserialize_from(file).unwrap();

        (client_key, server_keys)
    } else {
        println!("No {CLIENT_KEY_FILE_PATH} found, generating new keys and saving them",);
        let (client_key, server_keys) = gen_keys(params);
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
