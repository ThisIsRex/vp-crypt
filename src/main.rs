use std::{
    fs,
    path::{Path, PathBuf},
    str::FromStr,
};

use aes::cipher::{
    block_padding::{Pkcs7, UnpadError},
    BlockDecryptMut, BlockEncryptMut, KeyIvInit,
};
use clap::Parser;
use rand::{self, Rng};

const KEY: &[u8; 16] = &[
    0x46, 0x41, 0x38, 0x39, 0x34, 0x31, 0x32, 0x44, 0x38, 0x37, 0x42, 0x30, 0x45, 0x46, 0x44, 0x39,
];

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

#[derive(Parser, Debug)]
struct Args {
    input: String,

    #[clap(short)]
    encrypt: bool,

    #[clap(short)]
    output: Option<String>,
}

fn main() {
    let args = Args::parse();
    let input = PathBuf::from_str(&args.input).unwrap();

    let output = if let Some(out) = &args.output {
        PathBuf::from_str(&out).unwrap()
    } else {
        make_output_name(&input, args.encrypt).expect("Invalid file name")
    };

    let firmware_source = fs::read(&input).expect("File reading error");
    let firmware_dest = if args.encrypt {
        encrypt_firmware(&firmware_source, KEY)
    } else {
        decrypt_firmware(&firmware_source, KEY).expect("Can't decrypt. Maybe invalid firmware?")
    };

    fs::write(&output, &firmware_dest).expect("File writing error");
}

fn make_output_name(input: &Path, encrypt: bool) -> Option<PathBuf> {
    let ext = input.extension();
    let mut output = PathBuf::new();

    let new_ext = if encrypt { "encrypted" } else { "decrypted" }.to_string();

    let stem = input.with_extension("");
    output.push(stem);
    if let Some(e) = ext {
        output.set_extension(new_ext + "." + e.to_str().unwrap_or("bin"));
    }

    Some(output)
}

fn decrypt_firmware(source: &[u8], key: &[u8; 16]) -> Result<Vec<u8>, UnpadError> {
    let (iv, encrypted) = source.split_at(16);

    Aes128CbcDec::new(key.into(), iv.into()).decrypt_padded_vec_mut::<Pkcs7>(encrypted)
}

fn encrypt_firmware(source: &[u8], key: &[u8; 16]) -> Vec<u8> {
    let mut iv = [0; 16];
    rand::thread_rng().fill_bytes(&mut iv);

    let mut result = vec![];
    result.extend_from_slice(&iv);
    result.extend_from_slice(
        &Aes128CbcEnc::new(key.into(), &iv.into()).encrypt_padded_vec_mut::<Pkcs7>(&source),
    );

    result
}

///Decrypts `Dummy` dll from `NCode.dll` resources
fn decrypt_lib(lib_raw: &mut [u8]) {
    let mut counter = 3u32;

    lib_raw.iter_mut().for_each(|b| {
        *b = *b ^ counter as u8;
        counter = if counter + 3 >= 255 { 3 } else { counter + 3 };
    });
}

///Generates `AES` key from the public key token
fn generate_key(pub_token_key: &[u8; 8]) -> [u8; 16] {
    let mut key = [0; 16];

    let mut num = 66_u32;
    let mut ki = 0;

    pub_token_key.iter().enumerate().for_each(|(_i, &b)| {
        let byte = b ^ num as u8;
        num += 3;

        let b_str = format!("{:02X?}", byte);
        key[ki] = b_str.as_bytes()[0];
        key[ki + 1] = b_str.as_bytes()[1];
        ki += 2;
    });

    key
}
