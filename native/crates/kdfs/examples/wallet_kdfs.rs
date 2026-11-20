use bitcore_kdfs::bitcoin_core_wallet_key;
use hmac::Hmac;
use sha2::Sha256;
use std::fmt::Write;
use std::hint::black_box;
use std::time::Instant;

fn main() {
    // The driver supplies only synthetic benchmark data.
    let args: Vec<_> = std::env::args().collect();
    let password = args[2].as_bytes();
    let salt = args[3].as_bytes();
    let rounds = args[4].parse().unwrap();
    let mut output = [0; 64];
    let start = Instant::now();
    let key = match args[1].as_str() {
        "pbkdf2" => {
            let length: usize = args[5].parse().unwrap();
            pbkdf2::pbkdf2::<Hmac<Sha256>>(password, salt, rounds, &mut output[..length]).unwrap();
            &output[..length]
        }
        "scrypt" => {
            let params = scrypt::Params::new(14, 8, 8).unwrap();
            scrypt::scrypt(password, salt, &params, &mut output).unwrap();
            &output[..]
        }
        "sha512" => {
            let input = [password, salt].concat();
            bitcoin_core_wallet_key(&input, rounds, &mut output);
            &output[..]
        }
        _ => panic!("Unsupported wallet KDF benchmark"),
    };
    black_box(key);
    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
    let mut hex = String::new();
    for byte in key {
        write!(hex, "{byte:02x}").unwrap();
    }
    println!("{elapsed_ms} {hex}");
}
