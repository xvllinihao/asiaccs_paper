extern crate ecies;
extern crate aes;
extern crate pbkdf2;
extern crate rand;
extern crate sha3;
extern crate curve25519_dalek;
extern crate block_modes;


use std::fs::File;
use std::io::{self, BufRead, Write};
use std::path::Path;
use std::error::Error;
use std::cell::UnsafeCell;
use std::rc::Rc;
use self::ecies::utils::generate_keypair;
use self::ecies::{encrypt, decrypt};
use std::str;
use self::aes::cipher::generic_array::GenericArray;
use self::aes::{Block, ParBlocks, NewBlockCipher, BlockEncrypt, BlockDecrypt, Aes256, Aes128};
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use hex_literal::hex;
use rand::{Rng, ChaChaRng, RngCore, random};
use std::time::{Duration, Instant};
use slice_as_array::reexport::clone;


use pbkdf2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHasher, SaltString, PasswordHash
    },
    Pbkdf2
};
use sha3::{Sha3_256, Digest};
use curve25519_dalek::{constants, edwards, scalar::Scalar};
use std::convert::{TryInto, TryFrom};
use byteorder::{BigEndian, ReadBytesExt};
use std::hash::Hash;
use std::ptr::hash;

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
    where P: AsRef<Path>, {
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

pub(crate) fn enc_aes_then_ecies(filename: &String) {
    // let test_data = vec![(20,100),(40,200),(60,300),(80,400),(100,500)];
    let test_data = vec![(20,100)];
    let mut duration_aes = Duration::new(0,0);
    let mut duration_ecies = Duration::new(0,0);
    let mut duration_only_ecies = Duration::new(0,0);
    let mut key_list = Vec::new();
    let mut location_list = Vec::new();
    let mut ra = ChaChaRng::new_unseeded();
    let mut counter = 0;


    if let Ok(lines) = read_lines(filename) {
            for line in lines{
                counter += 1;
                if counter > 101 {
                    break;
                }
                if let Ok(msg) = line {
                    location_list.push(msg);
                }
            }
    }
    for (location_len, product_len) in test_data {
        println!("location_len = {}, product_len = {}",location_len, product_len);
        for i in [0..1001] {
            // let mut file = std::fs::File::create("data.txt").expect("create failed");


            for msg in &location_list[0..location_len]{
                let start = Instant::now();
                type Aes128Cbc = Cbc<Aes128, Pkcs7>;

                // let key = hex!("000102030405060708090a0b0c0d0e0f");
                let k1 = ra.next_u32();
                let k2 = ra.next_u32();
                let k3 = ra.next_u32();
                let k4 = ra.next_u32();
                let key = generate_128bit(k1, k2, k3, k4);
                // let iv = hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
                let i1 = ra.next_u32();
                let i2 = ra.next_u32();
                let i3 = ra.next_u32();
                let i4 = ra.next_u32();
                let iv = generate_128bit(i1, i2, i3, i4);
                key_list.push(key);
                let cipher = Aes128Cbc::new_from_slices(&key, &iv).unwrap();

                let plaintext = msg.as_bytes();
                let mut buffer = [0u8; 64];
                let pos = plaintext.len();
                buffer[..pos].copy_from_slice(plaintext);

                let ciphertext = cipher.encrypt(&mut buffer, pos).unwrap();
                // println!("{:?}", ciphertext);
                // file.write_all(ciphertext).expect("write failed");

                let duration = start.elapsed();
                duration_aes += duration;
            }
            let start2 = Instant::now();
            for i in 0..product_len+1{
                //println!("{:?}",i);
                let (P,R) = generate_PR();
                let idx = ra.gen_range(0, location_len);
                let (sk, pk) = generate_keypair();
                let (sk, pk) = (&sk.serialize(), &pk.serialize());
                let aes_key = &key_list[idx];
                let encrypted_msg = encrypt(pk, aes_key.as_ref()).unwrap();
                // println!("{:?}", encrypted_msg);
                // println!("{:?}, {:?}", P,R);

                // file.write_all(P.as_ref()).expect("write failed");
                // file.write_all(R.as_ref()).expect("write failed");
                // file.write_all(&*encrypted_msg).expect("write failed");
            }
            let duration2 = start2.elapsed();
            duration_ecies += duration2;

            let start3 = Instant::now();
            for i in 0..product_len+1{
                //println!("{:?}",i);
                let (P,R) = generate_PR();
                let idx = ra.gen_range(0, location_len);
                let (sk, pk) = generate_keypair();
                let (sk, pk) = (&sk.serialize(), &pk.serialize());
                let encrypted_msg = encrypt(pk, (&location_list[i]).as_ref()).unwrap();
                // println!("{:?}", encrypted_msg);
                // println!("{:?}, {:?}", P,R);

                // file.write_all(P.as_ref()).expect("write failed");
                // file.write_all(R.as_ref()).expect("write failed");
                // file.write_all(&*encrypted_msg).expect("write failed");
            }
            let duration3 = start3.elapsed();
            duration_only_ecies += duration3;
        }
        }



        println!("avg time elapsed in aes is: {:?}", duration_aes/1000);
        println!("avg time elapsed in ecies is: {:?}", duration_ecies/1000);
        println!("avg time elapsed in only ecies is: {:?}", duration_only_ecies/1000);
    }


fn generate_PR() -> (String, String) {
    let mut ra = ChaChaRng::new_unseeded();
    let f_ab1 =  ra.next_u32();
    let f_ab2 = ra.next_u32();
    let f_ba1 = ra.next_u32();
    let f_ba2 = ra.next_u32();
    let pid = ra.next_u32();
    // println!("{} {} {} {}", f_ab1,f_ab2,f_ba1,f_ba2);


    let password1 = f_ba1.to_string() + &f_ab1.to_string();
    let password2 = f_ba2.to_string() + &f_ab2.to_string();// Bad password; don't actually use!
    let salt = SaltString::generate(&mut OsRng);

// Hash password to PHC string ($pbkdf2-sha256$...)
    let k_aa= Pbkdf2.hash_password(password1.as_bytes(), &salt).unwrap().hash.unwrap().to_string();

    let k_ab = Pbkdf2.hash_password(password2.as_bytes(), &salt).unwrap().hash.unwrap().to_string();


    let start2 = Instant::now();
    let mut hasher = Sha3_256::new();
    let pid_kaa = pid.to_string() + &k_aa;
    hasher.update(pid_kaa.to_string().as_bytes());
    //
    let result = hasher.finalize();


    let G = constants::ED25519_BASEPOINT_POINT;
    let scalar: &[u8] = result.as_slice();
    let hash_scalar = Scalar::from_bits(<[u8; 32]>::try_from(scalar).unwrap());
    // println!("{:?}",hash_scalar);
    let tk_pid = hash_scalar * G;
    // println!("{:?}",tk_pid);

    let duration2 = start2.elapsed();
    // println!("Time elapsed in generate tk_pid is: {:?}", duration2);

    let start3 = Instant::now();
    let r = ra.next_u32();
    let R = Scalar::from(r) * G;

    let rtkpid = Scalar::from(r) * tk_pid;
    let mut hasher_1 = Sha3_256::new();
    hasher_1.update(rtkpid.compress().as_bytes());
    let hs_rtkpid = hasher_1.finalize();

    let P = String::from_utf8_lossy(&*hs_rtkpid.to_vec()).to_string() + &k_ab;
    let R = String::from_utf8_lossy(&*R.compress().as_bytes().to_vec()).to_string();
    (P,R)

}


fn generate_128bit(x1: u32,x2: u32,x3: u32,x4: u32) -> [u8; 16] {
    let a1: u8 = ((x1 >> 24) & 0xff) as u8;
    let a2: u8 = ((x1 >> 16) & 0xff) as u8;
    let a3: u8 = ((x1 >> 8) & 0xff) as u8;
    let a4: u8 = (x1 & 0xff) as u8;

    let b1: u8 = ((x1 >> 24) & 0xff) as u8;
    let b2: u8 = ((x1 >> 16) & 0xff) as u8;
    let b3: u8 = ((x1 >> 8) & 0xff) as u8;
    let b4: u8 = (x1 & 0xff) as u8;

    let c1: u8 = ((x1 >> 24) & 0xff) as u8;
    let c2: u8 = ((x1 >> 16) & 0xff) as u8;
    let c3: u8 = ((x1 >> 8) & 0xff) as u8;
    let c4: u8 = (x1 & 0xff) as u8;

    let d1: u8 = ((x1 >> 24) & 0xff) as u8;
    let d2: u8 = ((x1 >> 16) & 0xff) as u8;
    let d3: u8 = ((x1 >> 8) & 0xff) as u8;
    let d4: u8 = (x1 & 0xff) as u8;

    [a1, a2, a3, a4,b1, b2, b3, b4,c1, c2, c3, c4,d1, d2, d3, d4]
}