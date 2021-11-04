extern crate pbkdf2;
extern crate rand;
extern crate sha3;
extern crate curve25519_dalek;

use pbkdf2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHasher, SaltString, PasswordHash
    },
    Pbkdf2
};
use rand::{Rng, ChaChaRng};
use sha3::{Sha3_256, Digest};
use curve25519_dalek::{constants, edwards, scalar::Scalar};
use std::convert::{TryInto, TryFrom};
use byteorder::{BigEndian, ReadBytesExt};
use std::hash::Hash;


fn demo<T, const N: usize>(v: Vec<T>) -> [T; N] {
    v.try_into()
        .unwrap_or_else(|v: Vec<T>| panic!("Expected a Vec of length {} but it was {}", N, v.len()))
}


fn main() {
    let mut ra = ChaChaRng::new_unseeded();
    let f_ab1 =  ra.next_u32();
    let f_ab2 = ra.next_u32();
    let f_ba1 = ra.next_u32();
    let f_ba2 = ra.next_u32();
    let pid = ra.next_u32();
    println!("{} {} {} {}", f_ab1,f_ab2,f_ba1,f_ba2);

    let password1 = f_ba1.to_string() + &f_ab1.to_string();
    let password2 = f_ba2.to_string() + &f_ab2.to_string();// Bad password; don't actually use!
    let salt = SaltString::generate(&mut OsRng);

// Hash password to PHC string ($pbkdf2-sha256$...)
    let k_aa= Pbkdf2.hash_password(password1.as_bytes(), &salt).unwrap().hash.unwrap().to_string();
    println!("{:?}",k_aa);

    let k_ab = Pbkdf2.hash_password(password2.as_bytes(), &salt).unwrap().hash.unwrap().to_string();
    println!("{:?}",k_ab);

    let mut hasher = Sha3_256::new();
    let pid_kaa = pid.to_string() + &k_aa;
    hasher.update(pid_kaa.to_string().as_bytes());
    //
    let result = hasher.finalize();


    let G = constants::ED25519_BASEPOINT_POINT;
    let scalar: &[u8] = result.as_slice();
    let hash_scalar = Scalar::from_bits(<[u8; 32]>::try_from(scalar).unwrap());
    println!("{:?}",hash_scalar);
    let tk_pid = hash_scalar * G;
    println!("{:?}",tk_pid);

    let r = ra.next_u32();
    let R = Scalar::from(r) * G;
}
