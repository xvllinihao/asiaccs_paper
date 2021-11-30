mod encrypt;

#[macro_use] extern crate hex_literal;
extern crate pbkdf2;
extern crate rand;
extern crate sha3;
extern crate curve25519_dalek;
extern crate block_modes;


use encrypt::{enc_aes_then_ecies};



fn main() {
//     let mut i = 1;
//     let mut time_kdf = Duration::new(0, 0);
//     let mut time_tkpid = Duration::new(0, 0);
//     let mut time_p = Duration::new(0, 0);
//     let mut time_pprime = Duration::new(0, 0);
//     while i < 1 {
//         let start = Instant::now();
//         let mut ra = ChaChaRng::new_unseeded();
//         let f_ab1 =  ra.next_u32();
//         let f_ab2 = ra.next_u32();
//         let f_ba1 = ra.next_u32();
//         let f_ba2 = ra.next_u32();
//         let pid = ra.next_u32();
//         // println!("{} {} {} {}", f_ab1,f_ab2,f_ba1,f_ba2);
//
//
//         let password1 = f_ba1.to_string() + &f_ab1.to_string();
//         let password2 = f_ba2.to_string() + &f_ab2.to_string();// Bad password; don't actually use!
//         let salt = SaltString::generate(&mut OsRng);
//
// // Hash password to PHC string ($pbkdf2-sha256$...)
//         let k_aa= Pbkdf2.hash_password(password1.as_bytes(), &salt).unwrap().hash.unwrap().to_string();
//         // println!("{:?}",k_aa);
//
//         let k_ab = Pbkdf2.hash_password(password2.as_bytes(), &salt).unwrap().hash.unwrap().to_string();
//         // println!("{:?}",k_ab);
//         let duration = start.elapsed();
//
//         // println!("Time elapsed in KDF is: {:?}", duration);
//
//         let start2 = Instant::now();
//         let mut hasher = Sha3_256::new();
//         let pid_kaa = pid.to_string() + &k_aa;
//         hasher.update(pid_kaa.to_string().as_bytes());
//         //
//         let result = hasher.finalize();
//
//
//         let G = constants::ED25519_BASEPOINT_POINT;
//         let scalar: &[u8] = result.as_slice();
//         let hash_scalar = Scalar::from_bits(<[u8; 32]>::try_from(scalar).unwrap());
//         // println!("{:?}",hash_scalar);
//         let tk_pid = hash_scalar * G;
//         // println!("{:?}",tk_pid);
//
//         let duration2 = start2.elapsed();
//         // println!("Time elapsed in generate tk_pid is: {:?}", duration2);
//
//         let start3 = Instant::now();
//         let r = ra.next_u32();
//         let R = Scalar::from(r) * G;
//
//         let rtkpid = Scalar::from(r) * tk_pid;
//         let mut hasher_1 = Sha3_256::new();
//         hasher_1.update(rtkpid.compress().as_bytes());
//         let hs_rtkpid = hasher_1.finalize();
//
//         let P = String::from_utf8_lossy(&*hs_rtkpid.to_vec()).to_string() + &k_ab;
//         //println!("P = {}", P);
//         let duration3 = start3.elapsed();
//         // println!("Time elapsed in generate P is: {:?}", duration3);
//
//         // verification
//         let start4 = Instant::now();
//         let tkpidR = hash_scalar * R;
//         let mut hasher_2 = Sha3_256::new();
//         hasher_2.update(tkpidR.compress().as_bytes());
//
//         // println!("Time elapsed in generate Pprime is: {:?}", duration4);
//
//         let hs_tkpidR = hasher_2.finalize();
//         let P_prime = String::from_utf8_lossy(&*hs_tkpidR.to_vec()).to_string() + &k_ab;
//         let duration4 = start4.elapsed();
//         assert_eq!(P , P_prime);
//         // println!("verification successfully");
//         i+=1;
//         time_kdf += duration;
//         time_tkpid += duration2;
//         time_p += duration3;
//         time_pprime += duration4;
//     }
//     println!("avg time elapsed in kdf is: {:?}", time_kdf/1000);
//     println!("avg time elapsed in generate tkpid is: {:?}", time_tkpid/1000);
//     println!("avg time elapsed in generate P is: {:?}", time_p/1000);
//     println!("avg time elapsed in generate Pprime is: {:?}", time_pprime/1000);



    enc_aes_then_ecies(&String::from("data/data0/data0/data/1.txt"));
}
