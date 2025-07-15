use clap::Parser;
use sha2::{Digest, Sha256};
use core::hash;
use std::path::{Path, PathBuf};
use std::env;
use rand::prelude::*;

const MAX_DOMAIN:  u64 = 274877906943; // 2**38 - 1

/* @Student
 * Write necessary code here,  or create other files.
 */

/// Basic Hellman TMTO Table construction aimed to cover a 38-bits unsigned integer probability
/// space against a SHA256 hashing function.
/// Reduction functions are supposed to be a right rotation of N bits such that there are at most
/// 255 admissible reduction functions.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Number of tables to generate, limited to 255 tables.
    #[arg(short, long, default_value_t = 1, value_parser = clap::value_parser!(u8).range(1..=255))]
    ntables: u8,
    /// Number of chains.
    nchains: u64,
    /// Number of columns excluding the endpoints.
    ncolumns: u64,
    /// Path to directory storing table(s)
    #[arg(default_value=default_table_path().into_os_string())]
    path: PathBuf,
}

fn default_table_path() -> PathBuf {
    let mut path = env::current_dir().expect("Could not access current directory. Are rights correctly set?");
    path.push("tables");
    path
}


fn main() {
    let args = Args::parse();
    // Initialize random number generator
    let mut rng = rand::rng();
    let x0 = rng.random_range(0..MAX_DOMAIN);
    let mut x0_list : Vec<u64> = Vec::new();
    let mut x_end_list : Vec<u64> = Vec::new();
    println!("Number of chains: {}", args.nchains);

    for chain in 0..args.nchains {
        let x0_bis = (x0 + chain) % MAX_DOMAIN; 
        x0_list.push(x0_bis);
        for column in 0..args.ncolumns {
            // Hash the value using SHA256
            let mut hasher = Sha256::new();
            hasher.update(x0_bis.to_le_bytes());
            let hash_result = hasher.finalize();   

            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&hash_result[..8]);
            let mut reduc = u64::from_le_bytes(bytes);

            reduc = reduc.rotate_right(1);
            let x_end = reduc & ((1u64 << 38) - 1);  

        }
        x_end_list.push(x_end);
        
    }
    println!("Start = {}, End = {}", x0_list.last().unwrap() , x_end_list.last().unwrap());


    println!("Number of columns: {}", args.ncolumns);
    println!("Path to tables: {}", args.path.display());
    

    println!("TMTO table generation completed successfully.");

}

