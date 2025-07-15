use clap::Parser;
use sha2::{Digest, Sha256};
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

    
    println!("Number of chains: {}", args.nchains);

    for chain in 0..args.nchains {
        let x0_bis = (x0 + chain) % MAX_DOMAIN; 

        println!("Generating chain {} with starting point: {}", x0_bis, x0);
        
    }
    println!("Number of columns: {}", args.ncolumns);
    println!("Path to tables: {}", args.path.display());
    

    println!("TMTO table generation completed successfully.");

}

