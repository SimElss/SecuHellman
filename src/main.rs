use clap::Parser;
use sha2::{Digest, Sha256};
use std::path::{PathBuf};
use std::{env};
use rand::{prelude::*};
use std::fs::File;
use std::io::Write;

const MAX_DOMAIN:  u64 = 274877906943; // 2**38 - 1

/* @Student
 * Write necessary code here,  or create other files.
 */

/// Basic Hellman TMTO Table construction aimed to cover a 38-bits unsigned integer probability
/// space against a SHA256 hashing function.
/// Reduction functions are supposed to be a right rotation of N bits such that there are at most
/// 255 admissible reduction functions.
#[derive(Parser, Debug, Clone)]
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
    let mut threads= Vec::new();

    for _ in 0..args.ntables as usize{

        // Thread for each table

        let args = args.clone();
        let thread = std::thread::spawn(move || {
            // Init list
            let mut x0_list : Vec<u64> = Vec::new();
            let mut x_end_bis : Vec<u64> = Vec::new();
            let mut x_end_list : Vec<u64> = Vec::new();
            
            // Init random number generator
            let mut rng = rand::rng();
            let x0 = rng.random_range(0..MAX_DOMAIN);

            // Random generator for the N Reduc
            let mut rng_reduc = rand::rng();
            let n_reduc: u32 = rng_reduc.random_range(1..=255);
        
            //Hellman Table algo
            for chain in 0..args.nchains {

                //Store x0
                let mut x0_bis = (x0 + chain) % MAX_DOMAIN; 
                x0_list.push(x0_bis);

                for _column in 0..args.ncolumns {
                    // Hash the current x0_bis
                    let mut hasher = Sha256::new();
                    hasher.update(x0_bis.to_le_bytes());
                    let hash_result = hasher.finalize();   

                    let mut bytes = [0u8; 8];
                    bytes.copy_from_slice(&hash_result[..8]);
                    let mut reduc = u64::from_le_bytes(bytes);

                    // Reduction function
                    reduc = reduc.rotate_right(n_reduc);
                    let x_end = reduc & ((1u64 << 38) - 1);  
                    x0_bis = x_end;

                    x_end_bis.push(x_end);
                }
                
                // Store the last value of the chain (x_end)
                let x_end = x_end_bis.last().unwrap();
                x_end_list.push(*x_end);
                x_end_bis.clear();
            }
            
            // Create the directory
            if !args.path.exists() {
                std::fs::create_dir_all(&args.path).expect("Failed to create directory for tables");
            }

            let file_path = args.path.join(format!("{}.txt", n_reduc));
            let mut file = File::create(&file_path).expect("Failed to create file for TMTO table");
            
            writeln!(file, "nchain: {}, ncolumns: {}, redu:{} ", args.nchains, args.ncolumns, n_reduc).expect("Failed to write header to TMTO table file");
            for (x0, x_end) in x0_list.iter().zip(x_end_list.iter()) {
                writeln!(file, "{}, {}", x0, x_end).expect("Failed to write to TMTO table file");
            }
            
            // Reset the lists for each table
            x0_list.clear();
            x_end_list.clear();
        });
        threads.push(thread);
        }
        
    // Wait for all threads to finish
    for thread in threads {
        thread.join().expect("Thread didn't finish");
    }

    println!("TMTO table generation completed successfully.");

}
