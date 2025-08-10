use clap::Parser;
use sha2::{Digest, Sha256};
use std::path::{PathBuf};
use std::sync::mpsc;
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
    let (tx, rx) = mpsc::channel();

    for n_reduc in 1..=args.ntables as u32 {

        // Thread for each table
        let args = args.clone();
        let tx = tx.clone();

        let thread = std::thread::spawn(move || {
            // Init list
            let mut x0_list : Vec<u64> = Vec::new();
            let mut x_end_bis : Vec<u64> = Vec::new();
            let mut x_end_list : Vec<u64> = Vec::new();

            // Init random number generator
            let mut rng = rand::rng();
            let x0 = rng.random_range(0..MAX_DOMAIN);

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

                    //Split into 4 blocks
                    let mut blocks = [
                        u64::from_le_bytes(hash_result[0..8].try_into().unwrap()),
                        u64::from_le_bytes(hash_result[8..16].try_into().unwrap()),
                        u64::from_le_bytes(hash_result[16..24].try_into().unwrap()),
                        u64::from_le_bytes(hash_result[24..32].try_into().unwrap()),
                    ];

                    //Block rotation
                    let blockrotate = (n_reduc / 64) as usize;
                    let bitrotate = n_reduc % 64;

                    let mut rot = [0u64; 4];
                    for i in 0..4 {
                        rot[i] = blocks[(i + blockrotate) % 4];
                    }

                    // Bit rotation inside blocks
                    let mut new_rot = [0u64; 4];
                    for i in 0..4 {
                        let next = (i + 1) % 4;
                        new_rot[i] = rot[i].rotate_right(bitrotate) | rot[next].wrapping_shl(64 - bitrotate);
                    }
                    rot = new_rot;

                    // Extract 38 MSB
                    let x_end = (rot[3] >> 26) % MAX_DOMAIN ;
                    
                    x0_bis = x_end;

                    x_end_bis.push(x_end);
                }

                // Store the last value of the chain (x_end)
                let x_end = x_end_bis.last().unwrap();
                x_end_list.push(*x_end);
                x_end_bis.clear();
            }

            //Create the directory
            if !args.path.exists() {
                std::fs::create_dir_all(&args.path).expect("Failed to create directory");
            }

            // Create the file
            let file_path = args.path.join(format!("{}.txt", n_reduc));
            let mut file = File::create(&file_path).expect("Failed to create file");

            writeln!(file,"nchain: {}, ncolumns: {}, redu:{} ", args.nchains, args.ncolumns, n_reduc).expect("Failed to write header to TMTO table file");

            for (x0, x_end) in x0_list.iter().zip(x_end_list.iter()) {
                writeln!(file, "{}, {}", x0, x_end).expect("Failed to write to TMTO table file");
            }

            // Reset the lists for each table
            x0_list.clear();
            x_end_list.clear();

            // Send table number
            tx.send(n_reduc).expect("Failed to send message from thread");
        });

        threads.push(thread);
    }

    //Rx receives the number of the reduction      
    for _ in 0..args.ntables {
        let n_reduc = rx.recv().expect("Failed to receive message");
        println!("Table {} generated", n_reduc);
    }

    // Wait for all threads to finish
    for thread in threads {
        thread.join().expect("Thread didn't finish");
    }

}