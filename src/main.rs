#[macro_use(value_t)]
extern crate clap;
extern crate colored;
extern crate hamming;
extern crate crypto;
extern crate rand;
extern crate queryst;

mod set1;
mod set2;
mod set3;
mod utils;

use clap::{Arg, App};

fn main() {
    // Parse command line args
    let matches = App::new("Cryptopals")
        .about("Solutions to https://cryptopals.com/ challenges")
        .arg(Arg::with_name("SET")
            .help("Challenge set")
            .required(true)
            .index(1))
        .arg(Arg::with_name("CHALLENGE")
            .help("Challenge number (blank to run all)")
            .index(2))
        .get_matches();

    // Validate set as integer
    let set = match value_t!(matches, "SET", u32) {
        Ok(v) => v,
        Err(_) => {
            println!("CHALLENGE_SET must be an integer");
            return;
        }
    };

    let challenge = match matches.value_of("CHALLENGE") {
        Some(_) => {
            match value_t!(matches, "CHALLENGE", u32) {
                Ok(v) => v,
                Err(_) => { 0 }
            }
        },
        None => { 0 }
    };

    // Run the challenge(s)
    if set == 1 {
        set1::index(challenge);
    } else if set == 2 {
        set2::index(challenge);
    } else if set == 3 {
        set3::index(challenge);
    } else {
        println!("Sorry, I haven't implemented that challenge set");
    }
}
