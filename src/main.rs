#[macro_use(value_t)]
extern crate clap;

mod set1;

use clap::{Arg, App};

fn main() {
    // Parse command line args
    let matches = App::new("Cryptopals")
        .about("Solutions to https://cryptopals.com/ challenges")
        .arg(Arg::with_name("SET")
            .help("Challenge set (int)")
            .required(true)
            .index(1))
        .arg(Arg::with_name("CHALLENGE")
            .help("Challenge number within in the set (int)")
            .required(true)
            .index(2))
        .get_matches();

    // Validate set as integer
    let set = match value_t!(matches, "SET", u32) {
        Ok(v) => v,
        Err(_) => {
            println!("SET must be an integer");
            return;
        }
    };

    // Validate challenge as integer
    let challenge = match value_t!(matches, "CHALLENGE", u32) {
        Ok(v) => v,
        Err(_) => {
            println!("CHALLENGE must be an integer");
            return;
        }
    };

    // Challenge set 1
    if set == 1 {
        set1::index(challenge);
    } else {
        println!("Sorry, I haven't implemented any challenges from that set");
    }
}
