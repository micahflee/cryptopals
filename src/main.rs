#[macro_use(value_t)]
extern crate clap;

mod set1;

use clap::{Arg, App};

fn main() {
    // Parse command line args
    let matches = App::new("Cryptopals")
        .about("Solutions to https://cryptopals.com/ challenges")
        .arg(Arg::with_name("CHALLENGE_SET")
            .help("Challenge set to run (int)")
            .required(true)
            .index(1))
        .get_matches();

    // Validate set as integer
    let set = match value_t!(matches, "CHALLENGE_SET", u32) {
        Ok(v) => v,
        Err(_) => {
            println!("CHALLENGE_SET must be an integer");
            return;
        }
    };

    // Challenge set 1
    if set == 1 {
        set1::index();
    } else {
        println!("Sorry, I haven't implemented that challenge set");
    }
}
