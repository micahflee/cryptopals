use colored::Colorize;

pub fn index(challenge: u32) {
    if challenge == 17 {
        challenge17();
    } else if challenge == 18 {
        challenge18();
    } else if challenge == 19 {
        challenge19();
    } else if challenge == 20 {
        challenge20();
    } else if challenge == 21 {
        challenge21();
    } else if challenge == 22 {
        challenge22();
    } else if challenge == 23 {
        challenge23();
    } else if challenge == 24 {
        challenge24();
    } else {
        // Run all challanges
        challenge17();
        challenge18();
        challenge19();
        challenge20();
        challenge21();
        challenge22();
        challenge23();
        challenge24();
    }
}

fn challenge17() {
    // https://cryptopals.com/sets/3/challenges/17
    println!("\n{}", "Challenge 17: The CBC padding oracle".blue().bold());
    println!("(not implemented yet)");
}

fn challenge18() {
    // https://cryptopals.com/sets/3/challenges/18
    println!("\n{}", "Challenge 18: Implement CTR, the stream cipher mode".blue().bold());
    println!("(not implemented yet)");
}

fn challenge19() {
    // https://cryptopals.com/sets/3/challenges/19
    println!("\n{}", "Challenge 19: Break fixed-nonce CTR mode using substitutions".blue().bold());
    println!("(not implemented yet)");
}

fn challenge20() {
    // https://cryptopals.com/sets/3/challenges/20
    println!("\n{}", "Challenge 20: Break fixed-nonce CTR statistically".blue().bold());
    println!("(not implemented yet)");
}

fn challenge21() {
    // https://cryptopals.com/sets/3/challenges/21
    println!("\n{}", "Challenge 21: Implement the MT19937 Mersenne Twister RNG".blue().bold());
    println!("(not implemented yet)");
}

fn challenge22() {
    // https://cryptopals.com/sets/3/challenges/22
    println!("\n{}", "Challenge 22: Crack an MT19937 seed".blue().bold());
    println!("(not implemented yet)");
}

fn challenge23() {
    // https://cryptopals.com/sets/3/challenges/23
    println!("\n{}", "Challenge 23: Clone an MT19937 RNG from its output".blue().bold());
    println!("(not implemented yet)");
}

fn challenge24() {
    // https://cryptopals.com/sets/3/challenges/24
    println!("\n{}", "Challenge 24: Create the MT19937 stream cipher and break it".blue().bold());
    println!("(not implemented yet)");
}
