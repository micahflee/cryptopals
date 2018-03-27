use colored::Colorize;

pub fn index(challenge: u32) {
    if challenge == 0 || challenge == 1 {
        println!("{}", "Implement PKCS#7 padding".blue().bold());
        challenge1();
        println!("");
    }
}

fn challenge1() {

}
