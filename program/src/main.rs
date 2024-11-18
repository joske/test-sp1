#![no_main]
sp1_zkvm::entrypoint!(main);

use lib::Input;

pub fn main() {
    println!("Starting program");
    let input: Input = sp1_zkvm::io::read();
    if input.a != 0 {
        let digest: [u8; 32] = sp1_zkvm::io::read();
        println!("digest: {:?}", digest);
        sp1_zkvm::lib::verify::verify_sp1_proof(&input.verification_key, &digest);
    }

    // write public output
    sp1_zkvm::io::commit(&input);
    println!("Finished program");
}
