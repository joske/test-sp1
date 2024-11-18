use anyhow::Result;
use lib::Input;
use sha2::{Digest, Sha256};
use sp1_sdk::{include_elf, HashableKey, ProverClient, SP1Proof, SP1Stdin};

pub const VERIFY_ELF: &[u8] = include_elf!("verify");

fn main() -> Result<()> {
    sp1_sdk::utils::setup_logger();

    let client = ProverClient::new();
    // Setup the program for proving.
    let (pk, vk) = client.setup(VERIFY_ELF);
    let mut stdin = SP1Stdin::new();
    let first_input = Input {
        a: 0,
        b: 0,
        verification_key: vk.clone().hash_u32(),
    };
    stdin.write(&first_input);
    // Generate the proof
    let first_proof = client
        .prove(&pk, stdin)
        .compressed()
        .run()
        .expect("failed to generate proof");
    println!("Successfully generated proof!");
    // Verify the proof.
    client
        .verify(&first_proof, &vk)
        .expect("failed to verify proof");
    println!("Successfully verified proof!");
    let previous_input_encoded: Vec<u8> = first_proof.public_values.to_vec();
    let first_digest = Sha256::digest(&previous_input_encoded);
    println!("digest after proof: {:?}", first_digest);

    // second invocation
    let (pk, vk) = client.setup(VERIFY_ELF);
    let mut stdin = SP1Stdin::new();
    let input = Input {
        a: 1,
        b: 2,
        verification_key: vk.clone().hash_u32(),
    };
    let SP1Proof::Compressed(compressed_proof) = first_proof.proof else {
        panic!("expected compressed proof");
    };
    let reduce_proof = *compressed_proof;
    stdin.write_proof(reduce_proof, vk.clone().vk);
    stdin.write(&input);
    stdin.write_slice(first_digest.as_slice());
    // Generate the proof
    let proof = client
        .prove(&pk, stdin)
        .compressed()
        .run()
        .expect("failed to generate proof");

    println!("Successfully generated proof!");

    // Verify the proof.
    client.verify(&proof, &vk).expect("failed to verify proof");
    println!("Successfully verified proof!");
    Ok(())
}
