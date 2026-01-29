use merkle_spark::{Leaf, MerkleOptions, MerkleResult, MerkleTree};



fn main () -> MerkleResult<()> {
    // let sample = String::from("hello world");
    // Leaf::hash_data(sample.as_bytes());
    let option = MerkleOptions {
        depth: 3
    };

    let mut tree = MerkleTree::new(option)?;
    let sample_data = String::from("This is a sample data");

    println!("This is the current root hash before insertion: {}", tree.root_hash.stringify_hash_bytes());
    
    let sample_1_data_index = tree.insert_leaf(sample_data.as_bytes())?;
    
    println!("This is the current root hash After insertion: {}", tree.root_hash.stringify_hash_bytes());
    println!("Inserted leaf index: {sample_1_data_index}");

    let first_proof = tree.generate_proof(sample_1_data_index)?;
    println!("First proof {:?}", first_proof);

    let value = tree.verify_proof(first_proof)?;

    println!("Proof is {value}");


    Ok(())
}