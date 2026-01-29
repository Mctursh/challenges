use std::{collections::HashMap, fmt::Error};
use sha2::{Digest, Sha256};

/**
 * This is simply a light weight implementation of A merkle tree
 * 
 */


pub type MerkleResult<T> = Result<T, Error>;
type GenericArray = [u8; 32];

// const TREE_DEPTH: usize = 4;

pub struct MerkleOptions {
    pub depth: u32
}
pub struct MerkleTree {
    nodes: Vec<Leaf>,
    pub root_hash: Leaf,
    depth: u32,
    most_right_leaf_index: u32,
}

#[derive(Copy, Clone)]
pub struct Leaf {
    hash: GenericArray
}

impl MerkleTree {
    pub fn new (option: MerkleOptions) -> MerkleResult<Self> {
        let  MerkleOptions { depth } = option;
        // create empy nodes for each entry(leaf, internal node and root).
        let empty_node_hash = Leaf::empty_node_hash();
        let total_leaf_nodes = (2u32.pow(depth + 1) - 1) as usize;
        let mut nodes = Vec::with_capacity(total_leaf_nodes);
        for _ in 0..total_leaf_nodes {
            nodes.push(Leaf {
                hash: empty_node_hash
            })
        }
        let root_hash = Leaf { hash: empty_node_hash };
        let most_right_leaf_index = 2u32.pow(depth) - 1;
        // let most_right_leaf_index = 2u32.pow(depth - 1);
        // depth formula 2^(D + 1) - 1
        Ok(
            Self {
                nodes,
                root_hash,
                depth,
                most_right_leaf_index
            }
        )
    }

    pub fn insert_leaf(&mut self, data: &[u8]) -> MerkleResult<u32> {
        let hash_bytes = Leaf::hash_data(data);
        let next_free_node_index = self.most_right_leaf_index;

        if next_free_node_index >= ((self.nodes.len() - 1) as u32) {
            return Err(Error) // Todo: Use proper erro
        }
        
        self.nodes[next_free_node_index as usize] = Leaf::new(hash_bytes);
        self.compute_root(self.most_right_leaf_index)?;
        self.most_right_leaf_index += 1;
        Ok(next_free_node_index)
    }

    pub fn compute_root(&mut self, new_leaf_index: u32) -> MerkleResult<()> {
        let mut new_hash_index = new_leaf_index;
        
        while new_hash_index != 0 { // root index so end iteration
            let new_index_leaf = &self.nodes[new_hash_index as usize];
            let is_new_leaf_position_even = MerkleTree::is_leaf_position_even(new_hash_index);
            let new_hash_sibling_index = MerkleTree::get_sibling_index(new_hash_index);

            println!("Hash for node index {new_hash_index} is {}", new_index_leaf.stringify_hash_bytes());
            
            //cheking if this element is the last element
            if new_hash_sibling_index >= ((self.nodes.len() - 1) as u32) {
                return Err(Error) // Todo: Use proper error
            }
            
            let sibling_hash = &self.nodes[new_hash_sibling_index as usize];
            println!("Hash for node index {new_hash_sibling_index} is {}", sibling_hash.stringify_hash_bytes());
            //TODO compute the concatenated hash of the pair and get the parent then iterate every depth up until the root
            // Order of hashing is Left + right sibling
            let stringified_siblings = if is_new_leaf_position_even {
                MerkleTree::stringify_siblings_hash(sibling_hash,new_index_leaf)
            } else {
                MerkleTree::stringify_siblings_hash(new_index_leaf, sibling_hash)
            };
            
            let new_leaf_parent = Leaf::hash_data(stringified_siblings.as_bytes());
            
            let hash_parent_index= MerkleTree::get_parent_index(new_hash_index) as usize; // parent index of given index
            let hash_parent_node = Leaf { hash: new_leaf_parent };
            self.nodes[hash_parent_index] = hash_parent_node;


            println!("Parent hash for node index {new_hash_index} and {new_hash_sibling_index} is {}", hash_parent_node.stringify_hash_bytes());
            new_hash_index = hash_parent_index as u32;


            if new_hash_index == 0 {
                self.root_hash = self.nodes[hash_parent_index];
            }
        };

        Ok(())
    }

    fn stringify_siblings_hash(left_sibling: &Leaf, right_sibling: &Leaf) -> String {
        format!("{}{}", left_sibling.stringify_hash_bytes(), right_sibling.stringify_hash_bytes())
    }

    fn is_within_leaf_bound(&self, index: u32) -> bool { // exist within the last depth of the tree AKA the leaf nodes
        if index >= ((self.nodes.len() - 1) as u32) {
            false // 
        } else if index < (2u32.pow(self.depth) - 1) {
            false //
        } else {
            true
        }
    }

    fn get_sibling_index(index: u32) -> u32 {
        if (index % 2) == 0 {
            index - 1
        } else {
            index + 1
        }
    }

    fn get_parent_index(index: u32) -> u32 {
        (index - 1) / 2
    }

    fn is_leaf_position_even(index: u32) -> bool {
        (index % 2) == 0
    }

    // Creating a proof that a specific leaf exists.
    pub fn generate_proof(&self, leaf_index: u32) -> MerkleResult<Vec<u32>>{
        let mut proof: Vec<u32> = vec![leaf_index];
        let mut next_parent_sibling_index = MerkleTree::get_parent_index(leaf_index);

        println!("Next sibling index {next_parent_sibling_index}");
        println!("here 1");
        
        while next_parent_sibling_index != 0 {
            println!("here 2");
            proof.push(next_parent_sibling_index);
            next_parent_sibling_index = MerkleTree::get_parent_index(next_parent_sibling_index);
            // next_parent_sibling_index = MerkleTree::get_parent_index(leaf_index);
        }
        println!("here 3");
        
        Ok(proof)
    }

    // Verifying the proof that was generated
    pub fn verify_proof(&self, proof: Vec<u32>) -> MerkleResult<bool> {
        if proof.len() < 1 {
            return Err(Error) // can't proof an empty list.
        }

        let leaf_to_proof_index = proof[0] as usize;
        let leaf_to_proof = &self.nodes[leaf_to_proof_index];
        let leaf_to_proof_sibling_index = MerkleTree::get_sibling_index(leaf_to_proof_index as u32) as usize;
        let leaf_to_proof_sibling = &self.nodes[leaf_to_proof_sibling_index];

        println!("Hash for node index {leaf_to_proof_index} is {}", leaf_to_proof.stringify_hash_bytes());
        println!("Hash for node index {leaf_to_proof_sibling_index} is {}", leaf_to_proof_sibling.stringify_hash_bytes());
        
        let stringified_siblings = if MerkleTree::is_leaf_position_even(leaf_to_proof_index as u32) {
            MerkleTree::stringify_siblings_hash(&leaf_to_proof_sibling, leaf_to_proof)
        } else {
            MerkleTree::stringify_siblings_hash(leaf_to_proof,&leaf_to_proof_sibling)
        };

        let mut parent_node = Leaf { hash: Leaf::hash_data(stringified_siblings.as_bytes())};

        println!("Parent hash for node index {leaf_to_proof_index} and {leaf_to_proof_sibling_index} is {}", parent_node.stringify_hash_bytes());

        for (_index, proof_index) in proof[1..].iter().enumerate() {
            // if 

            // let parent_node_sibling_index = proof_index;
            let parent_node_sibling = &self.nodes[*proof_index as usize]; // should be the node not sibling
            // let parent_node_sibling = &self.nodes[parent_node_sibling_index];

            let leaf_to_proof_sibling_index = MerkleTree::get_sibling_index(*proof_index as u32) as usize;
            println!("Sibling index of {proof_index} is {leaf_to_proof_sibling_index}");
            let leaf_to_proof_sibling = &self.nodes[leaf_to_proof_sibling_index];
            
            let stringified_siblings = if MerkleTree::is_leaf_position_even(*proof_index as u32) {
                MerkleTree::stringify_siblings_hash(&parent_node, leaf_to_proof_sibling)
            } else {
                MerkleTree::stringify_siblings_hash(leaf_to_proof_sibling,&parent_node)
            };

            parent_node = Leaf { hash: Leaf::hash_data(stringified_siblings.as_bytes())};
            println!("Parent hash for node index {proof_index} and {leaf_to_proof_sibling_index} is {}", parent_node.stringify_hash_bytes())
        }

        if parent_node.stringify_hash_bytes() == self.root_hash.stringify_hash_bytes() {
            return Ok(true)
        }

        Ok(false)
    }
}


impl Leaf {

    pub fn new(data: GenericArray) -> Self {
        Self {
            hash: data
        }
    }

    // pub fn hash_data (data: &[u8]) -> String {
    // pub fn hash_data (data: &[u8]) -> Vec<u8> {
    pub fn hash_data (data: &[u8]) -> GenericArray {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        result.into()
        // result.to_vec()
        // let raw_string = format!("{:x}", result);
        // println!("The result is {:?}", raw_string);
        // raw_string
    }

    pub fn stringify_hash_bytes(&self) -> String {
    // pub fn stringify_hash_bytes(&self, bytes: GenericArray) -> String {
        self.hash.iter().map(|byte| format!("{:x}", byte)).collect()
        // bytes.iter().map(|byte| format!("{:x}", byte)).collect()
    }

    fn empty_node_hash () -> GenericArray {
        let empty = [0];
        Leaf::hash_data(&empty)
    }
}