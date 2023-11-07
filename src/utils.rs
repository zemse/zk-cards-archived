use halo2_utils::ethers::utils::keccak256;

pub fn randomize<const N: usize>(mut arr: [u64; N], rounds: usize) -> [u64; N] {
    let mut seed = [0; 32];
    for _ in 0..rounds {
        seed = keccak256(seed);
        for i in 0..16 {
            arr.swap((seed[i] as usize) % N, (seed[i + 16] as usize) % N);
        }
    }
    arr
}
