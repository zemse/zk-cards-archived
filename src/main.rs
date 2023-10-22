mod distinct_single_key;
use halo2_utils::{
    self, assignments_printer, ethers,
    ethers::utils::keccak256,
    halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr},
    CircuitExt,
};

fn main() {
    let raw_cards = randomize(std::array::from_fn(|i| i as u64), 20);

    let circuit = distinct_single_key::DistinctSingleKeyCircuit::<Fr, 90, 1, 31> {
        raw_cards,
        key: 3,
        key_salt: Fr::from(100),
    };

    let k = 9;

    let prover = MockProver::run(k, &circuit, circuit.instances()).unwrap();

    assignments_printer::print(
        k,
        &circuit,
        vec![
            "q_raw_cards",
            "q_range",
            "q_key_equal_gate",
            "q_compressor",
            "advice",
            "fixed",
            "instance",
        ],
    )
    .unwrap();

    prover.assert_satisfied();
}

fn randomize<const N: usize>(mut arr: [u64; N], rounds: usize) -> [u64; N] {
    let mut seed = [0; 32];
    for _ in 0..rounds {
        seed = keccak256(seed);
        for i in 0..16 {
            arr.swap((seed[i] as usize) % N, (seed[i + 16] as usize) % N);
        }
    }
    arr
}
