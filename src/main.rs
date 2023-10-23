mod distinct_single_key;
use std::{path::PathBuf, rc::Rc, str::FromStr};

use halo2_utils::{
    self, assignments_printer, ethers,
    ethers::utils::keccak256,
    example_circuit::MyCircuit,
    halo2_proofs::{
        dev::MockProver,
        halo2curves::bn256::{Bn256, Fq, Fr, G1Affine},
        plonk::{keygen_pk, keygen_vk, ProvingKey, VerifyingKey},
        poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
    },
    info_printer, CircuitExt, RealProver,
};
use halo2_utils::{
    rand_chacha::rand_core::OsRng,
    snark_verifier::{
        loader::evm::{self, deploy_and_call, encode_calldata, EvmLoader},
        pcs::kzg::{Gwc19, KzgAs},
        system::halo2::{compile, transcript::evm::EvmTranscript, Config},
        verifier::{self, SnarkVerifier},
    },
};

use crate::distinct_single_key::DistinctSingleKeyCircuit;

fn main() {
    let raw_cards = randomize(std::array::from_fn(|i| i as u64), 20);

    let circuit = DistinctSingleKeyCircuit::<Fr, 4, 1, 31> {
        raw_cards,
        key: 3,
        key_salt: Fr::from(0x1234),
    };
    // let circuit = MyCircuit {
    //     a: Fr::from(3),
    //     b: Fr::from(4),
    //     _marker: std::marker::PhantomData,
    // };

    let k = 7;

    let prover = MockProver::run(k, &circuit, circuit.instances()).unwrap();

    info_printer::print(k, &circuit).unwrap();

    // assignments_printer::print(
    //     k,
    //     &circuit,
    //     vec![
    //         "q_raw_cards",
    //         "q_range",
    //         "q_key_equal_gate",
    //         "q_compressor",
    //         "advice",
    //         "fixed",
    //         "instance",
    //     ],
    // )
    // .unwrap();

    prover.assert_satisfied();

    // let mut real_prover = RealProver::from(k, circuit);
    // let proof = real_prover.run().unwrap();
    // proof
    //     .write_to_file(&PathBuf::from_str("./out/proof.json").unwrap())
    //     .unwrap();

    // println!(
    //     "calldata: {:?}",
    //     ethers::utils::hex::encode(proof.encode_calldata())
    // );

    // let verifier = real_prover.verifier();
    // verifier.run(proof).unwrap();
    // let res = verifier
    //     .generate_yul(Some(&PathBuf::from_str("./out/verifier.yul").unwrap()))
    //     .unwrap();
    // println!("{res}");
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
