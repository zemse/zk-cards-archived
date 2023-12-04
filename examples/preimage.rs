use halo2_utils::halo2_proofs::halo2curves::bn256::Fr;

fn main() {
    let k = 7;

    let circuit = zk_card::preimage_circuit::PreimageCircuit::<Fr, 5> {
        a: Fr::from(3),
        b: Fr::from(4),
    };

    // halo2_utils::info_printer::print(k, &circuit).unwrap();
    // halo2_utils::assignments_printer::print(k, &circuit, vec!["advice", "instance", "q_gate"])
    //     .unwrap();
    // halo2_utils::assignments_printer::print_all(
    //     k,
    //     &circuit,
    //     Some(vec![halo2_utils::assignments_printer::Column::Fixed(0)]),
    // )
    // .unwrap();
    println!();

    zk_card::evm::run(k, &circuit);
}
