use halo2_utils::halo2_proofs::halo2curves::bn256::Fr;

fn main() {
    let k = 7;

    // let circuit = StandardPlonk::rand(OsRng);
    // let raw_cards = randomize(std::array::from_fn(|i| i as u64), 20);
    // let circuit = DistinctSingleKeyCircuit::<Fr, 4, 1, 31> {
    //     raw_cards,
    //     key: 3,
    //     key_salt: Fr::from(0x1234),
    // };
    // let circuit = MyCircuit {
    //     a: Fr::from(3),
    //     b: Fr::from(4),
    //     _marker: std::marker::PhantomData,
    // };

    let circuit = zk_card::first_circuit::FirstCircuit::<Fr, 5> {
        a: Fr::from(3),
        b: Fr::from(4),
        n: Fr::from(5),
    };

    halo2_utils::info_printer::print(k, &circuit).unwrap();
    halo2_utils::assignments_printer::print(k, &circuit, vec!["advice", "instance", "q_gate"])
        .unwrap();
    // halo2_utils::assignments_printer::print_all(
    //     k,
    //     &circuit,
    //     Some(vec![halo2_utils::assignments_printer::Column::Fixed(0)]),
    // )
    // .unwrap();
    println!();

    zk_card::evm::run(k, &circuit);
}
