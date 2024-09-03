#[allow(unused_imports)]
#[allow(unused_variables)]
use halo2_utils::{
    halo2_gadgets::poseidon::{
        primitives::{self as poseidon, generate_constants, ConstantLength, Mds, Spec},
        Hash, Pow5Chip, Pow5Config,
    },
    halo2_proofs::{
        circuit::{SimpleFloorPlanner, Value},
        plonk::{Advice, Circuit, Column, Expression, Fixed, Instance, Selector},
        poly::Rotation,
    },
    CircuitExt, Expr, FieldExt,
};
#[allow(unused_imports)]
#[allow(unused_variables)]
use std::marker;

#[derive(Debug, Clone)]
pub struct DistinctSingleKeyCircuit<
    F: FieldExt,
    const NUM_CARDS: usize,
    const WORD_BYTES: usize,
    const FIELD_BYTES: usize,
> {
    pub raw_cards: [u64; NUM_CARDS],
    pub key: u64,
    pub key_salt: F,
}

#[derive(Clone, Debug)]
pub struct DSKConfig<F: FieldExt> {
    q_raw_cards: Selector,
    q_range_check: Selector,
    q_key_equal_gate: Selector,
    q_compressor: Selector,
    advice: Column<Advice>,
    fixed: Column<Fixed>,
    instance: Column<Instance>,
    poseidon: Pow5Config<F, 3, 2>,
}

impl<F: FieldExt, const NUM_CARDS: usize, const WORD_BYTES: usize, const FIELD_BYTES: usize>
    Circuit<F> for DistinctSingleKeyCircuit<F, NUM_CARDS, WORD_BYTES, FIELD_BYTES>
{
    type Config = DSKConfig<F>;

    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        todo!()
    }

    fn configure(meta: &mut halo2_utils::halo2_proofs::plonk::ConstraintSystem<F>) -> Self::Config {
        let q_raw_cards = meta.complex_selector();
        let q_range_check = meta.complex_selector();
        let q_key_equal_gate = meta.complex_selector();
        let q_compressor = meta.complex_selector();
        let advice = meta.advice_column();
        let fixed = meta.fixed_column();
        let instance = meta.instance_column();
        meta.enable_equality(advice);
        meta.enable_equality(instance);

        let state = (0..3).map(|_| meta.advice_column()).collect::<Vec<_>>();
        let partial_sbox = meta.advice_column();
        let rc_a = (0..3).map(|_| meta.fixed_column()).collect::<Vec<_>>();
        let rc_b = (0..3).map(|_| meta.fixed_column()).collect::<Vec<_>>();
        meta.enable_constant(rc_b[0]);
        let poseidon = Pow5Chip::<F, 3, 2>::configure::<MySpec<F, 3, 2>>(
            meta,
            state.try_into().unwrap(),
            partial_sbox,
            rc_a.try_into().unwrap(),
            rc_b.try_into().unwrap(),
        );

        meta.lookup_any("raw cards must be unique", |meta| {
            // fixed table
            let fixed = meta.query_fixed(fixed, Rotation::cur());

            // witness
            let q_raw_cards = meta.query_selector(q_raw_cards);
            let advice = meta.query_advice(advice, Rotation::cur());

            vec![(fixed, q_raw_cards * advice)]
        });

        meta.lookup_any("value must be in range", |meta| {
            // witness
            let q_range_check = meta.query_selector(q_range_check);
            let advice = meta.query_advice(advice, Rotation::cur());

            // fixed table
            let fixed = meta.query_fixed(fixed, Rotation::cur());

            vec![(q_range_check * advice, fixed)]
        });

        meta.create_gate("key cells must be equal", |meta| {
            let q_key_equal_gate = meta.query_selector(q_key_equal_gate);
            let advice_cur = meta.query_advice(advice, Rotation::cur());
            let advice_next = meta.query_advice(advice, Rotation::next());
            vec![q_key_equal_gate * (advice_cur - advice_next)]
        });

        meta.create_gate("encryption should be correct", |meta| {
            let q_raw_cards = meta.query_selector(q_raw_cards);
            let raw_input = meta.query_advice(advice, Rotation::cur());
            let key = meta.query_advice(advice, Rotation(NUM_CARDS as i32));
            let solution = meta.query_advice(advice, Rotation(2 * NUM_CARDS as i32));
            let encryption = meta.query_advice(advice, Rotation(3 * NUM_CARDS as i32));
            vec![
                q_raw_cards
                    * (raw_input + key
                        - solution * Expression::Constant(F::from(NUM_CARDS as u64))
                        - encryption),
            ]
        });

        meta.create_gate("compression should be correct", |meta| {
            let q_compressor = meta.query_selector(q_compressor);

            let num_words_in_field = FIELD_BYTES / WORD_BYTES;
            let num_fields = NUM_CARDS * WORD_BYTES / FIELD_BYTES + 1;
            // let queries = (0..num_words_in_field)
            //     .map(|i| meta.query_advice(advice, Rotation(-(i as i32) - 1)))
            //     .collect();
            let mut expr = Expression::Constant(F::ZERO);
            // for i in ((num_words_in_field + 1)..((num_words_in_field) * 2 + 1)).rev() {
            for i in (((num_fields - 1) * num_words_in_field + 1)
                ..((num_words_in_field) * (num_fields) + 1))
                .rev()
            {
                let value = meta.query_advice(advice, Rotation(-(i as i32)));
                expr = expr * Expression::Constant(F::from(1 << (WORD_BYTES * 8))) + value;
            }

            let acc = meta.query_advice(advice, Rotation::cur());

            vec![q_compressor * (acc - expr)]
        });

        DSKConfig {
            q_raw_cards,
            q_range_check,
            q_key_equal_gate,
            q_compressor,
            advice,
            fixed,
            instance,
            poseidon,
        }
    }

    #[allow(clippy::needless_range_loop)]
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl halo2_utils::halo2_proofs::circuit::Layouter<F>,
    ) -> Result<(), halo2_utils::halo2_proofs::plonk::Error> {
        layouter.assign_region(
            || "range lookup table",
            |mut region| {
                for i in 0..NUM_CARDS {
                    region.assign_fixed(
                        || "range lookup table entry",
                        config.fixed,
                        i,
                        || Value::known(F::from(i as u64)),
                    )?;
                }
                Ok(())
            },
        )?;

        let (cells, key, key_salt) = layouter.assign_region(
            || "witness",
            |mut region| {
                let mut offset = 0;

                // Assign raw cards
                for i in 0..NUM_CARDS {
                    config.q_raw_cards.enable(&mut region, i)?;
                    config.q_range_check.enable(&mut region, i)?;
                    region.assign_advice(
                        || "raw card cell",
                        config.advice,
                        i,
                        || Value::known(F::from(self.raw_cards[i])),
                    )?;
                }
                offset += NUM_CARDS;

                // Assign key
                let mut key: Option<_> = None;
                for i in 0..NUM_CARDS {
                    config.q_range_check.enable(&mut region, offset + i)?;
                    if i < NUM_CARDS - 1 {
                        // since gate checks cur == next, we need last one to not be on
                        config.q_key_equal_gate.enable(&mut region, offset + i)?;
                    }
                    key = Some(region.assign_advice(
                        || "key cell",
                        config.advice,
                        offset + i,
                        || Value::known(F::from(self.key)),
                    )?);
                }
                offset += NUM_CARDS;

                // Assign addmod intermediate solution
                for i in 0..NUM_CARDS {
                    let raw_card = F::from(self.raw_cards[i]);
                    let key = F::from(self.key);
                    let sum = raw_card + key;
                    let n = F::from(NUM_CARDS as u64);
                    let mut solution = F::ZERO;
                    while sum - solution * n >= n {
                        solution += F::ONE;
                    }
                    region.assign_advice(
                        || "solution cell",
                        config.advice,
                        offset + i,
                        || Value::known(solution),
                    )?;
                }
                offset += NUM_CARDS;

                // Assign addmod encryption
                let mut encrypted_cards = [0; NUM_CARDS];
                for i in 0..NUM_CARDS {
                    config.q_range_check.enable(&mut region, offset + i)?;
                    encrypted_cards[i] = (self.raw_cards[i] + self.key) % NUM_CARDS as u64;
                    let encryption = F::from(encrypted_cards[i]);
                    region.assign_advice(
                        || "addmod cell",
                        config.advice,
                        offset + i,
                        || Value::known(encryption),
                    )?;
                }

                let num_slots = NUM_CARDS * WORD_BYTES / FIELD_BYTES + 1;

                // assiging zero to prevent mock prover cell not assigned error
                // TODO dont assign everythign in last section
                for i in NUM_CARDS..(num_slots * FIELD_BYTES * 2 - FIELD_BYTES + 1) {
                    region.assign_advice(
                        || "temp assign",
                        config.advice,
                        offset + i,
                        || Value::known(F::ZERO),
                    )?;
                }
                offset += num_slots * FIELD_BYTES;

                // final compressed value
                let mut compressed_cells = vec![];
                for i in 0..num_slots {
                    let start = FIELD_BYTES * i;
                    let end = FIELD_BYTES * (i + 1);
                    let mut acc = F::ZERO;
                    for j in start..end {
                        if j < NUM_CARDS {
                            acc =
                                acc * F::from(1 << (WORD_BYTES * 8)) + F::from(encrypted_cards[j]);
                        } else {
                            acc *= F::from(1 << (WORD_BYTES * 8));
                        }
                    }

                    config
                        .q_compressor
                        .enable(&mut region, offset + i * FIELD_BYTES)?;

                    compressed_cells.push(region.assign_advice(
                        || "addmod cell",
                        config.advice,
                        offset + i * FIELD_BYTES,
                        || Value::known(acc),
                    )?);
                }

                offset += (num_slots - 1) * FIELD_BYTES + 1;

                let key_salt = region.assign_advice(
                    || "key_salt",
                    config.advice,
                    offset,
                    || Value::known(self.key_salt),
                )?;

                Ok((compressed_cells, key.unwrap(), key_salt))
            },
        )?;

        let mut instance_offset = 0;

        // Expose encrypted cards
        for (i, cell) in cells.iter().enumerate() {
            layouter.constrain_instance(cell.cell(), config.instance, i)?;
        }
        instance_offset += cells.len();

        // Hash of key & key salt
        let poseidon_chip = Pow5Chip::construct(config.poseidon.clone());
        let hasher = Hash::<_, _, MySpec<F, 3, 2>, ConstantLength<2>, 3, 2>::init(
            poseidon_chip,
            layouter.namespace(|| "init"),
        )?;
        let output = hasher.hash(layouter.namespace(|| "hash"), [key, key_salt])?;
        layouter.constrain_instance(output.cell(), config.instance, instance_offset)?;

        Ok(())
    }
}

impl<F: FieldExt, const NUM_CARDS: usize, const WORD_BYTES: usize, const FIELD_BYTES: usize>
    CircuitExt<F> for DistinctSingleKeyCircuit<F, NUM_CARDS, WORD_BYTES, FIELD_BYTES>
{
    #[allow(clippy::needless_range_loop)]
    fn instances(&self) -> Vec<Vec<F>> {
        // Assign addmod encryption
        let mut encrypted_cards = [0; NUM_CARDS];
        for i in 0..NUM_CARDS {
            encrypted_cards[i] = (self.raw_cards[i] + self.key) % NUM_CARDS as u64;
        }

        let num_slots = NUM_CARDS * WORD_BYTES / FIELD_BYTES + 1;
        let mut values = vec![];
        for i in 0..num_slots {
            let start = FIELD_BYTES * i;
            let end = FIELD_BYTES * (i + 1);
            let mut acc = F::ZERO;
            for j in start..end {
                if j < NUM_CARDS {
                    acc = acc * F::from(1 << (WORD_BYTES * 8)) + F::from(encrypted_cards[j]);
                } else {
                    acc *= F::from(1 << (WORD_BYTES * 8));
                }
            }
            values.push(acc);
        }

        let output = poseidon::Hash::<F, MySpec<F, 3, 2>, ConstantLength<2>, 3, 2>::init()
            .hash([F::from(self.key), self.key_salt]);
        values.push(output);

        vec![values]
    }

    // fn annotations(&self) -> (Vec<&str>, Vec<&str>, Vec<&str>, Vec<&str>) {
    //     (
    //         vec!["advice"],
    //         vec!["fixed"],
    //         vec!["instance"],
    //         vec!["q_raw_cards", "q_range", "q_key_equal_gate", "q_compressor"],
    //     )
    // }
}

#[derive(Debug, Clone, Copy)]
struct MySpec<F: FieldExt, const WIDTH: usize, const RATE: usize>(marker::PhantomData<F>);

impl<F: FieldExt, const WIDTH: usize, const RATE: usize> Spec<F, WIDTH, RATE>
    for MySpec<F, WIDTH, RATE>
{
    fn full_rounds() -> usize {
        8
    }

    fn partial_rounds() -> usize {
        56
    }

    fn sbox(val: F) -> F {
        val.pow_vartime([5])
    }

    fn secure_mds() -> usize {
        0
    }

    fn constants() -> (Vec<[F; WIDTH]>, Mds<F, WIDTH>, Mds<F, WIDTH>) {
        generate_constants::<_, Self, WIDTH, RATE>()
    }
}
