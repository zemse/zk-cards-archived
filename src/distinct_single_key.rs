use halo2_utils::{
    halo2_proofs::{
        circuit::{SimpleFloorPlanner, Value},
        plonk::{Advice, Circuit, Column, Expression, Fixed, Instance, Selector},
        poly::Rotation,
    },
    CircuitExt, Expr, FieldExt,
};

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
pub struct DSKConfig {
    q_raw_cards: Selector,
    q_range_check: Selector,
    q_key_equal_gate: Selector,
    q_compressor: Selector,
    advice: Column<Advice>,
    fixed: Column<Fixed>,
    instance: Column<Instance>,
}

impl<F: FieldExt, const NUM_CARDS: usize, const WORD_BYTES: usize, const FIELD_BYTES: usize>
    Circuit<F> for DistinctSingleKeyCircuit<F, NUM_CARDS, WORD_BYTES, FIELD_BYTES>
{
    type Config = DSKConfig;

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

        let cells = layouter.assign_region(
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
                for i in 0..NUM_CARDS {
                    config.q_range_check.enable(&mut region, offset + i)?;
                    if i < NUM_CARDS - 1 {
                        // since gate checks cur == next, we need last one to not be on
                        config.q_key_equal_gate.enable(&mut region, offset + i)?;
                    }
                    region.assign_advice(
                        || "key cell",
                        config.advice,
                        offset + i,
                        || Value::known(F::from(self.key)),
                    )?;
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
                let mut cells = vec![];
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

                    cells.push(region.assign_advice(
                        || "addmod cell",
                        config.advice,
                        offset + i * FIELD_BYTES,
                        || Value::known(acc),
                    )?);
                }

                Ok(cells)
            },
        )?;

        for (i, cell) in cells.iter().enumerate() {
            layouter.constrain_instance(cell.cell(), config.instance, i)?;
        }

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

        vec![values]
    }

    fn annotations(&self) -> (Vec<&str>, Vec<&str>, Vec<&str>, Vec<&str>) {
        (
            vec!["advice"],
            vec!["fixed"],
            vec!["instance"],
            vec!["q_raw_cards", "q_range", "q_key_equal_gate", "q_compressor"],
        )
    }
}
