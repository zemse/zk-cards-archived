use std::marker::PhantomData;

use halo2_utils::{
    halo2_proofs::{
        circuit::{Region, SimpleFloorPlanner, Value},
        plonk::{Advice, Circuit, Column, Instance, Selector},
        poly::Rotation,
    },
    CircuitExt, FieldExt,
};

use crate::{
    addmod_chip::AddModChip,
    gate_chip::{self, GateChip},
    poseidon_chip::{poseidon_sync, PoseidonChip},
    range_chip::RangeConfig,
};

#[derive(Clone)]
pub struct FirstCircuit<F: FieldExt, const N: usize> {
    pub a: F,
    pub b: F,
    pub n: F,
}

#[derive(Clone)]
pub struct FirstCircuitConfig<F: FieldExt, const N: usize> {
    grand_chip: GateChip<F>,
    range_config: RangeConfig<F, N>,
    poseidon_chip: PoseidonChip<F, 2>,
    instance: Column<Instance>,
}

impl<F: FieldExt, const N: usize> Circuit<F> for FirstCircuit<F, N> {
    type Config = FirstCircuitConfig<F, N>;

    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        todo!()
    }

    fn configure(meta: &mut halo2_utils::halo2_proofs::plonk::ConstraintSystem<F>) -> Self::Config {
        let advice = meta.advice_column();

        let grand_chip = GateChip::configure(meta, Some(advice));
        let range_config = RangeConfig::<F, N>::configure(meta, Some(advice));
        let poseidon_chip = PoseidonChip::configure(meta);

        let instance = meta.instance_column();
        meta.enable_equality(instance);

        FirstCircuitConfig {
            grand_chip,
            range_config,
            poseidon_chip,
            instance,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl halo2_utils::halo2_proofs::circuit::Layouter<F>,
    ) -> Result<(), halo2_utils::halo2_proofs::plonk::Error> {
        let utils = config.grand_chip;
        let range_chip = config
            .range_config
            .construct(layouter.namespace(|| "range_chip"))?;
        let addmod_chip = AddModChip::from(utils.clone(), range_chip.clone());

        let a = utils.load_private(layouter.namespace(|| "load a"), Value::known(self.a))?;
        let b = utils.load_private(layouter.namespace(|| "load b"), Value::known(self.b))?;

        let result = addmod_chip.addmod(layouter.namespace(|| "addmod"), a.clone(), b.clone())?;

        range_chip.range_constrain(layouter.namespace(|| "range constrain"), b.clone())?;

        let product = utils.mul(layouter.namespace(|| "mul"), a.clone(), b)?;

        let product_2 = utils.mul(layouter.namespace(|| "mul"), product.clone(), product)?;

        let poseidon = config
            .poseidon_chip
            .construct(layouter.namespace(|| "poseidon"))?;
        let hashed = poseidon.hash(
            layouter.namespace(|| "hash"),
            [product_2.clone(), product_2],
        )?;

        let sum = utils.add(layouter.namespace(|| "add"), a.clone(), hashed)?;

        let poseidon = config
            .poseidon_chip
            .construct(layouter.namespace(|| "poseidon"))?;
        let final_hash = poseidon.hash(layouter.namespace(|| "poseidon"), [sum, a])?;

        layouter.constrain_instance(final_hash.cell(), config.instance, 0)?;
        Ok(())
    }
}

impl<F: FieldExt, const N: usize> CircuitExt<F> for FirstCircuit<F, N> {
    // fn annotations(&self) -> (Vec<&str>, Vec<&str>, Vec<&str>, Vec<&str>) {
    //     let grand_chip = GateChip::<F>::annotations();
    //     (
    //         grand_chip.0.iter().chain([].iter()).copied().collect(),
    //         grand_chip.1.iter().chain([].iter()).copied().collect(),
    //         grand_chip
    //             .2
    //             .iter()
    //             .chain(["instance"].iter())
    //             .copied()
    //             .collect(),
    //         grand_chip.3.iter().chain([].iter()).copied().collect(),
    //     )
    // }

    fn instances(&self) -> Vec<Vec<F>> {
        let intermediate = (self.a * self.b).square();
        vec![vec![poseidon_sync([
            self.a + poseidon_sync([intermediate, intermediate]),
            self.a,
        ])]]
    }
}
