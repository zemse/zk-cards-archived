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
pub struct ElgamalCircuit<F: FieldExt, const N: usize> {
    pub a: F,
    pub b: F,
    pub n: F,
}

#[derive(Clone)]
pub struct ElgamalCircuitConfig<F: FieldExt, const N: usize> {
    gate_chip: GateChip<F>,
    instance: Column<Instance>,
}

impl<F: FieldExt, const N: usize> Circuit<F> for ElgamalCircuit<F, N> {
    type Config = ElgamalCircuitConfig<F, N>;

    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        todo!()
    }

    fn configure(meta: &mut halo2_utils::halo2_proofs::plonk::ConstraintSystem<F>) -> Self::Config {
        let advice = meta.advice_column();

        let gate_chip = GateChip::configure(meta, Some(advice));

        let instance = meta.instance_column();
        meta.enable_equality(instance);

        ElgamalCircuitConfig {
            gate_chip,

            instance,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl halo2_utils::halo2_proofs::circuit::Layouter<F>,
    ) -> Result<(), halo2_utils::halo2_proofs::plonk::Error> {
        let utils = config.gate_chip;

        let a = utils.load_private(layouter.namespace(|| "load a"), Value::known(self.a))?;
        let b = utils.load_private(layouter.namespace(|| "load b"), Value::known(self.b))?;

        // layouter.constrain_instance(final_hash.cell(), config.instance, 0)?;
        Ok(())
    }
}

impl<F: FieldExt, const N: usize> CircuitExt<F> for ElgamalCircuit<F, N> {
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
