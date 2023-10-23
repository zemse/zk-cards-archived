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
    grand_chip::{self, GrandChip},
    poseidon_chip::{poseidon_sync, PoseidonChip},
};

#[derive(Clone)]
pub struct AddModCircuit<F: FieldExt> {
    pub a: F,
    pub b: F,
    pub n: F,
}

#[derive(Clone)]
pub struct AddModCircuitConfig<F: FieldExt> {
    grand_chip: GrandChip<F>,
    poseidon_chip: PoseidonChip<F, 2>,
    instance: Column<Instance>,
}

impl<F: FieldExt> Circuit<F> for AddModCircuit<F> {
    type Config = AddModCircuitConfig<F>;

    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        todo!()
    }

    fn configure(meta: &mut halo2_utils::halo2_proofs::plonk::ConstraintSystem<F>) -> Self::Config {
        let grand_chip = GrandChip::configure(meta);
        let poseidon_chip = PoseidonChip::configure(meta);

        let instance = meta.instance_column();
        meta.enable_equality(instance);

        AddModCircuitConfig {
            grand_chip,
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

        let a = utils.load_private(layouter.namespace(|| "load a"), Value::known(self.a))?;
        let b = utils.load_private(layouter.namespace(|| "load b"), Value::known(self.b))?;

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

impl<F: FieldExt> CircuitExt<F> for AddModCircuit<F> {
    fn annotations(&self) -> (Vec<&str>, Vec<&str>, Vec<&str>, Vec<&str>) {
        let grand_chip = GrandChip::<F>::annotations();
        (
            grand_chip.0.iter().chain([].iter()).copied().collect(),
            grand_chip.1.iter().chain([].iter()).copied().collect(),
            grand_chip
                .2
                .iter()
                .chain(["instance"].iter())
                .copied()
                .collect(),
            grand_chip.3.iter().chain([].iter()).copied().collect(),
        )
    }

    fn instances(&self) -> Vec<Vec<F>> {
        let intermediate = (self.a * self.b).square();
        vec![vec![poseidon_sync([
            self.a + poseidon_sync([intermediate, intermediate]),
            self.a,
        ])]]
    }
}
