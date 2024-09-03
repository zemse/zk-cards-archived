use crate::poseidon_chip::{poseidon_sync, PoseidonChip};
use halo2_utils::{
    halo2_proofs::{
        circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
        plonk::{Advice, Circuit, Column, Error, Instance},
    },
    CircuitExt, FieldExt,
};

#[derive(Clone)]
pub struct PreimageCircuit<F: FieldExt, const N: usize> {
    pub a: F,
    pub b: F,
}

#[derive(Clone)]
pub struct PreimageCircuitConfig<F: FieldExt, const N: usize> {
    advice: Column<Advice>,
    instance: Column<Instance>,
    poseidon_chip: PoseidonChip<F, 2>,
}

impl<F: FieldExt, const N: usize> PreimageCircuitConfig<F, N> {
    pub fn load_private(
        &self,
        mut layouter: impl Layouter<F>,
        value: Value<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "load private",
            |mut region| region.assign_advice(|| "private input", self.advice, 0, || value),
        )
    }
}

impl<F: FieldExt, const N: usize> Circuit<F> for PreimageCircuit<F, N> {
    type Config = PreimageCircuitConfig<F, N>;

    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        todo!()
    }

    fn configure(meta: &mut halo2_utils::halo2_proofs::plonk::ConstraintSystem<F>) -> Self::Config {
        let advice = meta.advice_column();
        let instance = meta.instance_column();
        let poseidon_chip = PoseidonChip::configure(meta);
        meta.enable_equality(advice);
        meta.enable_equality(instance);

        PreimageCircuitConfig {
            advice,
            instance,
            poseidon_chip,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl halo2_utils::halo2_proofs::circuit::Layouter<F>,
    ) -> Result<(), halo2_utils::halo2_proofs::plonk::Error> {
        let a = config.load_private(layouter.namespace(|| "load a"), Value::known(self.a))?;
        let b = config.load_private(layouter.namespace(|| "load b"), Value::known(self.b))?;
        let poseidon = config
            .poseidon_chip
            .construct(layouter.namespace(|| "poseidon"))?;
        let final_hash = poseidon.hash(layouter.namespace(|| "hash"), [a, b])?;

        layouter.constrain_instance(final_hash.cell(), config.instance, 0)?;
        Ok(())
    }
}

impl<F: FieldExt, const N: usize> CircuitExt<F> for PreimageCircuit<F, N> {
    // fn annotations(&self) -> (Vec<&str>, Vec<&str>, Vec<&str>, Vec<&str>) {
    //     (vec!["advice"], vec![], vec!["instance"], vec![])
    // }

    fn instances(&self) -> Vec<Vec<F>> {
        vec![vec![poseidon_sync([self.a, self.b])]]
    }
}
