use std::marker::PhantomData;

use halo2_utils::{
    halo2_proofs::{
        circuit::{AssignedCell, Layouter, Region, Value},
        plonk::{Advice, Column, Error, Selector},
        poly::Rotation,
    },
    FieldExt,
};

type Cell<F> = AssignedCell<F, F>;

#[derive(Clone)]
pub struct GateChip<F: FieldExt> {
    q_gate: Selector,
    advice: Column<Advice>,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> GateChip<F> {
    pub fn configure(meta: &mut halo2_utils::halo2_proofs::plonk::ConstraintSystem<F>) -> Self {
        let q_gate = meta.selector();
        let advice = meta.advice_column();
        meta.enable_equality(advice);

        meta.create_gate("grand condition", |meta| {
            let q_gate = meta.query_selector(q_gate);
            let a = meta.query_advice(advice, Rotation::cur());
            let b = meta.query_advice(advice, Rotation::next());
            let c = meta.query_advice(advice, Rotation(2));
            let d = meta.query_advice(advice, Rotation(3));
            vec![q_gate * (a * b + c - d)]
        });

        Self {
            q_gate,
            advice,
            _marker: PhantomData,
        }
    }

    pub fn annotations() -> (
        Vec<&'static str>,
        Vec<&'static str>,
        Vec<&'static str>,
        Vec<&'static str>,
    ) {
        (vec!["advice"], vec![], vec![], vec!["q_gate"])
    }

    pub fn load_private(
        &self,
        mut layouter: impl Layouter<F>,
        value: Value<F>,
    ) -> Result<Cell<F>, Error> {
        layouter.assign_region(
            || "load private",
            |mut region| region.assign_advice(|| "private input", self.advice, 0, || value),
        )
    }

    pub fn load_constant(
        &self,
        mut layouter: impl Layouter<F>,
        constant: F,
    ) -> Result<Cell<F>, Error> {
        layouter.assign_region(
            || "load constant",
            |mut region| {
                region.assign_advice_from_constant(|| "constant value", self.advice, 0, constant)
            },
        )
    }

    pub fn add(
        &self,
        mut layouter: impl Layouter<F>,
        a: Cell<F>,
        c: Cell<F>,
    ) -> Result<Cell<F>, Error> {
        layouter.assign_region(
            || "mul",
            |mut region: Region<'_, F>| {
                self.q_gate.enable(&mut region, 0)?;

                a.copy_advice(|| "a", &mut region, self.advice, 0)?;
                region.assign_advice(|| "b", self.advice, 1, || Value::known(F::ONE))?;
                c.copy_advice(|| "c", &mut region, self.advice, 2)?;

                let value = a.value().copied() + c.value();
                region.assign_advice(|| "d", self.advice, 3, || value)
            },
        )
    }

    pub fn mul(
        &self,
        mut layouter: impl Layouter<F>,
        a: Cell<F>,
        b: Cell<F>,
    ) -> Result<Cell<F>, Error> {
        layouter.assign_region(
            || "mul",
            |mut region: Region<'_, F>| {
                self.q_gate.enable(&mut region, 0)?;

                a.copy_advice(|| "a", &mut region, self.advice, 0)?;
                b.copy_advice(|| "b", &mut region, self.advice, 1)?;
                region.assign_advice(|| "c", self.advice, 2, || Value::known(F::ZERO))?;

                let value = a.value().copied() * b.value();
                region.assign_advice(|| "d", self.advice, 3, || value)
            },
        )
    }

    pub fn addmul(
        &self,
        mut layouter: impl Layouter<F>,
        a: Cell<F>,
        b: Cell<F>,
        c: Cell<F>,
    ) -> Result<Cell<F>, Error> {
        layouter.assign_region(
            || "mul",
            |mut region: Region<'_, F>| {
                self.q_gate.enable(&mut region, 0)?;

                a.copy_advice(|| "a", &mut region, self.advice, 0)?;
                b.copy_advice(|| "b", &mut region, self.advice, 1)?;
                b.copy_advice(|| "c", &mut region, self.advice, 2)?;

                let value = a.value().copied() * b.value() + c.value();
                region.assign_advice(|| "d", self.advice, 3, || value)
            },
        )
    }
}
