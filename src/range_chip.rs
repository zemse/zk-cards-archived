use std::marker::PhantomData;

use halo2_utils::{
    halo2_proofs::{
        circuit::{AssignedCell, Layouter, Value},
        plonk::{Advice, Column, Error, Selector, TableColumn},
        poly::Rotation,
    },
    FieldExt,
};

type Cell<F> = AssignedCell<F, F>;

#[derive(Clone)]
pub struct RangeConfig<F: FieldExt, const SIZE: usize> {
    q_range: Selector,
    lookup: TableColumn,
    advice: Column<Advice>,
    _marker: PhantomData<F>,
}

impl<F: FieldExt, const SIZE: usize> RangeConfig<F, SIZE> {
    pub fn configure(
        meta: &mut halo2_utils::halo2_proofs::plonk::ConstraintSystem<F>,
        advice: Option<Column<Advice>>,
    ) -> Self {
        let q_range = meta.complex_selector();
        let lookup = meta.lookup_table_column();
        let advice = advice.unwrap_or(meta.advice_column());

        meta.lookup("value must be in range", |meta| {
            let q_range = meta.query_selector(q_range);
            let advice = meta.query_advice(advice, Rotation::cur());

            vec![(q_range * advice, lookup)]
        });

        RangeConfig {
            q_range,
            lookup,
            advice,
            _marker: PhantomData,
        }
    }

    pub fn construct(&self, mut layouter: impl Layouter<F>) -> Result<RangeChip<F, SIZE>, Error> {
        layouter.namespace(|| "range init").assign_table(
            || "range table",
            |mut table| {
                for i in 0..SIZE {
                    table.assign_cell(
                        || "assign",
                        self.lookup,
                        i,
                        || Value::known(F::from(i as u64)),
                    )?
                }
                Ok(())
            },
        )?;

        Ok(RangeChip {
            config: self.clone(),
            _marker: PhantomData,
        })
    }
}

#[derive(Clone)]
pub struct RangeChip<F: FieldExt, const SIZE: usize> {
    config: RangeConfig<F, SIZE>,
    _marker: PhantomData<F>,
}

impl<F: FieldExt, const SIZE: usize> RangeChip<F, SIZE> {
    pub fn range_constrain(
        &self,
        mut layouter: impl Layouter<F>,
        cell: Cell<F>,
    ) -> Result<Cell<F>, Error> {
        layouter.namespace(|| "range constrain").assign_region(
            || "range constrain",
            |mut region| {
                self.config.q_range.enable(&mut region, 0)?;
                cell.copy_advice(|| "range", &mut region, self.config.advice, 0)
            },
        )
    }
}
