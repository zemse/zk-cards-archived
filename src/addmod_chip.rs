use crate::{gate_chip::GateChip, range_chip::RangeChip};
use halo2_utils::{
    halo2_proofs::{
        circuit::{AssignedCell, Layouter},
        plonk::Error,
    },
    FieldExt,
};

type Cell<F> = AssignedCell<F, F>;

pub struct AddModChip<F: FieldExt, const N: usize> {
    gate_chip: GateChip<F>,
    range_chip: RangeChip<F, N>,
}

impl<F: FieldExt, const N: usize> AddModChip<F, N> {
    pub fn from(gate_chip: GateChip<F>, range_chip: RangeChip<F, N>) -> Self {
        Self {
            gate_chip,
            range_chip,
        }
    }

    pub fn addmod(
        &self,
        mut layouter: impl Layouter<F>,
        a: Cell<F>,
        b: Cell<F>,
    ) -> Result<Cell<F>, Error> {
        // range check inputs
        self.range_chip
            .range_constrain(layouter.namespace(|| "range check"), a.clone())?;
        self.range_chip
            .range_constrain(layouter.namespace(|| "range check"), b.clone())?;

        // add them
        let sum = self.gate_chip.add(layouter.namespace(|| "sum"), a, b)?;

        // find if they overflow or not
        let n = F::from(N as u64);
        let w = sum
            .value()
            .copied()
            .map(|sum| if sum >= n { F::ONE.neg() } else { F::ZERO });
        let w = self
            .gate_chip
            .load_private(layouter.namespace(|| "load w"), w)?;
        let n = self
            .gate_chip
            .load_constant(layouter.namespace(|| "load c"), n)?;

        // find the add mod value
        let addmod = self
            .gate_chip
            .addmul(layouter.namespace(|| "add mul"), w, n, sum)?;

        // ensure it is within range
        self.range_chip
            .range_constrain(layouter.namespace(|| "range check"), addmod.clone())?;

        Ok(addmod)
    }
}
