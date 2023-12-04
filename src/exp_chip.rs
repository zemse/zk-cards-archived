use crate::gate_chip::GateChip;
use halo2_utils::{
    halo2_proofs::{
        circuit::{AssignedCell, Layouter},
        plonk::Error,
    },
    FieldExt,
};

type Cell<F> = AssignedCell<F, F>;

pub struct ExpChip<F: FieldExt, const N: usize> {
    gate_chip: GateChip<F>,
}

impl<F: FieldExt, const N: usize> ExpChip<F, N> {
    pub fn from(gate_chip: GateChip<F>) -> Self {
        Self { gate_chip }
    }

    pub fn exp(
        &self,
        mut layouter: impl Layouter<F>,
        a: Cell<F>,
        b: Cell<F>,
    ) -> Result<Cell<F>, Error> {
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
        let exp = self
            .gate_chip
            .addmul(layouter.namespace(|| "add mul"), w, n, sum)?;

        Ok(exp)
    }
}
