use std::marker::PhantomData;

use halo2_utils::{
    halo2_gadgets::poseidon::{
        primitives::{self as poseidon, generate_constants, ConstantLength, Mds, Spec},
        Hash, Pow5Chip,
    },
    halo2_proofs::{circuit::Layouter, plonk::Error},
    FieldExt,
};

pub fn poseidon_sync<F: FieldExt, const LENGTH: usize>(input: [F; LENGTH]) -> F {
    poseidon::Hash::<F, MySpec<F, 3, 2>, ConstantLength<LENGTH>, 3, 2>::init().hash(input)
}

#[derive(Clone)]
pub struct PoseidonChip<F: FieldExt, const LENGTH: usize> {
    pub chip: Pow5Chip<F, 3, 2>,
}

impl<F: FieldExt, const LENGTH: usize> PoseidonChip<F, LENGTH> {
    pub fn configure(meta: &mut halo2_utils::halo2_proofs::plonk::ConstraintSystem<F>) -> Self {
        let state = (0..3).map(|_| meta.advice_column()).collect::<Vec<_>>();
        let partial_sbox = meta.advice_column();
        let rc_a = (0..3).map(|_| meta.fixed_column()).collect::<Vec<_>>();
        let rc_b = (0..3).map(|_| meta.fixed_column()).collect::<Vec<_>>();
        meta.enable_constant(rc_b[0]);

        let config = Pow5Chip::<F, 3, 2>::configure::<MySpec<F, 3, 2>>(
            meta,
            state.try_into().unwrap(),
            partial_sbox,
            rc_a.try_into().unwrap(),
            rc_b.try_into().unwrap(),
        );
        Self {
            chip: Pow5Chip::<F, 3, 2>::construct(config),
        }
    }

    pub fn construct(
        &self,
        mut layouter: impl Layouter<F>,
    ) -> Result<Hash<F, Pow5Chip<F, 3, 2>, MySpec<F, 3, 2>, ConstantLength<2>, 3, 2>, Error> {
        Hash::<_, _, MySpec<F, 3, 2>, ConstantLength<2>, 3, 2>::init(
            self.chip.clone(),
            layouter.namespace(|| "poseidon init"),
        )
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MySpec<F: FieldExt, const WIDTH: usize, const RATE: usize>(PhantomData<F>);

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
