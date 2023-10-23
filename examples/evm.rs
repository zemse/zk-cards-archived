use halo2_utils::{
    ethers::utils::keccak256,
    halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        dev::MockProver,
        plonk::{
            create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column,
            ConstraintSystem, Error, Fixed, Instance, ProvingKey, VerifyingKey,
        },
        poly::{
            commitment::{Params, ParamsProver},
            kzg::{
                commitment::{KZGCommitmentScheme, ParamsKZG},
                multiopen::{ProverGWC, VerifierGWC},
                strategy::AccumulatorStrategy,
            },
            Rotation, VerificationStrategy,
        },
        transcript::{TranscriptReadBuffer, TranscriptWriterBuffer},
    },
};
use halo2_utils::{
    example_circuit::MyCircuit,
    snark_verifier::{
        loader::evm::{self, deploy_and_call, encode_calldata, EvmLoader},
        pcs::kzg::{Gwc19, KzgAs},
        system::halo2::{compile, transcript::evm::EvmTranscript, Config},
        verifier::{self, SnarkVerifier},
    },
};
use halo2_utils::{
    halo2_proofs::halo2curves::{
        bn256::{Bn256, Fq, Fr, G1Affine},
        ff::Field,
    },
    CircuitExt,
};
use itertools::Itertools;
use rand::{rngs::OsRng, RngCore};
use std::rc::Rc;
use zk_card::distinct_single_key::DistinctSingleKeyCircuit;

type PlonkVerifier = verifier::plonk::PlonkVerifier<KzgAs<Bn256, Gwc19>>;

#[derive(Clone, Copy)]
struct StandardPlonkConfig {
    a: Column<Advice>,
    b: Column<Advice>,
    c: Column<Advice>,
    q_a: Column<Fixed>,
    q_b: Column<Fixed>,
    q_c: Column<Fixed>,
    q_ab: Column<Fixed>,
    constant: Column<Fixed>,
    #[allow(dead_code)]
    instance: Column<Instance>,
}

impl StandardPlonkConfig {
    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self {
        let [a, b, c] = [(); 3].map(|_| meta.advice_column());
        let [q_a, q_b, q_c, q_ab, constant] = [(); 5].map(|_| meta.fixed_column());
        let instance = meta.instance_column();

        [a, b, c].map(|column| meta.enable_equality(column));

        meta.create_gate(
            "q_a·a + q_b·b + q_c·c + q_ab·a·b + constant + instance = 0",
            |meta| {
                let [a, b, c] = [a, b, c].map(|column| meta.query_advice(column, Rotation::cur()));
                let [q_a, q_b, q_c, q_ab, constant] = [q_a, q_b, q_c, q_ab, constant]
                    .map(|column| meta.query_fixed(column, Rotation::cur()));
                let instance = meta.query_instance(instance, Rotation::cur());
                Some(
                    q_a * a.clone()
                        + q_b * b.clone()
                        + q_c * c
                        + q_ab * a * b
                        + constant
                        + instance,
                )
            },
        );

        StandardPlonkConfig {
            a,
            b,
            c,
            q_a,
            q_b,
            q_c,
            q_ab,
            constant,
            instance,
        }
    }
}

#[derive(Clone, Default)]
struct StandardPlonk(Fr);

impl StandardPlonk {
    fn rand<R: RngCore>(mut rng: R) -> Self {
        Self(Fr::from(rng.next_u32() as u64))
    }

    fn num_instance() -> Vec<usize> {
        vec![1]
    }

    fn instances(&self) -> Vec<Vec<Fr>> {
        vec![vec![self.0]]
    }
}

impl Circuit<Fr> for StandardPlonk {
    type Config = StandardPlonkConfig;
    type FloorPlanner = SimpleFloorPlanner;
    #[cfg(feature = "halo2_circuit_params")]
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        meta.set_minimum_degree(4);
        StandardPlonkConfig::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "",
            |mut region| {
                region.assign_advice(|| "", config.a, 0, || Value::known(self.0))?;
                region.assign_fixed(|| "", config.q_a, 0, || Value::known(-Fr::ONE))?;

                region.assign_advice(|| "", config.a, 1, || Value::known(-Fr::from(5)))?;
                for (idx, column) in (1..).zip([
                    config.q_a,
                    config.q_b,
                    config.q_c,
                    config.q_ab,
                    config.constant,
                ]) {
                    region.assign_fixed(|| "", column, 1, || Value::known(Fr::from(idx)))?;
                }

                let a = region.assign_advice(|| "", config.a, 2, || Value::known(Fr::ONE))?;
                a.copy_advice(|| "", &mut region, config.b, 3)?;
                a.copy_advice(|| "", &mut region, config.c, 4)?;

                Ok(())
            },
        )
    }
}

fn gen_srs(k: u32) -> ParamsKZG<Bn256> {
    ParamsKZG::<Bn256>::setup(k, OsRng)
}

fn gen_pk<C: Circuit<Fr>>(params: &ParamsKZG<Bn256>, circuit: &C) -> ProvingKey<G1Affine> {
    let vk = keygen_vk(params, circuit).unwrap();
    keygen_pk(params, vk, circuit).unwrap()
}

fn gen_proof<C: Circuit<Fr>>(
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    circuit: C,
    instances: Vec<Vec<Fr>>,
) -> Vec<u8> {
    MockProver::run(params.k(), &circuit, instances.clone())
        .unwrap()
        .assert_satisfied();

    let instances = instances
        .iter()
        .map(|instances| instances.as_slice())
        .collect_vec();
    let proof = {
        let mut transcript = TranscriptWriterBuffer::<_, G1Affine, _>::init(Vec::new());
        create_proof::<KZGCommitmentScheme<Bn256>, ProverGWC<_>, _, _, EvmTranscript<_, _, _, _>, _>(
            params,
            pk,
            &[circuit],
            &[instances.as_slice()],
            OsRng,
            &mut transcript,
        )
        .unwrap();
        transcript.finalize()
    };

    let accept = {
        let mut transcript = TranscriptReadBuffer::<_, G1Affine, _>::init(proof.as_slice());
        VerificationStrategy::<_, VerifierGWC<_>>::finalize(
            verify_proof::<_, VerifierGWC<_>, _, EvmTranscript<_, _, _, _>, _>(
                params.verifier_params(),
                pk.get_vk(),
                AccumulatorStrategy::new(params.verifier_params()),
                &[instances.as_slice()],
                &mut transcript,
            )
            .unwrap(),
        )
    };
    assert!(accept);

    proof
}

fn gen_evm_verifier(
    params: &ParamsKZG<Bn256>,
    vk: &VerifyingKey<G1Affine>,
    num_instance: Vec<usize>,
) -> Vec<u8> {
    println!("1");
    let protocol = compile(
        params,
        vk,
        Config::kzg().with_num_instance(num_instance.clone()),
    );
    let vk = (params.get_g()[0], params.g2(), params.s_g2()).into();

    let loader = EvmLoader::new::<Fq, Fr>();
    let protocol = protocol.loaded(&loader);
    let mut transcript = EvmTranscript::<_, Rc<EvmLoader>, _, _>::new(&loader);

    let instances = transcript.load_instances(num_instance);
    let proof = PlonkVerifier::read_proof(&vk, &protocol, &instances, &mut transcript).unwrap();
    PlonkVerifier::verify(&vk, &protocol, &instances, &proof).unwrap();

    println!("solidity code {}", loader.solidity_code());

    evm::compile_solidity(&loader.solidity_code())
}

fn evm_verify(deployment_code: Vec<u8>, instances: Vec<Vec<Fr>>, proof: Vec<u8>) {
    let calldata = encode_calldata(&instances, &proof);
    println!("calldata: {:?}", (calldata));
    let gas_cost = deploy_and_call(deployment_code, calldata).unwrap();
    dbg!(gas_cost);
}

fn main() {
    let params = gen_srs(6);

    // let circuit = StandardPlonk::rand(OsRng);
    let raw_cards = randomize(std::array::from_fn(|i| i as u64), 20);
    let circuit = DistinctSingleKeyCircuit::<Fr, 4, 1, 31> {
        raw_cards,
        key: 3,
        key_salt: Fr::from(0x1234),
    };
    // let circuit = MyCircuit {
    //     a: Fr::from(3),
    //     b: Fr::from(4),
    //     _marker: std::marker::PhantomData,
    // };
    let pk = gen_pk(&params, &circuit);
    println!("11");
    let deployment_code = gen_evm_verifier(&params, pk.get_vk(), StandardPlonk::num_instance());

    let proof = gen_proof(&params, &pk, circuit.clone(), circuit.instances());
    evm_verify(deployment_code, circuit.instances(), proof);
}

fn randomize<const N: usize>(mut arr: [u64; N], rounds: usize) -> [u64; N] {
    let mut seed = [0; 32];
    for _ in 0..rounds {
        seed = keccak256(seed);
        for i in 0..16 {
            arr.swap((seed[i] as usize) % N, (seed[i + 16] as usize) % N);
        }
    }
    arr
}
