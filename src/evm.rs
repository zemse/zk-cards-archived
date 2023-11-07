use halo2_utils::halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    dev::MockProver,
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column,
        ConstraintSystem, Error, Fixed, Instance, ProvingKey, VerifyingKey,
    },
    poly::{
        commitment::ParamsProver,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverGWC, VerifierGWC},
            strategy::AccumulatorStrategy,
        },
        Rotation, VerificationStrategy,
    },
    transcript::{TranscriptReadBuffer, TranscriptWriterBuffer},
};
#[allow(unused_imports)]
#[allow(unused_variables)]
use halo2_utils::snark_verifier::{
    loader::evm::{self, deploy_and_call, encode_calldata, EvmLoader},
    pcs::kzg::{Gwc19, KzgAs},
    system::halo2::{compile, transcript::evm::EvmTranscript, Config},
    verifier::{self, SnarkVerifier},
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
use serde::{Deserialize, Serialize};
use std::{
    cmp,
    fs::File,
    io::{Read, Write},
    path::PathBuf,
    rc::Rc,
    str::FromStr,
};

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

#[allow(dead_code)]
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

    evm::compile_solidity(&loader.solidity_code())
}

fn evm_verify(deployment_code: Vec<u8>, instances: Vec<Vec<Fr>>, proof: Vec<u8>) -> (usize, usize) {
    let calldata = encode_calldata(&instances, &proof);
    let calldata_len = calldata.len();
    let gas_cost = deploy_and_call(deployment_code, calldata).unwrap();
    dbg!(gas_cost);
    (calldata_len, gas_cost as usize)
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct Info {
    bytecode_len: usize,
    calldata_len: usize,
    gas_cost: usize,
}

fn format_change(a: usize, b: usize) -> String {
    match cmp::Ord::cmp(&a, &b) {
        cmp::Ordering::Less => format!(" (-{})", b - a),
        cmp::Ordering::Equal => String::new(),
        cmp::Ordering::Greater => format!(" (+{})", a - b),
    }
}

pub fn run<C: Clone + Circuit<Fr> + CircuitExt<Fr>>(k: u32, circuit: &C) {
    let params = gen_srs(k);

    let pk = gen_pk(&params, circuit);
    let deployment_code = gen_evm_verifier(&params, pk.get_vk(), StandardPlonk::num_instance());
    let bytecode_len = deployment_code.len();

    let proof = gen_proof(&params, &pk, circuit.clone(), circuit.instances());
    let (calldata_len, gas_cost) = evm_verify(deployment_code, circuit.instances(), proof);

    let new_info = Info {
        bytecode_len,
        calldata_len,
        gas_cost,
    };

    let mut file = File::open(PathBuf::from_str("./data.json").unwrap()).unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    let old_info: Info = serde_json::from_str(&contents).unwrap();

    println!(
        "bytecode_len: {}{}",
        new_info.bytecode_len,
        format_change(new_info.bytecode_len, old_info.bytecode_len)
    );
    println!(
        "calldata_len: {}{}",
        new_info.calldata_len,
        format_change(new_info.calldata_len, old_info.calldata_len)
    );
    println!(
        "gas_cost: {}{}",
        new_info.gas_cost,
        format_change(new_info.gas_cost, old_info.gas_cost)
    );

    let str_val = serde_json::to_string(&new_info);
    let mut file = File::create(PathBuf::from_str("./data.json").unwrap()).unwrap();
    file.write_all(str_val.unwrap().as_bytes()).unwrap();
}
