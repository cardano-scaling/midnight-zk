//! Dev-only variant of [`create_proof`](crate::plonk::create_proof) that
//! additionally captures the values (over the base evaluation domain) of the
//! prover's internal polynomials: the final (blinded) advice columns, the
//! permutation grand products, the LogUp multiplicities / helpers /
//! aggregators, the trash polynomials and the quotient limbs.
//!
//! These values cannot be derived from the proof bytes, which only carry
//! commitments and openings; they are exported for visualisation and
//! debugging tools.
//!
//! The proof written to the transcript is a regular proof: this function
//! mirrors [`create_proof`] step by step (`compute_trace` +
//! `finalise_proof`), with snapshots taken in between. Any change to
//! `finalise_proof` in `prover.rs` must be mirrored here.

use std::hash::Hash;

use ff::{FromUniformBytes, WithSmallOrderMulGroup};
use rand_core::{CryptoRng, RngCore};

use super::{
    circuit::Circuit,
    linearization::prover::compute_linearization_poly,
    partially_evaluate_identities,
    prover::{
        compute_h_poly, compute_nu_poly, compute_queries, compute_trace, write_evals_to_transcript,
        Evals,
    },
    Error, ProvingKey,
};
use crate::{
    plonk::{logup, trash},
    poly::{commitment::PolynomialCommitmentScheme, Coeff, EvaluationDomain, Polynomial},
    transcript::{Hashable, Sampleable, Transcript},
    utils::arithmetic::eval_polynomial,
};

/// The values of one LogUp argument's committed polynomials over the base
/// domain rows.
#[derive(Debug)]
pub struct LookupPolyDump<F> {
    /// Index of the lookup argument in `cs.lookups`.
    pub argument_index: usize,
    /// Multiplicities polynomial m(X), one value per row.
    pub multiplicities: Vec<F>,
    /// Helper polynomials h_j(X), one per chunk.
    pub helpers: Vec<Vec<F>>,
    /// Aggregator (running sum) polynomial Z(X).
    pub aggregator: Vec<F>,
}

/// The values of the prover's internal polynomials over the base domain rows,
/// together with the challenges squeezed during proof construction (useful as
/// cross-check anchors for external transcript re-implementations).
#[derive(Debug)]
pub struct ProverPolyDump<F> {
    /// Lookup compression challenge.
    pub theta: F,
    /// LogUp / permutation challenge.
    pub beta: F,
    /// Permutation challenge.
    pub gamma: F,
    /// Trash argument challenge.
    pub trash_challenge: F,
    /// Identity batching challenge.
    pub y: F,
    /// Final (blinded) advice column values, one `Vec` per advice column.
    pub advice_values: Vec<Vec<F>>,
    /// Permutation sigma polynomials from the proving key, one per
    /// permutation column.
    pub sigma_values: Vec<Vec<F>>,
    /// Permutation grand-product polynomials z_c(X), one per chunk.
    pub permutation_z: Vec<Vec<F>>,
    /// LogUp polynomial values, one entry per lookup argument.
    pub lookups: Vec<LookupPolyDump<F>>,
    /// Trash polynomial values, one per trash argument.
    pub trash_values: Vec<Vec<F>>,
    /// Quotient limb values over the base domain rows, in limb order. These
    /// are the actual (blinded) limbs whose commitments appear in the proof.
    pub quotient_limbs: Vec<Vec<F>>,
}

fn lagrange_values<F: WithSmallOrderMulGroup<3>>(
    domain: &EvaluationDomain<F>,
    poly: &Polynomial<F, Coeff>,
) -> Vec<F> {
    domain.coeff_to_lagrange(poly.clone()).values
}

/// Creates a proof exactly like [`create_proof`](crate::plonk::create_proof)
/// (writing it to `transcript`), returning the captured
/// [`ProverPolyDump`] on success.
#[allow(clippy::too_many_arguments)]
pub fn create_proof_with_dump<
    F,
    CS: PolynomialCommitmentScheme<F>,
    T: Transcript,
    ConcreteCircuit: Circuit<F>,
>(
    params: &CS::Parameters,
    pk: &ProvingKey<F, CS>,
    circuit: &ConcreteCircuit,
    #[cfg(feature = "committed-instances")] nb_committed_instances: usize,
    instances: &[&[F]],
    transcript: &mut T,
    mut rng: impl RngCore + CryptoRng,
) -> Result<ProverPolyDump<F>, Error>
where
    CS::Commitment: Hashable<T::Hash>,
    F: WithSmallOrderMulGroup<3>
        + Sampleable<T::Hash>
        + Hashable<T::Hash>
        + Hash
        + Ord
        + FromUniformBytes<64>,
{
    let domain = pk.get_vk().get_domain();

    let trace = compute_trace(
        params,
        pk,
        circuit,
        #[cfg(feature = "committed-instances")]
        nb_committed_instances,
        instances,
        transcript,
        &mut rng,
    )?;

    // Snapshot the phase-1 internals before `finalise_proof` consumes them.
    let advice_values: Vec<Vec<F>> =
        trace.advice_polys.iter().map(|p| lagrange_values(domain, p)).collect();
    let sigma_values: Vec<Vec<F>> =
        pk.permutation.permutations.iter().map(|p| p.values.clone()).collect();
    let permutation_z: Vec<Vec<F>> = trace
        .permutations
        .sets
        .iter()
        .map(|set| lagrange_values(domain, &set.permutation_product_poly))
        .collect();
    let lookup_dumps: Vec<LookupPolyDump<F>> = trace
        .lookups
        .iter()
        .map(|committed| LookupPolyDump {
            argument_index: committed.argument_index,
            multiplicities: lagrange_values(domain, &committed.multiplicities),
            helpers: committed.helper_polys.iter().map(|p| lagrange_values(domain, p)).collect(),
            aggregator: lagrange_values(domain, &committed.aggregator_poly),
        })
        .collect();
    let trash_values: Vec<Vec<F>> =
        trace.trashcans.iter().map(|c| lagrange_values(domain, &c.trash_poly)).collect();

    // The rest mirrors `finalise_proof` (prover.rs), with the quotient limbs
    // captured after `compute_h_poly`.
    #[cfg(not(feature = "committed-instances"))]
    let nb_committed_instances: usize = 0;

    let nu_poly = compute_nu_poly(pk, &trace);
    let quotient_limbs = compute_h_poly::<F, CS, T>(params, domain, nu_poly, transcript)?;

    let quotient_limb_values: Vec<Vec<F>> =
        quotient_limbs.iter().map(|p| lagrange_values(domain, p)).collect();

    let super::traces::ProverTrace {
        advice_polys,
        instance_polys,
        lookups,
        trashcans,
        permutations,
        beta,
        gamma,
        theta,
        trash_challenge,
        y,
        ..
    } = trace;

    let x: F = transcript.squeeze_challenge();

    let Evals {
        fixed_evals,
        instance_evals,
        advice_evals,
        ..
    } = write_evals_to_transcript(
        pk,
        nb_committed_instances,
        &instance_polys,
        &advice_polys,
        x,
        transcript,
    )?;

    let permutations_common = pk.permutation.evaluate(x, transcript)?;
    let permutations = permutations.evaluate(pk, x, transcript)?;
    let lookups: Vec<logup::prover::Evaluated<F>> = lookups
        .into_iter()
        .map(|p| p.evaluate(pk, x, transcript))
        .collect::<Result<Vec<_>, _>>()?;
    let trashcans: Vec<trash::prover::Evaluated<F>> = trashcans
        .into_iter()
        .map(|p| p.evaluate(x, transcript))
        .collect::<Result<Vec<_>, _>>()?;

    let splitting_factor = x.pow_vartime([pk.vk.n() - 1]);
    let xn = splitting_factor * x;
    let expressions = partially_evaluate_identities(
        &pk.vk,
        &fixed_evals,
        &instance_evals,
        &advice_evals,
        &permutations.evaluated,
        lookups.iter().map(|inner| &inner.evaluated),
        trashcans.iter().map(|inner| &inner.evaluated),
        &permutations_common,
        x,
        xn,
        beta,
        gamma,
        theta,
        trash_challenge,
    );

    let (lin_poly_non_constant_part, lin_poly_constant_term) =
        compute_linearization_poly(expressions, pk, y, xn, splitting_factor, quotient_limbs);

    debug_assert_eq!(
        eval_polynomial(&lin_poly_non_constant_part, x),
        -lin_poly_constant_term,
        "L'(x) should equal -C, where C is the constant part of the linearization polynomial"
    );

    let queries = compute_queries(
        pk,
        nb_committed_instances,
        &instance_polys,
        &advice_polys,
        &permutations,
        &lookups,
        &trashcans,
        x,
        &lin_poly_non_constant_part,
    );

    CS::multi_open(params, &queries, transcript).map_err(|_| Error::ConstraintSystemFailure)?;

    Ok(ProverPolyDump {
        theta,
        beta,
        gamma,
        trash_challenge,
        y,
        advice_values,
        sigma_values,
        permutation_z,
        lookups: lookup_dumps,
        trash_values,
        quotient_limbs: quotient_limb_values,
    })
}
