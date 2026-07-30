//! Hand-rolled JSON export of everything an external verifier implementation
//! needs to verify proofs for a circuit: SRS verifier element, verifying key
//! (including the full constraint system with gate/lookup/trash expressions)
//! and, optionally, a known-good proof bundle (public inputs + proof bytes)
//! serving as a smoke test for the external verifier.
//!
//! This module deliberately avoids any new dependency (no serde_json): the
//! JSON is built by string concatenation with proper escaping. It is written
//! for the concrete BLS12-381 instantiation used by `midnight-zk-stdlib`.
//!
//! Encodings:
//! - scalars: canonical little-endian 32-byte hex via `to_repr()`;
//! - G1 points: 48-byte compressed hex;
//! - G2 points: 96-byte compressed hex.
//!
//! All hex is lowercase without `0x` prefix.

use std::path::Path;

use ff::PrimeField;
use group::{Group, GroupEncoding};
use midnight_curves::{Bls12, Fq, G1Projective, G2Projective};

use crate::{
    plonk::{Any, ConstraintSystem, Expression, Gate, VerifyingKey},
    poly::{kzg::KZGCommitmentScheme, Rotation},
};

const REPO: &str = "cardano-scaling/midnight-zk";
const BRANCH: &str = "wasm-parallel-msm-v2";
// The upstream revision whose verifier protocol this export describes (the
// commits on top of it do not alter the protocol).
const REV: &str = "f5e6e16d589b201c707457079af5063445cdab23";
const PROTOCOL: &str = "v2";
const CURVE: &str = "BLS12-381";

/// The protocol-shaping cargo features of this build, so an importing
/// verifier generator can refuse a bundle built for a different variant.
fn features() -> String {
    let mut fs = Vec::new();
    if cfg!(feature = "committed-instances") {
        fs.push("committed-instances");
    }
    if cfg!(feature = "truncated-challenges") {
        fs.push("truncated-challenges");
    }
    fs.join(",")
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex_scalar(f: &Fq) -> String {
    hex_bytes(f.to_repr().as_ref())
}

fn hex_g1(p: &G1Projective) -> String {
    hex_bytes(p.to_bytes().as_ref())
}

fn hex_g2(p: &G2Projective) -> String {
    hex_bytes(p.to_bytes().as_ref())
}

/// Escapes a string for inclusion in a JSON string literal.
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Recursively encodes an [`Expression`] as JSON.
///
/// Panics if a `Selector` leaf appears: virtual selectors must have been
/// compiled away in the verifying key's constraint system.
fn expr_json(e: &Expression<Fq>) -> String {
    e.evaluate(
        &|scalar| format!("{{\"const\":\"{}\"}}", hex_scalar(&scalar)),
        &|_selector| panic!("Selector leaf must not appear in a keygen'd constraint system"),
        &|q| {
            format!(
                "{{\"fixed\":{{\"query\":{},\"column\":{},\"rotation\":{}}}}}",
                q.index.expect("unresolved fixed query index"),
                q.column_index,
                q.rotation.0
            )
        },
        &|q| {
            format!(
                "{{\"advice\":{{\"query\":{},\"column\":{},\"rotation\":{}}}}}",
                q.index.expect("unresolved advice query index"),
                q.column_index,
                q.rotation.0
            )
        },
        &|q| {
            format!(
                "{{\"instance\":{{\"query\":{},\"column\":{},\"rotation\":{}}}}}",
                q.index.expect("unresolved instance query index"),
                q.column_index,
                q.rotation.0
            )
        },
        &|challenge| {
            format!(
                "{{\"challenge\":{{\"index\":{},\"phase\":{}}}}}",
                challenge.index(),
                challenge.phase()
            )
        },
        &|a| format!("{{\"neg\":{a}}}"),
        &|a, b| format!("{{\"sum\":[{a},{b}]}}"),
        &|a, b| format!("{{\"prod\":[{a},{b}]}}"),
        &|a, scalar| format!("{{\"scaled\":[\"{}\",{}]}}", hex_scalar(&scalar), a),
    )
}

fn exprs_json(exprs: &[Expression<Fq>]) -> String {
    let items: Vec<String> = exprs.iter().map(expr_json).collect();
    format!("[{}]", items.join(","))
}

fn queries_json<C: crate::plonk::ColumnType>(
    queries: &[(crate::plonk::Column<C>, Rotation)],
) -> String {
    let items: Vec<String> =
        queries.iter().map(|(col, rot)| format!("[{},{}]", col.index(), rot.0)).collect();
    format!("[{}]", items.join(","))
}

fn gate_json(gate: &Gate<Fq>) -> String {
    format!(
        "{{\"name\":\"{}\",\"constraints\":{}}}",
        esc(gate.name()),
        exprs_json(gate.polynomials())
    )
}

fn cs_json(cs: &ConstraintSystem<Fq>) -> String {
    let advice_phase: Vec<String> =
        cs.advice_column_phase().iter().map(|p| p.to_string()).collect();
    let challenge_phase: Vec<String> =
        cs.challenge_phase().iter().map(|p| p.to_string()).collect();

    let gates: Vec<String> = cs.gates.iter().map(gate_json).collect();

    let lookups: Vec<String> = cs
        .lookups
        .iter()
        .map(|l| {
            format!(
                "{{\"name\":\"{}\",\"input_expressions\":{},\"table_expressions\":{}}}",
                esc(&l.name),
                exprs_json(&l.input_expressions),
                exprs_json(&l.table_expressions)
            )
        })
        .collect();

    let trashcans: Vec<String> = cs
        .trashcans
        .iter()
        .map(|t| {
            format!(
                "{{\"name\":\"{}\",\"selector\":{},\"constraints\":{}}}",
                esc(t.name()),
                expr_json(t.selector()),
                exprs_json(t.constraint_expressions())
            )
        })
        .collect();

    let perm_columns: Vec<String> = cs
        .permutation
        .columns
        .iter()
        .map(|col| {
            let kind = match col.column_type() {
                Any::Advice(_) => "advice",
                Any::Fixed => "fixed",
                Any::Instance => "instance",
            };
            format!("{{\"kind\":\"{}\",\"index\":{}}}", kind, col.index())
        })
        .collect();

    format!(
        concat!(
            "{{",
            "\"num_fixed_columns\":{},",
            "\"num_advice_columns\":{},",
            "\"num_instance_columns\":{},",
            "\"num_challenges\":{},",
            "\"advice_column_phase\":[{}],",
            "\"challenge_phase\":[{}],",
            "\"blinding_factors\":{},",
            "\"degree\":{},",
            "\"fixed_queries\":{},",
            "\"advice_queries\":{},",
            "\"instance_queries\":{},",
            "\"gates\":[{}],",
            "\"lookups\":[{}],",
            "\"trash\":[{}],",
            "\"permutation_columns\":[{}]",
            "}}"
        ),
        cs.num_fixed_columns,
        cs.num_advice_columns,
        cs.num_instance_columns,
        cs.num_challenges,
        advice_phase.join(","),
        challenge_phase.join(","),
        cs.blinding_factors(),
        cs.degree(),
        queries_json(&cs.fixed_queries),
        queries_json(&cs.advice_queries),
        queries_json(&cs.instance_queries),
        gates.join(","),
        lookups.join(","),
        trashcans.join(","),
        perm_columns.join(","),
    )
}

/// Builds a JSON bundle with everything an external verifier needs for this
/// circuit: SRS verifier element, verifying key (with the full constraint
/// system) and the committed-instance commitments.
///
/// `transcript_hash` names the Fiat--Shamir hash the proofs are generated
/// with; an importing verifier generator must check it matches its own
/// transcript instantiation.
///
/// If `proof_bundle = Some((instances, proof))` is given, the bundle
/// additionally carries the public inputs (one list of scalars per
/// non-committed instance column, in column order), the raw proof byte
/// stream and `"expected": true` — the caller is responsible for only
/// passing proofs that verify. Without it, only the setup data is emitted.
pub fn verification_json(
    name: &str,
    transcript_hash: &str,
    s_g2: &G2Projective,
    vk: &VerifyingKey<Fq, KZGCommitmentScheme<Bls12>>,
    committed_instances: &[G1Projective],
    proof_bundle: Option<(&[&[Fq]], &[u8])>,
) -> String {
    let n = vk.n();
    let k = n.trailing_zeros();

    let fixed_commitments: Vec<String> =
        vk.fixed_commitments().iter().map(|c| format!("\"{}\"", hex_g1(c))).collect();
    let permutation_commitments: Vec<String> =
        vk.permutation().commitments().iter().map(|c| format!("\"{}\"", hex_g1(c))).collect();

    let committed: Vec<String> =
        committed_instances.iter().map(|c| format!("\"{}\"", hex_g1(c))).collect();

    let proof_fields = proof_bundle
        .map(|(instances, proof)| {
            let instance_columns: Vec<String> = instances
                .iter()
                .map(|col| {
                    let vals: Vec<String> =
                        col.iter().map(|v| format!("\"{}\"", hex_scalar(v))).collect();
                    format!("[{}]", vals.join(","))
                })
                .collect();
            format!(
                ",\"instances\":[{}],\"proof\":\"{}\",\"expected\":true",
                instance_columns.join(","),
                hex_bytes(proof),
            )
        })
        .unwrap_or_default();

    format!(
        concat!(
            "{{",
            "\"meta\":{{",
            "\"name\":\"{name}\",",
            "\"repo\":\"{repo}\",",
            "\"branch\":\"{branch}\",",
            "\"rev\":\"{rev}\",",
            "\"protocol\":\"{protocol}\",",
            "\"transcript_hash\":\"{th}\",",
            "\"curve\":\"{curve}\",",
            "\"features\":\"{features}\"",
            "}},",
            "\"srs\":{{\"s_g2\":\"{s_g2}\",\"g2\":\"{g2}\"}},",
            "\"vk\":{{",
            "\"k\":{k},",
            "\"n\":{n},",
            "\"transcript_repr\":\"{repr}\",",
            "\"fixed_commitments\":[{fixed}],",
            "\"permutation_commitments\":[{perm}],",
            "\"cs\":{cs}",
            "}},",
            "\"nb_committed_instances\":{nb_ci},",
            "\"committed_instances\":[{ci}]",
            "{proof_fields}",
            "}}"
        ),
        name = esc(name),
        repo = REPO,
        branch = BRANCH,
        rev = REV,
        protocol = PROTOCOL,
        th = esc(transcript_hash),
        curve = CURVE,
        features = features(),
        s_g2 = hex_g2(s_g2),
        g2 = hex_g2(&G2Projective::generator()),
        k = k,
        n = n,
        repr = hex_scalar(&vk.transcript_repr()),
        fixed = fixed_commitments.join(","),
        perm = permutation_commitments.join(","),
        cs = cs_json(vk.cs()),
        nb_ci = committed_instances.len(),
        ci = committed.join(","),
        proof_fields = proof_fields,
    )
}

/// Writes the JSON of [`verification_json`] to `out_path`, creating parent
/// directories as needed.
#[allow(clippy::too_many_arguments)]
pub fn dump_verification_json(
    name: &str,
    transcript_hash: &str,
    s_g2: &G2Projective,
    vk: &VerifyingKey<Fq, KZGCommitmentScheme<Bls12>>,
    committed_instances: &[G1Projective],
    proof_bundle: Option<(&[&[Fq]], &[u8])>,
    out_path: &Path,
) -> std::io::Result<()> {
    let json =
        verification_json(name, transcript_hash, s_g2, vk, committed_instances, proof_bundle);
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(out_path, json)
}
