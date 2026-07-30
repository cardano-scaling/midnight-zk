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
use group::Group;
use midnight_curves::{Bls12, Fq, G1Projective, G2Projective};

use crate::{
    plonk::{Any, ConstraintSystem, Expression, VerifyingKey},
    poly::{kzg::{commitment::KZGMultiCommitment, KZGCommitmentScheme}, Rotation},
    utils::{helpers::ProcessedSerdeObject, SerdeFormat},
};

const REPO: &str = "cardano-scaling/midnight-zk";
const BRANCH: &str = "wasm-parallel-msm-main";
// The upstream revision whose verifier protocol this export describes (the
// commits on top of it do not alter the protocol).
const REV: &str = "234dcf42805017e382b59d22e6f13b4bc5b6c181";
const PROTOCOL: &str = "main";
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
    if cfg!(feature = "fewer-point-sets") {
        fs.push("fewer-point-sets");
    }
    if cfg!(feature = "single-h-commitment") {
        fs.push("single-h-commitment");
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
    let mut buf = Vec::with_capacity(48);
    p.write(&mut buf, SerdeFormat::Processed).expect("G1 serialization");
    assert_eq!(buf.len(), 48, "expected 48-byte compressed G1");
    hex_bytes(&buf)
}

fn hex_g2(p: &G2Projective) -> String {
    let mut buf = Vec::with_capacity(96);
    p.write(&mut buf, SerdeFormat::Processed).expect("G2 serialization");
    assert_eq!(buf.len(), 96, "expected 96-byte compressed G2");
    hex_bytes(&buf)
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

fn query_json(kind: &str, index: Option<usize>, column: usize, rotation: Rotation) -> String {
    let idx = index.unwrap_or_else(|| panic!("unresolved {kind} query index in vk expression"));
    format!("{{\"{kind}\":{{\"query\":{idx},\"column\":{column},\"rotation\":{}}}}}", rotation.0)
}

/// Recursive EXPR encoding:
/// {"const":"<hex32>"} | {"fixed":{"query":i,"column":c,"rotation":r}} |
/// {"advice":{...}} | {"instance":{...}} | {"neg":EXPR} | {"sum":[E,E]} |
/// {"prod":[E,E]} | {"scaled":["<hex32>",E]}.
///
/// A raw `Selector` leaf must never appear in vk expressions (they are
/// converted into fixed columns during keygen); we panic if one is found.
fn expr_json(e: &Expression<Fq>) -> String {
    match e {
        Expression::Constant(c) => format!("{{\"const\":\"{}\"}}", hex_scalar(c)),
        Expression::Selector(s) => {
            panic!("raw Selector leaf found in vk expression: {s:?}")
        }
        Expression::Fixed(q) => query_json("fixed", q.index(), q.column_index(), q.rotation()),
        Expression::Advice(q) => query_json("advice", q.index, q.column_index(), q.rotation()),
        Expression::Instance(q) => query_json("instance", q.index, q.column_index(), q.rotation()),
        Expression::Negated(a) => format!("{{\"neg\":{}}}", expr_json(a)),
        Expression::Sum(a, b) => format!("{{\"sum\":[{},{}]}}", expr_json(a), expr_json(b)),
        Expression::Product(a, b) => format!("{{\"prod\":[{},{}]}}", expr_json(a), expr_json(b)),
        Expression::Scaled(a, f) => {
            format!("{{\"scaled\":[\"{}\",{}]}}", hex_scalar(f), expr_json(a))
        }
    }
}

fn exprs_json(es: &[Expression<Fq>]) -> String {
    let items: Vec<String> = es.iter().map(expr_json).collect();
    format!("[{}]", items.join(","))
}

fn queries_json<C: crate::plonk::ColumnType>(
    queries: &[(crate::plonk::Column<C>, Rotation)],
) -> String {
    let items: Vec<String> =
        queries.iter().map(|(c, r)| format!("[{},{}]", c.index(), r.0)).collect();
    format!("[{}]", items.join(","))
}

fn multi_commitments_points(mcs: &[KZGMultiCommitment<Bls12>]) -> Vec<String> {
    mcs.iter()
        .flat_map(|mc| mc.0.iter().map(|c| format!("\"{}\"", hex_g1(c.as_point()))))
        .collect()
}

fn cs_json(cs: &ConstraintSystem<Fq>) -> String {
    let degree = cs.degree();

    // Fixed-column indices of simple (multiplicative) selectors; their
    // evaluations are omitted from proofs (placeholder-1 rule on the verifier
    // side).
    let mut simple_selector_columns: Vec<usize> = cs
        .selector_flags
        .iter()
        .filter(|f| f.is_simple())
        .map(|f| f.col_idx().expect("simple selector without a fixed column index"))
        .collect();
    simple_selector_columns.sort_unstable();
    let simple_sel = format!(
        "[{}]",
        simple_selector_columns.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(",")
    );

    let gates: Vec<String> = cs
        .gates
        .iter()
        .map(|g| {
            format!(
                "{{\"name\":\"{}\",\"constraints\":{}}}",
                esc(g.name()),
                exprs_json(g.polynomials())
            )
        })
        .collect();

    let lookups: Vec<String> = cs
        .lookups
        .iter()
        .map(|arg| {
            let chunked = arg.chunk_by_degree(degree);
            let num_chunks = chunked.num_chunks();
            // [chunk][parallel_lookup][lookup_width] — the extra (innermost)
            // level relative to a flat expression list is required because
            // each parallel lookup can be multi-column (theta-compressed).
            let chunks: Vec<String> = chunked
                .input_expression_chunks
                .iter()
                .map(|chunk| {
                    let pls: Vec<String> = chunk.iter().map(|pl| exprs_json(pl)).collect();
                    format!("[{}]", pls.join(","))
                })
                .collect();
            format!(
                "{{\"name\":\"{}\",\"selector\":{},\"input_expression_chunks\":[{}],\"table_expressions\":{},\"num_chunks\":{}}}",
                esc(arg.name()),
                expr_json(&chunked.selector),
                chunks.join(","),
                exprs_json(&chunked.table_expressions),
                num_chunks
            )
        })
        .collect();

    let trash: Vec<String> = cs
        .trashcans
        .iter()
        .map(|arg| {
            format!(
                "{{\"name\":\"{}\",\"selector\":{},\"constraints\":{}}}",
                esc(arg.name()),
                expr_json(arg.selector()),
                exprs_json(arg.constraint_expressions())
            )
        })
        .collect();

    let perm_cols: Vec<String> = cs
        .permutation
        .columns
        .iter()
        .map(|col| {
            let kind = match col.column_type() {
                Any::Advice => "advice",
                Any::Fixed => "fixed",
                Any::Instance => "instance",
            };
            format!("{{\"kind\":\"{kind}\",\"index\":{}}}", col.index())
        })
        .collect();

    format!(
        concat!(
            "{{",
            "\"num_fixed_columns\":{},",
            "\"num_advice_columns\":{},",
            "\"num_instance_columns\":{},",
            "\"blinding_factors\":{},",
            "\"degree\":{},",
            "\"simple_selector_columns\":{},",
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
        cs.blinding_factors(),
        degree,
        simple_sel,
        queries_json(&cs.fixed_queries),
        queries_json(&cs.advice_queries),
        queries_json(&cs.instance_queries),
        gates.join(","),
        lookups.join(","),
        trash.join(","),
        perm_cols.join(",")
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
    committed_instances: &[KZGMultiCommitment<Bls12>],
    proof_bundle: Option<(&[&[Fq]], &[u8])>,
) -> String {
    let n = vk.n();
    let k = n.trailing_zeros();

    let fixed_commitments = multi_commitments_points(vk.fixed_commitments());
    let permutation_commitments = multi_commitments_points(vk.permutation().commitments());
    let committed = multi_commitments_points(committed_instances);
    let nb_committed = committed_instances.len();

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
        nb_ci = nb_committed,
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
    committed_instances: &[KZGMultiCommitment<Bls12>],
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
