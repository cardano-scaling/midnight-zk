/**
 * Schema (zod) and parsed representation of the vk.json bundle emitted by
 * `proofs/src/dev/json_dump.rs` / `zk_stdlib::export_verifier_bundle`.
 */

import { z } from "zod";
import type { Expr } from "./expr";

const hexScalar = z.string().regex(/^[0-9a-f]{64}$/);
const hexG1 = z.string().regex(/^[0-9a-f]{96}$/);
const hexG2 = z.string().regex(/^[0-9a-f]{192}$/);

const exprSchema: z.ZodType<Expr> = z.lazy(() =>
  z.union([
    z.object({ const: hexScalar }).strict(),
    z.object({ fixed: querySchema }).strict(),
    z.object({ advice: querySchema }).strict(),
    z.object({ instance: querySchema }).strict(),
    z.object({ neg: exprSchema }).strict(),
    z.object({ sum: z.tuple([exprSchema, exprSchema]) }).strict(),
    z.object({ prod: z.tuple([exprSchema, exprSchema]) }).strict(),
    z.object({ scaled: z.tuple([hexScalar, exprSchema]) }).strict(),
  ]),
) as z.ZodType<Expr>;

const querySchema = z.object({
  query: z.number().int().nonnegative(),
  column: z.number().int().nonnegative(),
  rotation: z.number().int(),
});

const columnQuery = z.tuple([z.number().int(), z.number().int()]); // [column, rotation]

const gateSchema = z.object({
  name: z.string(),
  constraints: z.array(exprSchema),
});

const lookupSchema = z.object({
  name: z.string(),
  selector: exprSchema,
  // [chunk][parallel_lookup][lookup_width]
  input_expression_chunks: z.array(z.array(z.array(exprSchema))),
  table_expressions: z.array(exprSchema),
  num_chunks: z.number().int().positive(),
});

const trashSchema = z.object({
  name: z.string(),
  selector: exprSchema,
  constraints: z.array(exprSchema),
});

const permColumnSchema = z.object({
  kind: z.enum(["advice", "fixed", "instance"]),
  index: z.number().int().nonnegative(),
});

export const vkBundleSchema = z.object({
  meta: z.object({
    name: z.string(),
    repo: z.string(),
    branch: z.string().optional(),
    rev: z.string(),
    protocol: z.literal("main"),
    transcript_hash: z.string(),
    curve: z.literal("BLS12-381"),
    features: z.string(),
  }),
  srs: z.object({ s_g2: hexG2, g2: hexG2 }),
  vk: z.object({
    k: z.number().int().positive(),
    n: z.number().int().positive(),
    transcript_repr: hexScalar,
    fixed_commitments: z.array(hexG1),
    permutation_commitments: z.array(hexG1),
    cs: z.object({
      num_fixed_columns: z.number().int().nonnegative(),
      num_advice_columns: z.number().int().nonnegative(),
      num_instance_columns: z.number().int().nonnegative(),
      blinding_factors: z.number().int().nonnegative(),
      degree: z.number().int().positive(),
      simple_selector_columns: z.array(z.number().int().nonnegative()),
      fixed_queries: z.array(columnQuery),
      advice_queries: z.array(columnQuery),
      instance_queries: z.array(columnQuery),
      gates: z.array(gateSchema),
      lookups: z.array(lookupSchema),
      trash: z.array(trashSchema),
      permutation_columns: z.array(permColumnSchema),
    }),
  }),
  nb_committed_instances: z.number().int().nonnegative(),
  committed_instances: z.array(hexG1),
  instances: z.array(z.array(hexScalar)).optional(),
  proof: z.string().regex(/^[0-9a-f]*$/).optional(),
  expected: z.boolean().optional(),
});

export type VkBundle = z.infer<typeof vkBundleSchema>;
export type ConstraintSystem = VkBundle["vk"]["cs"];
export type Gate = z.infer<typeof gateSchema>;
export type Lookup = z.infer<typeof lookupSchema>;
export type Trash = z.infer<typeof trashSchema>;
export type PermColumn = z.infer<typeof permColumnSchema>;

export function parseVkBundle(json: unknown): VkBundle {
  return vkBundleSchema.parse(json);
}
