/**
 * Interactive renderer for the vk.json expression AST.
 *
 * Two modes:
 *  - symbolic: leaves render as column references (a3, f2[+1], i1);
 *  - substituted: leaves also show the concrete value from a row binding or
 *    from the verifier's evaluation vectors.
 *
 * Hovering a leaf reports the referenced cell(s) so the table can highlight
 * them (including the rotated row).
 */

import { ReactNode } from "react";
import type { Expr, QueryRef } from "../../verifier/expr";
import { fromLEHex } from "../../verifier/field";
import { CellAddr, fmtValue, fmtValueFull, useStore } from "../../store";

export interface LeafValueSource {
  /** Value of a leaf; return null when unknown. */
  value: (kind: "fixed" | "advice" | "instance", q: QueryRef) => bigint | null;
}

interface Props {
  expr: Expr;
  values?: LeafValueSource;
  /** Row context (for hover-highlighting rotated cells); null = verifier view. */
  row?: number | null;
  n?: number;
  /** Fixed columns that are simple selectors (rendered as q_i). */
  simpleSelectors?: Set<number>;
  numFixedBase?: number;
}

const KIND_COLOR: Record<string, string> = {
  advice: "text-green-300 bg-green-950/60 border-green-800",
  fixed: "text-amber-300 bg-amber-950/60 border-amber-800",
  instance: "text-sky-300 bg-sky-950/60 border-sky-800",
  selector: "text-pink-300 bg-pink-950/60 border-pink-800",
  const: "text-slate-300 bg-slate-800 border-slate-600",
};

export default function ExprView(props: Props) {
  return <span className="font-mono text-sm leading-7">{render(props.expr, props, 0)}</span>;
}

function Leaf({
  kind,
  q,
  props,
}: {
  kind: "fixed" | "advice" | "instance";
  q: QueryRef;
  props: Props;
}) {
  const setHoverCells = useStore((s) => s.setHoverCells);
  const isSelector =
    kind === "fixed" &&
    props.numFixedBase !== undefined &&
    q.column >= props.numFixedBase;
  const cls = KIND_COLOR[isSelector ? "selector" : kind];
  const short = isSelector
    ? `q${q.column - props.numFixedBase!}`
    : `${kind[0]}${q.column}`;
  const rot = q.rotation === 0 ? "" : q.rotation > 0 ? `[+${q.rotation}]` : `[${q.rotation}]`;
  const value = props.values?.value(kind, q) ?? null;

  const onEnter = () => {
    if (props.row == null || props.n == null) return;
    const row = (((props.row + q.rotation) % props.n) + props.n) % props.n;
    const cells: CellAddr[] = [{ kind, column: q.column, row }];
    setHoverCells(cells);
  };
  const onLeave = () => setHoverCells([]);

  return (
    <span
      className={`mx-0.5 inline-block cursor-default rounded border px-1 ${cls}`}
      title={value !== null ? fmtValueFull(value) : `${kind} column ${q.column}, rotation ${q.rotation}`}
      onMouseEnter={onEnter}
      onMouseLeave={onLeave}
    >
      {short}
      <sub className="text-[10px] opacity-80">{rot}</sub>
      {value !== null && (
        <span className="ml-1 border-l border-current/40 pl-1 text-xs opacity-90">
          {fmtValue(value)}
        </span>
      )}
    </span>
  );
}

// Precedence: sum(0) < prod(1) < unary(2).
function render(e: Expr, props: Props, prec: number): ReactNode {
  if ("const" in e) {
    const v = fromLEHex(e.const);
    return (
      <span
        className={`mx-0.5 inline-block rounded border px-1 ${KIND_COLOR.const}`}
        title={fmtValueFull(v)}
      >
        {fmtValue(v)}
      </span>
    );
  }
  if ("fixed" in e) return <Leaf kind="fixed" q={e.fixed} props={props} />;
  if ("advice" in e) return <Leaf kind="advice" q={e.advice} props={props} />;
  if ("instance" in e) return <Leaf kind="instance" q={e.instance} props={props} />;
  if ("neg" in e) {
    return wrap(prec > 1, <>−{render(e.neg, props, 2)}</>);
  }
  if ("sum" in e) {
    // Render a + (-b) as a - b for readability.
    const [a, b] = e.sum;
    if (typeof b === "object" && "neg" in b) {
      return wrap(prec > 0, <>{render(a, props, 0)} − {render(b.neg, props, 1)}</>);
    }
    return wrap(prec > 0, <>{render(a, props, 0)} + {render(b, props, 0)}</>);
  }
  if ("prod" in e) {
    return wrap(prec > 1, <>{render(e.prod[0], props, 1)} · {render(e.prod[1], props, 1)}</>);
  }
  if ("scaled" in e) {
    const v = fromLEHex(e.scaled[0]);
    return wrap(
      prec > 1,
      <>
        <span className={`mx-0.5 inline-block rounded border px-1 ${KIND_COLOR.const}`} title={fmtValueFull(v)}>
          {fmtValue(v)}
        </span>
        {" · "}
        {render(e.scaled[1], props, 1)}
      </>,
    );
  }
  return <span className="text-red-400">?</span>;
}

function wrap(needed: boolean, inner: ReactNode): ReactNode {
  return needed ? (
    <span>
      <span className="text-slate-500">(</span>
      {inner}
      <span className="text-slate-500">)</span>
    </span>
  ) : (
    inner
  );
}
