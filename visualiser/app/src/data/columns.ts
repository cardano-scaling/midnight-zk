/**
 * Reader for the MZKC binary column format written by the generator:
 * magic "MZKC", u8 version, u8 encoding (0 dense, 1 sparse-bitmap),
 * u16 reserved, u32 n, u32 count, [bitmap], count x 32-byte LE scalars.
 * And "MZKP" permutation-copy records.
 */

export interface Cell {
  value: bigint;
  assigned: boolean;
}

export class ColumnData {
  readonly n: number;
  private readonly bitmap: Uint8Array | null; // null = dense
  private readonly scalars: DataView;
  /** For sparse columns: prefix counts of assigned cells per 64-row block. */
  private readonly blockCounts: Uint32Array | null;

  constructor(buf: ArrayBuffer) {
    const view = new DataView(buf);
    const magic = String.fromCharCode(...new Uint8Array(buf, 0, 4));
    if (magic !== "MZKC") throw new Error(`bad column magic ${magic}`);
    if (view.getUint8(4) !== 1) throw new Error("unsupported MZKC version");
    const encoding = view.getUint8(5);
    this.n = view.getUint32(8, true);
    const count = view.getUint32(12, true);
    if (encoding === 0) {
      this.bitmap = null;
      this.blockCounts = null;
      this.scalars = new DataView(buf, 16, count * 32);
    } else {
      const bitmapLen = Math.ceil(this.n / 8);
      this.bitmap = new Uint8Array(buf, 16, bitmapLen);
      this.scalars = new DataView(buf, 16 + bitmapLen, count * 32);
      // popcount prefix per byte-block of 8 rows for O(1)-ish rank queries.
      this.blockCounts = new Uint32Array(bitmapLen + 1);
      let acc = 0;
      for (let i = 0; i < bitmapLen; i++) {
        this.blockCounts[i] = acc;
        acc += popcount8(this.bitmap[i]);
      }
      this.blockCounts[bitmapLen] = acc;
    }
  }

  isAssigned(row: number): boolean {
    if (!this.bitmap) return true;
    return (this.bitmap[row >> 3] & (1 << (row & 7))) !== 0;
  }

  /** Index of `row` among assigned rows (rank). Only valid if assigned. */
  private rank(row: number): number {
    const byte = row >> 3;
    let r = this.blockCounts![byte];
    const bits = this.bitmap![byte] & ((1 << (row & 7)) - 1);
    return r + popcount8(bits);
  }

  get(row: number): Cell {
    if (row < 0 || row >= this.n) throw new Error(`row ${row} out of range`);
    if (this.bitmap) {
      if (!this.isAssigned(row)) return { value: 0n, assigned: false };
      return { value: this.readScalar(this.rank(row)), assigned: true };
    }
    return { value: this.readScalar(row), assigned: true };
  }

  private readScalar(index: number): bigint {
    let v = 0n;
    // 32 bytes LE = 4 u64 reads.
    for (let w = 3; w >= 0; w--) {
      v = (v << 64n) | this.scalars.getBigUint64(index * 32 + w * 8, true);
    }
    return v;
  }
}

function popcount8(b: number): number {
  b = b - ((b >> 1) & 0x55);
  b = (b & 0x33) + ((b >> 2) & 0x33);
  return (b + (b >> 4)) & 0x0f;
}

export interface CopyRecord {
  col: number;
  row: number;
  mappedCol: number;
  mappedRow: number;
}

export function parseCopies(buf: ArrayBuffer): CopyRecord[] {
  const view = new DataView(buf);
  const magic = String.fromCharCode(...new Uint8Array(buf, 0, 4));
  if (magic !== "MZKP") throw new Error(`bad copies magic ${magic}`);
  const count = view.getUint32(8, true);
  const out: CopyRecord[] = [];
  for (let i = 0; i < count; i++) {
    const off = 12 + i * 16;
    out.push({
      col: view.getUint32(off, true),
      row: view.getUint32(off + 4, true),
      mappedCol: view.getUint32(off + 8, true),
      mappedRow: view.getUint32(off + 12, true),
    });
  }
  return out;
}
