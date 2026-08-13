import { useEffect, useState } from "react";
import { wrap, Remote } from "comlink";
import type { VerifierWorkerApi } from "../workers/verifier.worker";
import type { StepLog } from "../verifier/steplog";
import type { LoadedExample } from "../data/loader";

let workerApi: Remote<VerifierWorkerApi> | null = null;

function getWorker(): Remote<VerifierWorkerApi> {
  if (!workerApi) {
    const worker = new Worker(new URL("../workers/verifier.worker.ts", import.meta.url), {
      type: "module",
    });
    workerApi = wrap<VerifierWorkerApi>(worker);
  }
  return workerApi;
}

const cache = new Map<string, StepLog>();

/** Runs the TS verifier on the example's own proof bundle, off-thread. */
export function useVerify(ex: LoadedExample): StepLog | null {
  const [log, setLog] = useState<StepLog | null>(cache.get(ex.id) ?? null);

  useEffect(() => {
    if (cache.has(ex.id)) {
      setLog(cache.get(ex.id)!);
      return;
    }
    let cancelled = false;
    setLog(null);
    getWorker()
      .verify(ex.vk, ex.vk.instances!, ex.vk.proof!)
      .then((result) => {
        cache.set(ex.id, result);
        if (!cancelled) setLog(result);
      });
    return () => {
      cancelled = true;
    };
  }, [ex]);

  return log;
}
