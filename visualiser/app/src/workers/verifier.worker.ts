/// <reference lib="webworker" />
import { expose } from "comlink";
import { verify, VerifyOptions } from "../verifier/verify";
import type { VkBundle } from "../verifier/vk";
import type { StepLog } from "../verifier/steplog";

const api = {
  verify(bundle: VkBundle, instances: string[][], proofHex: string, options?: VerifyOptions): StepLog {
    return verify(bundle, instances, proofHex, options);
  },
};

export type VerifierWorkerApi = typeof api;
expose(api);
