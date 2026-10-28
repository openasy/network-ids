export type ProblemCode = "invalid-token" | "invalid-json" | "invalid-body" | "not-found" | "conflict" | "payload-too-large" | "internal-error";

/** A refusal the API answers with Problem Details (ADR 0024). */
export class IdsError extends Error {
  readonly status: number;
  readonly code: ProblemCode;
  constructor(status: number, code: ProblemCode, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export const bad = (detail: string) => new IdsError(422, "invalid-body", detail);
