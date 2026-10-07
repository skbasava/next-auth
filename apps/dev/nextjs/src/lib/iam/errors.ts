export type IamErrorStatus = 400 | 401 | 403 | 404 | 409 | 429 | 503
/** Codes must be public constants, never request data or underlying error messages. */
export class IamError extends Error {
  readonly name = "IamError"
  constructor(
    public readonly status: IamErrorStatus,
    public readonly code: string
  ) {
    super(code)
  }
}
