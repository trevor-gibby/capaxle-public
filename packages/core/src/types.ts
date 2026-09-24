/** Type inference only; schema detection, portability, and parsing belong to providers. */
export interface AuthorSchema<Input = unknown, Output = unknown> {
  readonly "~standard": {
    readonly version: 1;
    readonly vendor: string;
    readonly types?:
      { readonly input: Input; readonly output: Output } | undefined;
  };
}

declare const runtimeBindingBrand: unique symbol;

/** Opaque process-local binding; only the framework runtime can resolve it. */
export interface RuntimeBindingHandle {
  readonly [runtimeBindingBrand]: true;
}

declare const sharedSchemaBrand: unique symbol;

/** Opaque application-wide schema declaration issued by defineSharedSchema. */
export interface SharedSchema<
  Name extends string = string,
  Schema extends AuthorSchema = AuthorSchema,
> {
  readonly [sharedSchemaBrand]: true;
  readonly name: Name;
  readonly authorSchema: Schema;
}

export type CapabilitySchema =
  AuthorSchema | SharedSchema<string, AuthorSchema>;

export type UnwrapCapabilitySchema<Schema extends CapabilitySchema> =
  Schema extends SharedSchema<string, infer Author> ? Author : Schema;

export type SchemaInput<Schema extends CapabilitySchema> = NonNullable<
  UnwrapCapabilitySchema<Schema>["~standard"]["types"]
>["input"];
export type SchemaOutput<Schema extends CapabilitySchema> = NonNullable<
  UnwrapCapabilitySchema<Schema>["~standard"]["types"]
>["output"];

type NonEmptyList = readonly [string, ...string[]];
export type Permissions =
  | "public"
  | { readonly allOf: NonEmptyList; readonly anyOf?: NonEmptyList }
  | { readonly anyOf: NonEmptyList; readonly allOf?: NonEmptyList };

export type ExposureLevel = "disabled" | "private" | "authenticated" | "public";

export interface CapabilityExposure {
  readonly http?: ExposureLevel;
  readonly cli?: ExposureLevel;
  readonly mcp?: ExposureLevel;
  readonly internal?: ExposureLevel;
}

type Retry = { readonly mode: "never" | "safe" };
type MutatingIdempotency =
  | {
      readonly idempotency: "none";
      readonly retry?: { readonly mode: "never" };
    }
  | { readonly idempotency: "intrinsic" | "key"; readonly retry?: Retry };

export type CapabilityEffects =
  | {
      readonly impact: "read";
      readonly idempotency?: "intrinsic";
      readonly confirmation?: "none" | "required";
      readonly retry?: Retry;
    }
  | ({
      readonly impact: "write";
      readonly confirmation?: "none" | "required";
    } & MutatingIdempotency)
  | ({
      readonly impact: "destructive";
      readonly confirmation?: "required";
    } & MutatingIdempotency);

export type ErrorStatus =
  | "invalid_argument"
  | "unauthenticated"
  | "permission_denied"
  | "not_found"
  | "already_exists"
  | "failed_precondition"
  | "conflict"
  | "resource_exhausted"
  | "cancelled"
  | "deadline_exceeded"
  | "unavailable"
  | "internal";

export interface DeclaredError {
  readonly status: ErrorStatus;
  readonly message: string;
  readonly details?: CapabilitySchema;
  readonly retryable?: boolean;
}
export type ErrorDeclarations = Readonly<Record<string, DeclaredError>>;

/** The shared runtime will create this declared domain error. */
export interface CapabilityError extends Error {
  readonly code: string;
  readonly details?: unknown;
}

type ErrorArguments<Errors extends ErrorDeclarations> = {
  [Code in keyof Errors & string]: Errors[Code] extends {
    readonly details: infer Schema extends CapabilitySchema;
  }
    ? [code: Code, details: SchemaOutput<Schema>]
    : [code: Code];
}[keyof Errors & string];

/** Kernel-created normalized identity; no credentials or executable bindings. */
export interface PrincipalSnapshot {
  readonly providerId: string;
  readonly type: "user" | "service" | "agent" | "anonymous";
  readonly subject: string;
  readonly tenant?: string;
  readonly scopes: readonly string[];
  readonly roles: readonly string[];
  readonly authMethod?: string;
  readonly assurance?: string;
  readonly claims: Readonly<Record<string, import("@capaxle/ir").JsonValue>>;
}
export interface IdentityContext {
  readonly originating: PrincipalSnapshot;
  readonly effective: PrincipalSnapshot;
  readonly authorityChain: readonly PrincipalSnapshot[];
  readonly provenance: readonly {
    readonly mode: "delegate" | "derive" | "service";
    readonly caller: string;
    readonly target: string;
  }[];
}
interface InternalInvocationControls {
  readonly version?: string;
  readonly deadline?: Date;
  readonly signal?: AbortSignal;
  readonly idempotencyKey?: string;
  readonly confirmationToken?: string;
}
export type InternalInvocationOptions = InternalInvocationControls &
  (
    | { readonly mode?: "delegate"; readonly policyId?: never }
    | {
        readonly mode: "derive" | "service";
        readonly policyId: string;
      }
  );
// Declaration generators augment this intentionally empty interface.
// eslint-disable-next-line @typescript-eslint/no-empty-object-type
export interface GeneratedCapabilityFacade {}
export interface CapabilityInvocationSuccess<Output> {
  readonly ok: true;
  readonly value: Output;
  readonly correlationId: string;
}
export interface DeclaredCapabilityError {
  readonly code: string;
  readonly status: ErrorStatus;
  readonly message: string;
  readonly retryable: boolean;
  readonly correlationId: string;
  readonly details?: import("@capaxle/ir").JsonValue;
}
/** Dynamic ctx.invoke may target any capability, so its declared-error codes
 * are discovered only at runtime. Generated facade leaves replace this broad
 * surface with their target-specific declared-error union. */
export type DynamicDeclaredCapabilityError = DeclaredCapabilityError;
type FrameworkError<
  Code extends string,
  Status extends ErrorStatus,
  Retryable extends boolean = false,
> = {
  readonly code: Code;
  readonly status: Status;
  readonly message: string;
  readonly retryable: Retryable;
  readonly correlationId: string;
};
type FrameworkErrorWithDetails<
  Code extends string,
  Status extends ErrorStatus,
  Details,
  Retryable extends boolean = false,
> = FrameworkError<Code, Status, Retryable> & { readonly details: Details };
type FrameworkErrorWithOptionalDetails<
  Code extends string,
  Status extends ErrorStatus,
  Details,
  Retryable extends boolean = false,
> = FrameworkError<Code, Status, Retryable> & {
  readonly details?: Details;
};
export type FrameworkCapabilityError =
  | FrameworkError<"CAP_NOT_FOUND", "not_found">
  | FrameworkError<"CAP_VERSION_UNSUPPORTED", "failed_precondition">
  | FrameworkErrorWithOptionalDetails<
      "CAP_INPUT_INVALID",
      "invalid_argument",
      import("@capaxle/ir").JsonValue
    >
  | FrameworkError<"CAP_UNAUTHENTICATED", "unauthenticated">
  | FrameworkError<"CAP_PERMISSION_DENIED", "permission_denied">
  | FrameworkErrorWithDetails<
      "CAP_CONFIRMATION_REQUIRED",
      "failed_precondition",
      Readonly<{
        readonly challenge: string;
        readonly capability: Readonly<{
          readonly id: string;
          readonly version: string;
        }>;
        readonly summary: string;
        readonly impact: string;
        readonly expiresAt: string;
      }>
    >
  | FrameworkError<"CAP_CONFIRMATION_INVALID", "failed_precondition">
  | FrameworkError<"CAP_CONFIRMATION_POLICY_INVALID", "internal">
  | FrameworkError<"CAP_IDEMPOTENCY_KEY_REQUIRED", "invalid_argument">
  | FrameworkError<"CAP_IDEMPOTENCY_CONFLICT", "failed_precondition">
  | FrameworkError<"CAP_IDEMPOTENCY_IN_PROGRESS", "failed_precondition">
  | FrameworkError<"CAP_IDEMPOTENCY_RESULT_UNAVAILABLE", "failed_precondition">
  | FrameworkError<"CAP_IDEMPOTENCY_AMBIGUOUS", "failed_precondition">
  | FrameworkErrorWithDetails<
      "CAP_RATE_LIMITED",
      "resource_exhausted",
      Readonly<{
        readonly retryAfterMs: number;
        readonly limit?: number;
        readonly remaining?: number;
        readonly resetAt?: string;
      }>,
      true
    >
  | FrameworkErrorWithDetails<
      "CAP_DEADLINE_EXCEEDED",
      "deadline_exceeded",
      Readonly<{ readonly executionState: "not_started" | "started" }>
    >
  | FrameworkErrorWithDetails<
      "CAP_CANCELLED",
      "cancelled",
      Readonly<{ readonly executionState: "not_started" | "started" }>
    >
  | FrameworkError<"CAP_DEPENDENCY_UNAVAILABLE", "unavailable", true>
  | FrameworkError<"CAP_DEPENDENCY_UNAVAILABLE", "unavailable", false>
  | FrameworkError<"CAP_INTERNAL_INVOCATION_INVALID", "internal">
  | FrameworkError<"CAP_INTERNAL_INVOCATION_CYCLE", "failed_precondition">
  | FrameworkError<
      "CAP_INTERNAL_INVOCATION_DEPTH_EXCEEDED",
      "resource_exhausted"
    >
  | FrameworkError<"CAP_INVALID_HANDLER_OUTPUT", "internal">
  | FrameworkErrorWithOptionalDetails<
      "CAP_MCP_CLIENT_METADATA_REQUIRED",
      "failed_precondition",
      import("@capaxle/ir").JsonValue
    >
  | FrameworkError<"CAP_INTERNAL", "internal">;
export interface CapabilityInvocationFailure<
  Error extends DeclaredCapabilityError | FrameworkCapabilityError,
> {
  readonly ok: false;
  readonly error: Error;
}
export type CapabilityInvocationResult<
  Output = import("@capaxle/ir").JsonValue,
  DeclaredError extends DeclaredCapabilityError = never,
> =
  | CapabilityInvocationSuccess<Output>
  | CapabilityInvocationFailure<DeclaredError | FrameworkCapabilityError>;

export interface CapabilityRequirements {
  readonly secrets: readonly {
    readonly name: string;
    readonly optional?: boolean;
    readonly description?: string;
  }[];
}

export interface CapabilityLimits {
  readonly rateLimit?: {
    readonly policy: string;
    readonly cost?: number;
    readonly description?: string;
  };
}

/** Portable example data; schemas and handlers remain separate from examples. */
export interface CapabilityExample {
  readonly name: string;
  readonly description?: string;
  readonly input: import("@capaxle/ir").JsonValue;
  readonly output?: import("@capaxle/ir").JsonValue;
  readonly error?: {
    readonly code: string;
    readonly details?: import("@capaxle/ir").JsonValue;
  };
}

export interface CapabilityContext<
  Services = Readonly<Record<string, never>>,
  Errors extends ErrorDeclarations = Record<never, never>,
> {
  readonly services: Services;
  readonly secrets: { readonly get: (name: string) => string | undefined };
  readonly trace: {
    readonly traceId: string;
    readonly spanId: string;
    readonly parentSpanId?: string;
  };
  readonly logger: {
    readonly info: (code: string) => void;
    readonly warn: (code: string) => void;
    readonly error: (code: string) => void;
  };
  readonly identity: IdentityContext;
  readonly invoke: (
    capability: string,
    input: unknown,
    options?: InternalInvocationOptions,
  ) => Promise<
    CapabilityInvocationResult<
      import("@capaxle/ir").JsonValue,
      DynamicDeclaredCapabilityError
    >
  >;
  readonly capabilities: GeneratedCapabilityFacade;
  readonly signal: AbortSignal;
  readonly deadline: Date;
  readonly correlationId: string;
  readonly error: (...args: ErrorArguments<Errors>) => CapabilityError;
}

export type CapabilityDefinition<
  Input extends CapabilitySchema,
  Output extends CapabilitySchema,
  Errors extends ErrorDeclarations = Record<never, never>,
  Services = Readonly<Record<string, never>>,
> = {
  readonly id?: string;
  readonly version?: string;
  readonly description?: string;
  readonly tags?: readonly string[];
  readonly authentication?: "public" | "optional" | "required";
  readonly exposure?: CapabilityExposure;
  readonly requirements?: CapabilityRequirements;
  readonly limits?: CapabilityLimits;
  readonly examples?: readonly CapabilityExample[];
  readonly summary: string;
  readonly input: Input;
  readonly output: Output;
  readonly permissions: Permissions;
  readonly effects: CapabilityEffects;
  readonly errors?: Errors;
  readonly handler: (
    input: NoInfer<SchemaOutput<Input>>,
    ctx: CapabilityContext<Services, NoInfer<Errors>>,
  ) => NoInfer<SchemaOutput<Output>> | Promise<NoInfer<SchemaOutput<Output>>>;
} & (keyof Errors extends never ? unknown : { readonly errors: Errors });

declare const capabilityBrand: unique symbol;

/** Opaque authoring descriptor. It is not portable IR or an invocation API. */
export interface Capability<
  Input extends CapabilitySchema = CapabilitySchema,
  Output extends CapabilitySchema = CapabilitySchema,
  Errors extends ErrorDeclarations = ErrorDeclarations,
> {
  readonly [capabilityBrand]: true;
  readonly id?: string;
  readonly version?: string;
  readonly description?: string;
  readonly tags?: readonly string[];
  readonly authentication?: "public" | "optional" | "required";
  readonly exposure?: CapabilityExposure;
  readonly requirements?: {
    readonly secrets: readonly (CapabilityRequirements["secrets"][number] & {
      readonly optional: boolean;
    })[];
  };
  readonly limits?: {
    readonly rateLimit?: NonNullable<CapabilityLimits["rateLimit"]> & {
      readonly cost: number;
    };
  };
  readonly examples?: readonly CapabilityExample[];
  readonly summary: string;
  readonly input: Input;
  readonly output: Output;
  readonly permissions: Permissions;
  readonly effects: {
    readonly impact: "read" | "write" | "destructive";
    readonly idempotency: "none" | "intrinsic" | "key";
    readonly confirmation: "none" | "required";
    readonly retry: { readonly mode: "never" | "safe" };
  };
  readonly errors: {
    readonly [Code in keyof Errors]: Readonly<Errors[Code]> & {
      readonly retryable: boolean;
    };
  };
}
