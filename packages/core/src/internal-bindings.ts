import type { RuntimeBindingHandle } from "./types.js";

/** Framework-only module; deliberately absent from package exports. */
export interface RuntimeBindingIdentity {
  readonly id: string;
  readonly version: string;
  readonly irHash: string;
}
export interface RuntimeBindingResolution extends RuntimeBindingIdentity {
  readonly handler: unknown;
}

const descriptors = new WeakMap<object, unknown>();
const descriptorHas = descriptors.has.bind(descriptors);
const descriptorGet = descriptors.get.bind(descriptors);
const descriptorSet = descriptors.set.bind(descriptors);
const handles = new WeakMap<object, RuntimeBindingResolution>();
const handleGet = handles.get.bind(handles);
const handleSet = handles.set.bind(handles);

export function isBoundDescriptor(value: unknown): value is object {
  return typeof value === "object" && value !== null && descriptorHas(value);
}

export function registerDescriptorBinding(
  descriptor: object,
  handler: unknown,
): void {
  if (descriptorHas(descriptor))
    throw new Error("Descriptor binding already registered.");
  descriptorSet(descriptor, handler);
}

export function getBindingHandle(
  descriptor: unknown,
  identity: RuntimeBindingIdentity,
): RuntimeBindingHandle | undefined {
  if (!isBoundDescriptor(descriptor)) return undefined;
  const handle = Object.freeze(Object.create(null)) as RuntimeBindingHandle;
  handleSet(
    handle,
    Object.freeze({
      id: identity.id,
      version: identity.version,
      irHash: identity.irHash,
      handler: descriptorGet(descriptor),
    }),
  );
  return handle;
}

export function resolveBindingHandle(
  value: unknown,
): RuntimeBindingResolution | undefined {
  return typeof value === "object" && value !== null
    ? handleGet(value)
    : undefined;
}
