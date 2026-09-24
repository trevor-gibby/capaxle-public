import { z } from "zod";

import {
  canonicalizeInput,
  jcs,
  validateCapabilityDocument,
} from "@capaxle/ir";

const DIALECT = "https://json-schema.org/draft/2020-12/schema";
const MAX_AUTHOR_SCHEMA_DEPTH = 64;
const MAX_AUTHOR_SCHEMA_NODES = 1_000;
const MAX_AUTHOR_SCHEMA_OCCURRENCES = 10_000;
const PORTABLE_DEFAULTS = new WeakMap();
const PORTABLE_LAZIES = new WeakMap();
const DEFAULT_EMAIL_PATTERN = z.email()._zod.def.pattern.source;
const PINNED_IPV6_SCHEMA = z.ipv6();
const PINNED_IPV6_CHECK = PINNED_IPV6_SCHEMA._zod.def;
const PINNED_IPV6_CONSTRUCTOR = PINNED_IPV6_SCHEMA.constructor;
const PINNED_IPV6_PROTOTYPE = Object.getPrototypeOf(PINNED_IPV6_SCHEMA);
const PINNED_IPV6_INTERNAL_CONSTRUCTOR = PINNED_IPV6_SCHEMA._zod.constr;
const PINNED_IPV6_PATTERN = PINNED_IPV6_CHECK.pattern.source;
const PINNED_IPV6_FLAGS = PINNED_IPV6_CHECK.pattern.flags;
const PINNED_IPV6_NATIVE_PATTERN = PINNED_IPV6_PATTERN;
const IPV6_PROVENANCE_KEY = "x-capaxle-private-pinned-ipv6";
const IPV6_PROVENANCE_VALUE = "capaxle-zod-4.5.2-ipv6";
const SUPPORTED_NUMBER_FORMATS = new Set([
  "float32",
  "float64",
  "int32",
  "safeint",
  "uint32",
]);
const SUPPORTED_SOURCE_FORMATS = new Set([
  "date",
  "datetime",
  "duration",
  "email",
  "hostname",
  "ipv4",
  "ipv6",
  "regex",
  "starts_with",
  "ends_with",
  "includes",
  "time",
  "url",
  "uuid",
]);
const SUPPORTED_CHECKS = new Set([
  "greater_than",
  "length_equals",
  "less_than",
  "max_length",
  "min_length",
  "number_format",
]);
const SUPPORTED_TYPES = new Set([
  "array",
  "boolean",
  "default",
  "enum",
  "lazy",
  "literal",
  "null",
  "nullable",
  "number",
  "object",
  "optional",
  "string",
  "union",
]);

function codePointCompare(left, right) {
  const a = Array.from(left, (value) => value.codePointAt(0));
  const b = Array.from(right, (value) => value.codePointAt(0));
  for (let index = 0; index < Math.min(a.length, b.length); index += 1) {
    if (a[index] !== b[index]) return a[index] - b[index];
  }
  return a.length - b.length;
}

function escapePointerToken(value) {
  return String(value).replaceAll("~", "~0").replaceAll("/", "~1");
}

function childPath(path, token) {
  return `${path}/${escapePointerToken(token)}`;
}

function basePath(fixtureId) {
  return fixtureId.startsWith("/")
    ? fixtureId
    : `/fixtures/${escapePointerToken(fixtureId)}/schema`;
}

function normalizeContext(context) {
  try {
    return {
      fixtureId:
        typeof context?.path === "string"
          ? context.path
          : typeof context?.fixtureId === "string"
            ? context.fixtureId
            : "/schema",
      direction: context?.direction === "output" ? "output" : "input",
    };
  } catch {
    return { fixtureId: "/schema", direction: "input" };
  }
}

function diagnostic(code, path, message) {
  return { code, severity: "error", path, message };
}

function hasValidUnicode(value) {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) return false;
  }
  return true;
}

function isPortableNumber(value) {
  return (
    Number.isFinite(value) &&
    (!Number.isInteger(value) || Number.isSafeInteger(value))
  );
}

function isPortableJson(value, ancestors = new Set()) {
  if (value === null || typeof value === "boolean") return true;
  if (typeof value === "string") return hasValidUnicode(value);
  if (typeof value === "number") return isPortableNumber(value);
  if (typeof value !== "object" || ancestors.has(value)) return false;
  let array;
  let descriptors;
  try {
    array = Array.isArray(value);
    const prototype = Object.getPrototypeOf(value);
    if (
      (array && prototype !== Array.prototype) ||
      (!array && prototype !== Object.prototype)
    )
      return false;
    if (Object.getOwnPropertySymbols(value).length) return false;
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch {
    return false;
  }
  ancestors.add(value);
  try {
    const entries = Object.entries(descriptors).filter(
      ([key]) => !array || key !== "length",
    );
    if (array && entries.length !== value.length) return false;
    return entries.every(([key, descriptor], index) => {
      if (
        !hasValidUnicode(key) ||
        !("value" in descriptor) ||
        !descriptor.enumerable ||
        (array && key !== String(index))
      )
        return false;
      return isPortableJson(descriptor.value, ancestors);
    });
  } finally {
    ancestors.delete(value);
  }
}

function isPortableZodLiteral(value) {
  return (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "string" ||
    (typeof value === "number" && isPortableNumber(value))
  );
}

function jsonType(value) {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  return typeof value === "object" ? "object" : typeof value;
}

function finiteValues(schema, seen = new Set()) {
  if (!schema?._zod || seen.has(schema)) return undefined;
  seen.add(schema);
  const def = schema._zod.def;
  if (def.type === "literal")
    return def.values.every((value) => isPortableZodLiteral(value))
      ? def.values
      : undefined;
  if (def.type === "enum") {
    const values = Object.values(def.entries);
    return values.every((value) => isPortableZodLiteral(value))
      ? values
      : undefined;
  }
  if (def.type === "null") return [null];
  if (def.type === "nullable") {
    const inner = finiteValues(def.innerType, seen);
    return inner ? [...inner, null] : undefined;
  }
  return undefined;
}

function possibleTypes(schema, seen = new Set()) {
  if (!schema?._zod || seen.has(schema)) return new Set();
  seen.add(schema);
  const def = schema._zod.def;
  if (["default", "optional", "nullable"].includes(def.type)) {
    const types = possibleTypes(def.innerType, seen);
    if (def.type === "nullable") types.add("null");
    return types;
  }
  if (def.type === "lazy") {
    const portable = PORTABLE_LAZIES.get(schema);
    return portable ? possibleTypes(portable.resolve(), seen) : new Set();
  }
  if (def.type === "union")
    return new Set(
      def.options.flatMap((option) => [
        ...possibleTypes(option, new Set(seen)),
      ]),
    );
  if (def.type === "literal")
    return new Set(
      def.values.every((value) => isPortableZodLiteral(value))
        ? def.values.map(jsonType)
        : [],
    );
  if (def.type === "enum") {
    const values = Object.values(def.entries);
    return new Set(
      values.every((value) => isPortableZodLiteral(value))
        ? values.map(jsonType)
        : [],
    );
  }
  return new Set(
    {
      array: ["array"],
      boolean: ["boolean"],
      null: ["null"],
      number: ["number"],
      object: ["object"],
      string: ["string"],
    }[def.type] ?? [],
  );
}

function isOptionalProperty(schema) {
  return ["optional", "default"].includes(schema?._zod?.def?.type);
}

function objectsHaveExclusiveDiscriminator(left, right) {
  const leftDef = left?._zod?.def;
  const rightDef = right?._zod?.def;
  if (leftDef?.type !== "object" || rightDef?.type !== "object") return false;
  const common = Object.keys(leftDef.shape)
    .filter((key) => Object.hasOwn(rightDef.shape, key))
    .sort(codePointCompare);
  return common.some((key) => {
    const leftProperty = leftDef.shape[key];
    const rightProperty = rightDef.shape[key];
    if (isOptionalProperty(leftProperty) || isOptionalProperty(rightProperty))
      return false;
    const leftValues = finiteValues(leftProperty);
    const rightValues = finiteValues(rightProperty);
    return (
      leftValues &&
      rightValues &&
      leftValues.every((a) => rightValues.every((b) => jcs(a) !== jcs(b)))
    );
  });
}

function branchesAreExclusive(left, right) {
  const leftValues = finiteValues(left);
  const rightValues = finiteValues(right);
  if (leftValues && rightValues) {
    return leftValues.every((a) => rightValues.every((b) => jcs(a) !== jcs(b)));
  }
  const leftTypes = possibleTypes(left);
  const rightTypes = possibleTypes(right);
  if ([...leftTypes].every((type) => !rightTypes.has(type))) return true;
  return objectsHaveExclusiveDiscriminator(left, right);
}

function unionIsExclusive(options) {
  for (let left = 0; left < options.length; left += 1) {
    for (let right = left + 1; right < options.length; right += 1) {
      if (!branchesAreExclusive(options[left], options[right])) return false;
    }
  }
  return true;
}

function graphChildren(schema) {
  const def = schema?._zod?.def;
  if (!def) return [];
  switch (def.type) {
    case "object":
      return Object.keys(def.shape)
        .sort(codePointCompare)
        .map((key) => ({
          schema: def.shape[key],
          segment: ["properties", key],
          property: true,
        }));
    case "array":
      return [{ schema: def.element, segment: ["items"], property: false }];
    case "optional":
    case "nullable":
    case "default":
      return [{ schema: def.innerType, segment: [], property: false }];
    case "union":
      return def.options.map((option, index) => ({
        schema: option,
        segment: ["oneOf", index],
        property: false,
      }));
    case "lazy": {
      const portable = PORTABLE_LAZIES.get(schema);
      if (!portable) return [];
      try {
        return [
          {
            schema: portable.resolve(),
            segment: [],
            property: false,
            lazy: true,
          },
        ];
      } catch {
        return [];
      }
    }
    default:
      return [];
  }
}

function collectGraph(root) {
  const entries = [];
  const paths = new WeakMap();
  const distinctNodes = new WeakSet();
  let distinctNodeCount = 0;
  let occurrenceCount = 0;
  const recursiveTargets = [];
  const stack = [
    { schema: root, path: "", property: false, depth: 0, ancestors: [] },
  ];
  while (stack.length) {
    const current = stack.pop();
    const { schema, path, property, depth, ancestors } = current;
    if (!schema?._zod) continue;
    if (occurrenceCount >= MAX_AUTHOR_SCHEMA_OCCURRENCES) {
      return {
        entries,
        paths,
        recursiveTargets,
        budgetFailure: {
          path,
          reason: `Author schema exceeds the maximum expansion budget of ${MAX_AUTHOR_SCHEMA_OCCURRENCES} schema occurrences.`,
        },
      };
    }
    occurrenceCount += 1;
    if (depth > MAX_AUTHOR_SCHEMA_DEPTH) {
      return {
        entries,
        paths,
        recursiveTargets,
        budgetFailure: {
          path,
          reason: `Author schema exceeds maximum depth ${MAX_AUTHOR_SCHEMA_DEPTH}.`,
        },
      };
    }
    if (ancestors.includes(schema)) {
      if (!recursiveTargets.includes(schema)) recursiveTargets.push(schema);
      continue;
    }
    if (
      !distinctNodes.has(schema) &&
      distinctNodeCount >= MAX_AUTHOR_SCHEMA_NODES
    ) {
      return {
        entries,
        paths,
        recursiveTargets,
        budgetFailure: {
          path,
          reason: `Author schema exceeds maximum node count ${MAX_AUTHOR_SCHEMA_NODES}.`,
        },
      };
    }
    if (!distinctNodes.has(schema)) {
      distinctNodes.add(schema);
      distinctNodeCount += 1;
      paths.set(schema, path);
    }
    entries.push({ schema, path, property });
    const children = graphChildren(schema);
    for (let index = children.length - 1; index >= 0; index -= 1) {
      const edge = children[index];
      let nextPath = path;
      for (const segment of edge.segment)
        nextPath = childPath(nextPath, segment);
      stack.push({
        schema: edge.schema,
        path: nextPath,
        property: edge.property,
        depth: depth + 1,
        ancestors: [...ancestors, schema],
      });
    }
  }
  return { entries, paths, recursiveTargets };
}

function constraintKeyword(checkDef, schemaType) {
  if (checkDef.check === "greater_than")
    return checkDef.inclusive ? "minimum" : "exclusiveMinimum";
  if (checkDef.check === "less_than")
    return checkDef.inclusive ? "maximum" : "exclusiveMaximum";
  if (["min_length", "length_equals"].includes(checkDef.check))
    return schemaType === "array" ? "minItems" : "minLength";
  if (checkDef.check === "max_length")
    return schemaType === "array" ? "maxItems" : "maxLength";
  return undefined;
}

function constraintOperand(checkDef) {
  if (["greater_than", "less_than"].includes(checkDef.check))
    return checkDef.value;
  if (checkDef.check === "min_length") return checkDef.minimum;
  if (checkDef.check === "max_length") return checkDef.maximum;
  if (checkDef.check === "length_equals") return checkDef.length;
  return undefined;
}

function constraintIsRepresentable(checkDef, schemaType) {
  const value = constraintOperand(checkDef);
  if (value === undefined) return true;
  if (!Number.isFinite(value)) return false;
  if (["min_length", "max_length", "length_equals"].includes(checkDef.check)) {
    return (
      ["array", "string"].includes(schemaType) &&
      Number.isSafeInteger(value) &&
      value >= 0
    );
  }
  return true;
}

function isPinnedIpv6Check(check) {
  const checkDef = check?._zod?.def;
  return (
    check?.constructor === PINNED_IPV6_CONSTRUCTOR &&
    Object.getPrototypeOf(check) === PINNED_IPV6_PROTOTYPE &&
    check?._zod?.constr === PINNED_IPV6_INTERNAL_CONSTRUCTOR &&
    checkDef?.check === "string_format" &&
    checkDef.type === "string" &&
    checkDef.format === "ipv6" &&
    checkDef.abort === false &&
    checkDef.pattern instanceof RegExp &&
    checkDef.pattern.source === PINNED_IPV6_PATTERN &&
    checkDef.pattern.flags === PINNED_IPV6_FLAGS
  );
}

function hasPinnedIpv6Check(schema) {
  const def = schema?._zod?.def;
  return (
    isPinnedIpv6Check(schema) ||
    (def?.checks ?? []).some((check) => isPinnedIpv6Check(check))
  );
}

function hasAuthoredPatternAlongsideIpv6(schema) {
  const def = schema?._zod?.def;
  return (
    hasPinnedIpv6Check(schema) &&
    (def?.checks ?? []).some((check) => {
      const checkDef = check?._zod?.def;
      return checkDef?.pattern instanceof RegExp && checkDef.format !== "ipv6";
    })
  );
}

function stringFormatIssue(checkDef, check) {
  const flags =
    checkDef.pattern instanceof RegExp ? checkDef.pattern.flags : "";
  if (checkDef.format === "regex" && flags !== "u")
    return "authored regex patterns require exactly the u flag";
  if (
    !SUPPORTED_SOURCE_FORMATS.has(checkDef.format) ||
    !["", "u"].includes(flags)
  )
    return "unsupported format or regex flags";
  if (checkDef.format === "url")
    return "ordinary Zod URL parsing is value-changing";
  if (["duration", "hostname"].includes(checkDef.format))
    return "source and portable format semantics differ";
  if (checkDef.format === "ipv6" && !isPinnedIpv6Check(check))
    return "IPv6 check does not match the pinned built-in provenance";
  if (
    checkDef.format === "email" &&
    checkDef.pattern?.source !== DEFAULT_EMAIL_PATTERN
  )
    return "custom email patterns do not preserve asserted email agreement";
  if (checkDef.format === "datetime") {
    if (checkDef.local === true)
      return "local date-times are outside asserted RFC 3339 semantics";
    if (
      checkDef.precision !== null &&
      !(Number.isSafeInteger(checkDef.precision) && checkDef.precision >= 0)
    )
      return "date-time precision is not representable";
  }
  if (
    checkDef.format === "time" &&
    checkDef.precision !== null &&
    !(Number.isSafeInteger(checkDef.precision) && checkDef.precision >= -1)
  )
    return "time precision is not representable";
  if (
    checkDef.format === "uuid" &&
    (checkDef.version === undefined || !/^v[1-8]$/u.test(checkDef.version))
  )
    return "UUID must declare a supported version";
  if (checkDef.format === "includes") {
    if (
      typeof checkDef.includes !== "string" ||
      !hasValidUnicode(checkDef.includes)
    )
      return "included value is not portable Unicode";
    if (
      checkDef.position !== undefined &&
      !(Number.isSafeInteger(checkDef.position) && checkDef.position >= 0)
    )
      return "include position is not representable";
  }
  if (
    checkDef.format === "starts_with" &&
    (typeof checkDef.prefix !== "string" || !hasValidUnicode(checkDef.prefix))
  )
    return "prefix is not portable Unicode";
  if (
    checkDef.format === "ends_with" &&
    (typeof checkDef.suffix !== "string" || !hasValidUnicode(checkDef.suffix))
  )
    return "suffix is not portable Unicode";
  return undefined;
}

function inspectMetadata(schema) {
  const layers = [];
  const seen = new WeakSet();
  try {
    let current = schema;
    while (current?._zod) {
      if (seen.has(current)) return { annotations: {}, issues: [{ key: "" }] };
      seen.add(current);
      layers.unshift(z.globalRegistry._map.get(current));
      current = current._zod.parent;
    }
  } catch {
    return { annotations: {}, issues: [{ key: "" }] };
  }
  const annotations = {};
  const issues = [];
  for (const [layerIndex, metadata] of layers.entries()) {
    if (metadata === undefined) continue;
    let descriptors;
    try {
      if (
        metadata === null ||
        typeof metadata !== "object" ||
        Array.isArray(metadata) ||
        ![Object.prototype, null].includes(Object.getPrototypeOf(metadata)) ||
        Object.getOwnPropertySymbols(metadata).length
      ) {
        issues.push({ key: "" });
        continue;
      }
      descriptors = Object.getOwnPropertyDescriptors(metadata);
    } catch {
      issues.push({ key: "" });
      continue;
    }
    for (const key of Object.keys(descriptors).sort(codePointCompare)) {
      if (key === "id" && layerIndex !== layers.length - 1) continue;
      const descriptor = descriptors[key];
      if (!("value" in descriptor) || !descriptor.enumerable) {
        issues.push({ key });
        continue;
      }
      const value = descriptor.value;
      const annotationValid =
        key === "description"
          ? typeof value === "string" && hasValidUnicode(value)
          : key === "examples"
            ? Array.isArray(value) && isPortableJson(value)
            : false;
      if (!annotationValid) {
        issues.push({ key });
        continue;
      }
      annotations[key] = key === "examples" ? copyLiteral(value) : value;
    }
  }
  return { annotations, issues };
}

function checkDefinition(entry, context, diagnostics) {
  const { schema, path, property } = entry;
  const def = schema._zod.def;
  const at = `${basePath(context.fixtureId)}${path}`;
  const metadata = inspectMetadata(schema);
  for (const { key } of metadata.issues) {
    diagnostics.push(
      diagnostic(
        "CAP_ZOD_METADATA_OVERRIDE",
        key ? childPath(at, key) : at,
        "Zod metadata cannot override portable schema structure.",
      ),
    );
  }
  if (!SUPPORTED_TYPES.has(def.type)) {
    const code =
      def.type === "pipe" && def.in?._zod?.def?.type === "transform"
        ? "CAP_ZOD_PREPROCESS_UNREPRESENTABLE"
        : def.type === "transform" || def.type === "pipe"
          ? "CAP_ZOD_TRANSFORM_UNREPRESENTABLE"
          : "CAP_ZOD_CONSTRUCT_UNSUPPORTED";
    diagnostics.push(
      diagnostic(
        code,
        at,
        `Zod construct ${def.type} is outside the portable subset.`,
      ),
    );
    return;
  }
  if (def.coerce) {
    diagnostics.push(
      diagnostic(
        "CAP_ZOD_PREPROCESS_UNREPRESENTABLE",
        at,
        "Coercion changes the accepted wire value before portable validation.",
      ),
    );
  }
  if (def.type === "object" && def.catchall?._zod?.def?.type !== "never") {
    diagnostics.push(
      diagnostic(
        "CAP_ZOD_OBJECT_MODE_UNSUPPORTED",
        childPath(at, "additionalProperties"),
        "Only explicitly strict fixed-shape objects are portable.",
      ),
    );
  }
  if (def.type === "object" && Object.hasOwn(def.shape, "__proto__")) {
    diagnostics.push(
      diagnostic(
        "CAP_ZOD_CONSTRUCT_UNSUPPORTED",
        childPath(childPath(at, "properties"), "__proto__"),
        "Zod does not preserve an own __proto__ object property canonically.",
      ),
    );
  }
  if (
    def.type === "literal" &&
    !def.values.every((value) => isPortableZodLiteral(value))
  ) {
    diagnostics.push(
      diagnostic(
        "CAP_ZOD_CONSTRUCT_UNSUPPORTED",
        childPath(at, def.values.length === 1 ? "const" : "enum"),
        "Zod literal is not a portable primitive value.",
      ),
    );
  }
  if (
    def.type === "enum" &&
    !Object.values(def.entries).every((value) => isPortableZodLiteral(value))
  ) {
    diagnostics.push(
      diagnostic(
        "CAP_ZOD_CONSTRUCT_UNSUPPORTED",
        childPath(at, "enum"),
        "Zod enum contains a value outside the portable primitive subset.",
      ),
    );
  }
  if (def.type === "default") {
    const authored = PORTABLE_DEFAULTS.get(schema);
    const valid =
      context.direction === "input" &&
      property &&
      PORTABLE_DEFAULTS.has(schema) &&
      isPortableJson(authored);
    if (!valid) {
      diagnostics.push(
        diagnostic(
          "CAP_ZOD_DEFAULT_UNREPRESENTABLE",
          childPath(at, "default"),
          "Only provider-recorded literal JSON input-property defaults are portable.",
        ),
      );
    }
  }
  if (def.type === "union" && !unionIsExclusive(def.options)) {
    diagnostics.push(
      diagnostic(
        "CAP_ZOD_UNION_NOT_EXCLUSIVE",
        childPath(at, "oneOf"),
        "Union branches are not provably pairwise exclusive.",
      ),
    );
  }
  if (def.type === "lazy") {
    const portable = PORTABLE_LAZIES.get(schema);
    if (!portable)
      diagnostics.push(
        diagnostic(
          "CAP_ZOD_REF_UNREPRESENTABLE",
          childPath(at, "$ref"),
          "Only provider-recorded memoized lazy references are portable.",
        ),
      );
    else
      try {
        if (!portable.resolve()?._zod)
          diagnostics.push(
            diagnostic(
              "CAP_ZOD_REF_UNREPRESENTABLE",
              childPath(at, "$ref"),
              "Lazy reference does not resolve to a local Zod schema.",
            ),
          );
      } catch {
        diagnostics.push(
          diagnostic(
            "CAP_ZOD_REF_UNREPRESENTABLE",
            childPath(at, "$ref"),
            "Lazy reference cannot be resolved locally.",
          ),
        );
      }
  }
  if (hasAuthoredPatternAlongsideIpv6(schema)) {
    diagnostics.push(
      diagnostic(
        "CAP_ZOD_FORMAT_UNSUPPORTED",
        childPath(at, "pattern"),
        "Authored pattern checks cannot be distinguished from the pinned IPv6 emitter pattern.",
      ),
    );
  }
  const checks = def.check
    ? [schema, ...(def.checks ?? [])]
    : (def.checks ?? []);
  for (const check of checks) {
    const checkDef = check._zod?.def ?? {};
    if (checkDef.check === "custom") {
      diagnostics.push(
        diagnostic(
          "CAP_ZOD_REFINEMENT_UNREPRESENTABLE",
          at,
          "Arbitrary refinements have no portable JSON Schema equivalent.",
        ),
      );
    } else if (checkDef.check === "overwrite") {
      diagnostics.push(
        diagnostic(
          "CAP_ZOD_TRANSFORM_UNREPRESENTABLE",
          at,
          "Value-changing overwrite checks are not portable.",
        ),
      );
    } else if (checkDef.check === "string_format") {
      const issue = stringFormatIssue(checkDef, check);
      if (issue) {
        const code =
          checkDef.format === "url"
            ? "CAP_ZOD_TRANSFORM_UNREPRESENTABLE"
            : "CAP_ZOD_FORMAT_UNSUPPORTED";
        diagnostics.push(
          diagnostic(
            code,
            code === "CAP_ZOD_FORMAT_UNSUPPORTED"
              ? childPath(
                  at,
                  ["ipv6", "regex"].includes(checkDef.format)
                    ? "pattern"
                    : "format",
                )
              : at,
            `Zod format ${checkDef.format} is not portable: ${issue}.`,
          ),
        );
      }
    } else if (
      checkDef.check === "number_format" &&
      !SUPPORTED_NUMBER_FORMATS.has(checkDef.format)
    ) {
      diagnostics.push(
        diagnostic(
          "CAP_ZOD_REFINEMENT_UNREPRESENTABLE",
          childPath(at, "format"),
          `Zod number format ${checkDef.format} is outside the portable subset.`,
        ),
      );
    } else if (checkDef.check === "multiple_of") {
      diagnostics.push(
        diagnostic(
          "CAP_ZOD_REFINEMENT_UNREPRESENTABLE",
          childPath(at, "multipleOf"),
          "Zod multipleOf tolerance behavior is outside the portable subset.",
        ),
      );
    } else if (checkDef.check && !SUPPORTED_CHECKS.has(checkDef.check)) {
      diagnostics.push(
        diagnostic(
          "CAP_ZOD_REFINEMENT_UNREPRESENTABLE",
          at,
          `Zod check ${checkDef.check} is not represented by the Capability schema profile.`,
        ),
      );
    } else if (
      checkDef.check &&
      !constraintIsRepresentable(checkDef, def.type)
    ) {
      const keyword = constraintKeyword(checkDef, def.type) ?? "constraint";
      diagnostics.push(
        diagnostic(
          "CAP_ZOD_REFINEMENT_UNREPRESENTABLE",
          childPath(at, keyword),
          `Zod check ${checkDef.check} has a non-representable operand.`,
        ),
      );
    }
  }
}

function checkDefaultAgreement(entry, context, diagnostics) {
  const { schema, path, property } = entry;
  if (schema?._zod?.def?.type !== "default") return;
  const authored = PORTABLE_DEFAULTS.get(schema);
  if (
    context.direction !== "input" ||
    !property ||
    !PORTABLE_DEFAULTS.has(schema) ||
    !isPortableJson(authored)
  )
    return;
  let parsed;
  try {
    parsed = schema._zod.def.innerType.safeParse(copyLiteral(authored));
  } catch {
    parsed = { success: false };
  }
  const agrees =
    parsed.success &&
    isPortableJson(parsed.data) &&
    jcs(parsed.data) === jcs(authored);
  if (!agrees) {
    const at = `${basePath(context.fixtureId)}${path}`;
    diagnostics.push(
      diagnostic(
        "CAP_ZOD_DEFAULT_UNREPRESENTABLE",
        childPath(at, "default"),
        "The authored default must already equal its canonical parsed value.",
      ),
    );
  }
}

function dedupeAndSort(diagnostics) {
  const sorted = diagnostics.sort(
    (left, right) =>
      codePointCompare(left.path, right.path) ||
      codePointCompare(left.code, right.code),
  );
  const seen = new Set();
  return sorted.filter(({ code, path }) => {
    const key = `${path}\0${code}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export class SchemaAuthoringError extends Error {
  severity = "error";

  constructor(code, path, message) {
    super(message);
    this.name = "SchemaAuthoringError";
    this.code = code;
    this.path = path;
  }
}

function copyLiteral(value, ancestors = new Set()) {
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "string" && hasValidUnicode(value)) return value;
  if (typeof value === "number" && isPortableNumber(value)) return value;
  if (typeof value !== "object" || ancestors.has(value)) throw new Error();
  const array = Array.isArray(value);
  const prototype = Object.getPrototypeOf(value);
  if (
    (array && prototype !== Array.prototype) ||
    (!array && prototype !== Object.prototype)
  )
    throw new Error();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Object.getOwnPropertySymbols(value).length) throw new Error();
  ancestors.add(value);
  try {
    const entries = Object.entries(descriptors).filter(
      ([key]) => !array || key !== "length",
    );
    if (array && entries.length !== value.length) throw new Error();
    const copy = array ? [] : {};
    for (const [index, [key, descriptor]] of entries.entries()) {
      if (
        !hasValidUnicode(key) ||
        !("value" in descriptor) ||
        !descriptor.enumerable ||
        (array && key !== String(index))
      )
        throw new Error();
      Object.defineProperty(copy, key, {
        value: copyLiteral(descriptor.value, ancestors),
        enumerable: true,
        writable: true,
        configurable: true,
      });
    }
    return copy;
  } finally {
    ancestors.delete(value);
  }
}

export function portableDefault(schema, value) {
  let recorded;
  try {
    recorded = copyLiteral(value);
  } catch {
    throw new SchemaAuthoringError(
      "CAP_ZOD_DEFAULT_UNREPRESENTABLE",
      "/default",
      "Supply a finite literal JSON value without accessors, cycles, or callable defaults.",
    );
  }
  const defaulted = schema.default(() => copyLiteral(recorded));
  PORTABLE_DEFAULTS.set(defaulted, recorded);
  return defaulted;
}

export function portableLazy(getter) {
  let state = "unresolved";
  let target;
  let failure;
  const resolve = () => {
    if (state === "resolving") {
      throw new SchemaAuthoringError(
        "CAP_ZOD_REF_UNREPRESENTABLE",
        "/$ref",
        "A lazy getter must return its local schema without resolving itself.",
      );
    }
    if (state === "unresolved") {
      state = "resolving";
      try {
        target = getter();
        state = "resolved";
      } catch (error) {
        failure = error;
        state = "failed";
      }
    }
    if (state === "failed") throw failure;
    return target;
  };
  const lazy = z.lazy(resolve);
  // Zod's accessor retains an evaluation sentinel after a throw; keep every consumer on the outcome memoizer.
  Object.defineProperty(lazy._zod, "innerType", {
    configurable: true,
    get: resolve,
  });
  PORTABLE_LAZIES.set(lazy, { resolve });
  return lazy;
}

function portabilityDiagnosticsUnchecked(schema, context) {
  if (!schema?._zod) {
    return [
      diagnostic(
        "CAP_ZOD_CONSTRUCT_UNSUPPORTED",
        basePath(context.fixtureId),
        "Value is not a supported author schema.",
      ),
    ];
  }
  const graph = collectGraph(schema);
  if (graph.budgetFailure) {
    return [
      diagnostic(
        "CAP_ZOD_CONSTRUCT_UNSUPPORTED",
        `${basePath(context.fixtureId)}${graph.budgetFailure.path}`,
        graph.budgetFailure.reason,
      ),
    ];
  }
  const diagnostics = [];
  for (const entry of graph.entries)
    checkDefinition(entry, context, diagnostics);
  if (diagnostics.length === 0) {
    for (const entry of graph.entries)
      checkDefaultAgreement(entry, context, diagnostics);
  }
  return dedupeAndSort(diagnostics);
}

export function portabilityDiagnostics(schema, context) {
  const stableContext = normalizeContext(context);
  try {
    return portabilityDiagnosticsUnchecked(schema, stableContext);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return [
      diagnostic(
        "CAP_ZOD_CONVERSION_FAILED",
        basePath(stableContext.fixtureId),
        `Zod portability preflight failed: ${message}`,
      ),
    ];
  }
}

function normalizeSchema(value) {
  if (Array.isArray(value)) return value.map(normalizeSchema);
  if (!value || typeof value !== "object") return value;
  const source = { ...value };
  if (source.anyOf) {
    source.oneOf = source.anyOf;
    delete source.anyOf;
  }
  if (
    Array.isArray(source.type) &&
    !(source.type.length === 2 && source.type.includes("null"))
  ) {
    source.oneOf = source.type.map((type) => ({ type }));
    delete source.type;
  }
  if (
    source.$ref &&
    source.$defs &&
    Object.keys(source).every((key) =>
      ["$schema", "$ref", "$defs"].includes(key),
    )
  ) {
    const name = source.$ref.match(/^#\/\$defs\/(.+)$/u)?.[1];
    if (name && source.$defs[name])
      Object.assign(source, source.$defs[name], { $defs: source.$defs });
    delete source.$ref;
  }
  const normalized = {};
  for (const key of Object.keys(source).sort(codePointCompare)) {
    let child = source[key];
    if (["$defs", "properties"].includes(key)) {
      child = Object.fromEntries(
        Object.keys(child)
          .sort(codePointCompare)
          .map((name) => [name, normalizeSchema(child[name])]),
      );
    } else if (key === "items") child = normalizeSchema(child);
    else if (key === "oneOf")
      child = child
        .map(normalizeSchema)
        .sort((left, right) => codePointCompare(jcs(left), jcs(right)));
    else if (key === "required" || (key === "type" && Array.isArray(child)))
      child = [...new Set(child)].sort(codePointCompare);
    else if (key === "enum")
      child = [...child].sort((left, right) =>
        codePointCompare(jcs(left), jcs(right)),
      );
    normalized[key] = child;
  }
  return normalized;
}

function removePinnedIpv6Patterns(schema) {
  if (!schema || typeof schema !== "object" || Array.isArray(schema)) return;
  if (schema[IPV6_PROVENANCE_KEY] === IPV6_PROVENANCE_VALUE) {
    delete schema[IPV6_PROVENANCE_KEY];
    if (
      schema.format === "ipv6" &&
      schema.pattern === PINNED_IPV6_NATIVE_PATTERN
    )
      delete schema.pattern;
  }
  for (const key of ["$defs", "properties"]) {
    const entries = schema[key];
    if (entries && typeof entries === "object" && !Array.isArray(entries))
      for (const child of Object.values(entries))
        removePinnedIpv6Patterns(child);
  }
  removePinnedIpv6Patterns(schema.items);
  for (const key of ["anyOf", "oneOf"]) {
    const alternatives = schema[key];
    if (Array.isArray(alternatives))
      for (const child of alternatives) removePinnedIpv6Patterns(child);
  }
}

function profileDocument(schema, direction) {
  const emptyObject = {
    type: "object",
    properties: {},
    required: [],
    additionalProperties: false,
  };
  return {
    irVersion: "0.1",
    service: { name: "zod-portability-spike", version: "0.0.0", tags: [] },
    schemas: {},
    capabilities: [
      {
        id: "fixtures.portability",
        version: "0.0.0",
        summary: "Portability fixture",
        tags: [],
        input: { schema: direction === "input" ? schema : emptyObject },
        output: { schema: direction === "output" ? schema : emptyObject },
        errors: {},
        access: {
          authentication: "public",
          permissions: { public: true },
          exposure: {
            http: "disabled",
            cli: "disabled",
            mcp: "disabled",
            internal: "private",
          },
        },
        effects: {
          impact: "read",
          idempotency: "intrinsic",
          confirmation: "none",
          retry: { mode: "safe" },
        },
        execution: { mode: "inline", result: "unary", cancellable: false },
        requirements: { secrets: [], resources: [], environment: [] },
        limits: {},
        lifecycle: { status: "experimental" },
        interfaces: {
          http: { enabled: false },
          cli: { enabled: false },
          mcp: { enabled: false },
          docs: { enabled: false },
          sdk: { enabled: false },
        },
        examples: [],
      },
    ],
  };
}

export function validatePortableProfile(schema, context) {
  const stableContext = normalizeContext(context);
  try {
    const field = stableContext.direction === "output" ? "output" : "input";
    const prefix = `/capabilities/0/${field}/schema`;
    return validateCapabilityDocument(
      profileDocument(schema, stableContext.direction),
      { requireNormalized: true },
    ).map((item) => ({
      ...item,
      path: item.path.startsWith(prefix)
        ? `${basePath(stableContext.fixtureId)}${item.path.slice(prefix.length)}`
        : basePath(stableContext.fixtureId),
    }));
  } catch (error) {
    return [
      diagnostic(
        "CAP_ZOD_CONVERSION_FAILED",
        basePath(stableContext.fixtureId),
        `Portable profile validation failed: ${error instanceof Error ? error.message : String(error)}`,
      ),
    ];
  }
}

function convertZodSchemaUnchecked(schema, context) {
  const diagnostics = portabilityDiagnostics(schema, context);
  if (diagnostics.length) return { accepted: false, diagnostics };
  const graph = collectGraph(schema);
  const metadata = z.registry();
  const recursiveNames = new Map(
    graph.recursiveTargets.map((node, index) => [node, `d${index}`]),
  );
  const registered = new WeakSet();
  for (const { schema: node } of graph.entries) {
    if (registered.has(node)) continue;
    registered.add(node);
    const source = inspectMetadata(node).annotations;
    const annotations = {
      ...source,
      ...(recursiveNames.has(node) ? { id: recursiveNames.get(node) } : {}),
      ...(hasPinnedIpv6Check(node)
        ? { [IPV6_PROVENANCE_KEY]: IPV6_PROVENANCE_VALUE }
        : {}),
    };
    if (Object.keys(annotations).length) metadata.add(node, annotations);
  }
  let emitted;
  try {
    emitted = z.toJSONSchema(schema, {
      target: "draft-2020-12",
      io: context.direction,
      cycles: "ref",
      reused: "inline",
      metadata,
      unrepresentable: "throw",
    });
  } catch (error) {
    return {
      accepted: false,
      diagnostics: [
        diagnostic(
          "CAP_ZOD_CONVERSION_FAILED",
          basePath(context.fixtureId),
          `Native Zod conversion failed: ${error.message}`,
        ),
      ],
    };
  }
  removePinnedIpv6Patterns(emitted);
  const jsonSchema = normalizeSchema(emitted);
  const profileDiagnostics = validatePortableProfile(jsonSchema, context);
  if (profileDiagnostics.length)
    return { accepted: false, diagnostics: profileDiagnostics };
  return { accepted: true, diagnostics: [], jsonSchema };
}

export function convertZodSchema(schema, context) {
  const stableContext = normalizeContext(context);
  try {
    return convertZodSchemaUnchecked(schema, stableContext);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      accepted: false,
      diagnostics: [
        diagnostic(
          "CAP_ZOD_CONVERSION_FAILED",
          basePath(stableContext.fixtureId),
          `Zod portability conversion failed: ${message}`,
        ),
      ],
    };
  }
}

export function validatePortableValue(jsonSchema, value) {
  return canonicalizeInput(
    { schemas: {} },
    { input: { schema: jsonSchema } },
    value,
  );
}

export const zodSchemaProvider = {
  id: "zod@4.5.2",
  canHandle(value) {
    return Boolean(value?._zod?.def);
  },
  portabilityDiagnostics,
  toJsonSchema(value, context) {
    const result = convertZodSchema(value, context);
    if (!result.accepted) {
      const error = new Error(
        `${result.diagnostics[0].code} ${result.diagnostics[0].path}`,
      );
      error.diagnostics = result.diagnostics;
      throw error;
    }
    return result.jsonSchema;
  },
  createValidator(value) {
    const portableForRuntime =
      portabilityDiagnostics(value, {
        path: "/schema",
        direction: "input",
      }).length === 0;
    return {
      validate(input) {
        if (!portableForRuntime || !isPortableJson(input))
          return { accepted: false };
        const result = value.safeParse(input);
        return result.success && isPortableJson(result.data)
          ? { accepted: true, value: structuredClone(result.data) }
          : { accepted: false };
      },
    };
  },
};

export { DIALECT };
