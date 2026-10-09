# @capaxle/docs-styles

Dependency-free CSS for Capaxle consumer capability documentation: resource navigation, interface views, request fields and response reference. Source train
`0.1.0-alpha.3`; source readiness does not authorize publication. This asset-only
package exports exactly `@capaxle/docs-styles/docs.css`, with no root or JavaScript
entry and no TypeScript configuration, declarations, build step or dependencies.
The packed inventory is `package.json`, `docs.css`, `README.md` and Apache-2.0
`LICENSE`.

## Consumer bundlers and offline use

A bundler with CSS support can import the exported stylesheet:

```ts
import "@capaxle/docs-styles/docs.css";
```

The bundler must include those bytes in the page's delivered CSS. Browsers cannot
resolve an npm package specifier directly. An offline site can copy the resolved
asset and serve it locally through a stylesheet link; no remote font, image or
other network dependency is required. Node tooling can resolve and read the file
without importing CSS as JavaScript:

```js
import { readFileSync } from "node:fs";
const css = readFileSync(
  new URL(import.meta.resolve("@capaxle/docs-styles/docs.css")),
  "utf8",
);
```

`@capaxle/app` embeds the verified stylesheet in generated documentation HTML
under the existing response CSP; no separate asset mount is needed. The
stylesheet identity and bytes are fingerprinted and verified in application
builds and deployments. Rebuild older documentation-enabled deployment artifacts
to include this required asset. CSS packaging does not change portable IR,
existing documentation archives or browser-model provenance.

## Themes and customization

The default follows `prefers-color-scheme`. A host may force a palette with
`<html data-capaxle-theme="light">` or `data-capaxle-theme="dark"`; a host is
responsible for selecting and persisting that preference. No theme-toggle script
or renderer option is provided by this package.

Override these custom properties after the package CSS to customize a
bundler/local host. All use the `--capaxle-docs-` prefix:

| Group      | Property suffixes                                                                                | Defaults                                  |
| ---------- | ------------------------------------------------------------------------------------------------ | ----------------------------------------- |
| Colors     | `background`, `surface`, `code-background`, `text`, `muted`, `link`, `border`, `focus`, `accent` | Light/dark palettes below                 |
| Typography | `font`, `mono`, `font-size`, `line-height`                                                       | system sans, UI monospace, `1rem`, `1.65` |
| Spacing    | `space`, `radius`                                                                                | `1rem`, `0.625rem`                        |
| Layout     | `max-width`, `reading-width`, `sidebar-width`, `header-height`                                   | `90rem`, `66rem`, `18rem`, `4rem`         |

For example, `:root { --capaxle-docs-space: 1.125rem; }` changes page spacing.
Arbitrary override colors are not certified for contrast. App's embedded
stylesheet is a verified build asset; changing an installed asset requires a
fresh build rather than modifying an existing deployment.

## Semantic selectors

The stylesheet presents a compact sticky header, an independently scrollable
18rem resource sidebar and a spacious main reference. Native sidebar and resource
`details`/`summary` controls collapse the renderer's disclosed navigation tree;
active ancestors open initially. Bounded nesting receives a modest inset; deeper
continuations retain explicit depth labels without cumulative indentation. Current-page links, deeper-group labels and
service/overview/connection links retain their renderer-owned semantics. Active
group summaries carry the full-row indicator with space before the native
disclosure arrow and label; the linked label keeps its current-page semantics.
Leaf capabilities retain their full-row current-page indicator.

A labeled native radio group presents API, CLI, MCP and SDK as segmented choices.
CSS shows the checked interface's panel; without CSS, all clearly headed
interface content remains readable. This is presentation only: no request
console, execution path, JavaScript state or ARIA tab claim. Canonical downloads,
summary and safety guidance stay outside the switch. API is selected first when
enabled; otherwise the first enabled projection in API/CLI/MCP/SDK order is
selected. Disabled projections are omitted by the renderer. The four choices
fit a 360px viewport and wrap naturally at smaller widths.

The primary hooks are `.documentation-layout`, `.sidebar`, `.docs-sidebar`,
`.docs-tree`, `.resource-group`, `.resource-item` (`--group-depth`),
`.resource-level`, `[aria-current="page"]`, `main#content`, `.skip`, `.summary`,
`.consumer-facts`, `.docs-fact`, `.notice`, `.invocation`, `.docs-method`, `.docs-endpoint`,
`.interface-switch`, `.interface-panels`, `.interface-panel`, `.docs-request`,
`.docs-response`, `.docs-binding-group`, `.docs-field`, `.docs-field-heading`,
`.docs-field-type`, `.docs-field-presence`, `.docs-field-origin`,
`.docs-field-constraints`, `.docs-interface-jump`, `.schema`, `.table-scroll`, `.capability-list` and
`.group-list`. Headings, native disclosure controls, readonly snippet textareas,
copy buttons and status regions retain their content and accessibility semantics.
The interface radio IDs `docs-view-api`, `docs-view-cli`, `docs-view-mcp` and
`docs-view-sdk` are
siblings before `.interface-panels`; each selects a panel's matching
`data-interface` value. A stylesheet host should use renderer-produced HTML.

Shared metadata uses five compact factual columns on wide desktops, three below
`70rem` and two below `48rem`. Each interface offers Request/Response/Examples
anchors; lengthy parameter constraints remain available through native disclosure
without obscuring the field description and requiredness.

SDK uses a dedicated code-first layout: setup, typed capability usage, unwrapped
returns, typed errors and authored examples. Labels and TypeScript badges identify
readonly, selectable `.docs-sdk-code` textareas; existing copy buttons copy their
static text. These snippets are documentation, never browser execution.
`capaxle build` emits TypeScript; the consuming project compiles the generated
client before using the shown `./capaxle-sdk.js` imports. Renderer-owned snippets
preserve mounted connection setup, actual SDK methods and caller-supplied controls;
the stylesheet supplies no code generation or credentials.

SDK hooks are `.docs-sdk`, `.docs-sdk-setup`, `.docs-sdk-usage`,
`.docs-sdk-returns`, `.docs-sdk-errors`, `.docs-sdk-code-block`,
`.docs-sdk-code-header`, `.docs-sdk-language`,
`textarea.docs-sdk-code` and `details.docs-sdk-details`. SDK code keeps indentation
and scrolls inside its labeled textarea; row counts come from the actual static
snippet, with a readable minimum and bounded initial height. Users can resize
vertically. Canonical schemas and declared errors remain reachable in native
disclosures and existing downloads. SDK-only styling leaves the API/CLI/MCP
layouts and shared safety guidance intact.

The sidebar becomes a full-width disclosure above the reference below `48rem`,
with tighter spacing below `30rem`. Schema tables keep a readable `36rem` minimum width at every viewport,
retain unbroken field/type/presence cells and reserve room for independently
wrapped description/constraints. Long field paths scroll inside the named table
region instead of compressing types or requiredness; other wrapped tables adopt
the same minimum below `30rem`. Long content wraps without page overflow. Focus outlines
cover links, buttons, textareas, disclosure summaries, interface choices,
keyboard-scrollable table regions and the skip-link landing. Meaningful control
borders and focus styles retain their contrast in both palettes and forced-color
mode. Subtle decorative dividers use the `divider` custom property; these do not
carry control boundaries or required content meaning.

## Default contrast evidence

WCAG relative-luminance measurements are asserted in
`tooling/tests/cap121-docs-styles.test.mjs`. The minimum ratios below compare each
foreground against all three theme backgrounds (`background`, `surface`,
`code-background`). Text targets are at least 4.5:1 for normal text and 3:1 for
large text; meaningful control borders and focus indicators target at least 3:1.

| Foreground | Light   | Dark    | Minimum target |
| ---------- | ------- | ------- | -------------- |
| text       | 13.80:1 | 12.25:1 | 4.5:1          |
| muted      | 6.74:1  | 7.69:1  | 4.5:1          |
| link       | 5.96:1  | 7.44:1  | 4.5:1          |
| border     | 4.24:1  | 4.76:1  | 3:1            |
| focus      | 5.96:1  | 8.04:1  | 3:1            |
| accent     | 5.96:1  | 7.44:1  | 3:1            |
