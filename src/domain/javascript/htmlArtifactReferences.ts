import {
  defaultTreeAdapter,
  parse,
  type DefaultTreeAdapterTypes,
} from "parse5";

interface HtmlScriptReference {
  readonly scriptPath: string;
  readonly startOffset: number;
  readonly endOffset: number;
}

/** JavaScript written directly in a script element instead of loaded by URL. */
export interface HtmlInlineScript {
  readonly scriptType: "classic" | "module";
  /** Offsets of the script body, between the opening and closing tags. */
  readonly startOffset: number;
  readonly endOffset: number;
}

/**
 * Inline bodies whose exact locations are retained per HTML file. Every body
 * is still counted; locations beyond this bound are reported as omitted.
 */
export const HTML_INLINE_SCRIPT_LOCATION_LIMIT = 100;

// The JavaScript MIME type essences from the WHATWG MIME Sniffing standard.
const JAVASCRIPT_MIME_TYPES = new Set([
  "application/ecmascript",
  "application/javascript",
  "application/x-ecmascript",
  "application/x-javascript",
  "text/ecmascript",
  "text/javascript",
  "text/javascript1.0",
  "text/javascript1.1",
  "text/javascript1.2",
  "text/javascript1.3",
  "text/javascript1.4",
  "text/javascript1.5",
  "text/jscript",
  "text/livescript",
  "text/x-ecmascript",
  "text/x-javascript",
]);

/**
 * Classify a script element's type as HTML "prepare the script element" does.
 * Import maps, speculation rules and data blocks are not JavaScript.
 */
const inlineScriptType = (
  attrs: readonly { readonly name: string; readonly value: string }[],
): HtmlInlineScript["scriptType"] | null => {
  const type = attrs.find(({ name }) => name === "type");
  const language = attrs.find(({ name }) => name === "language");
  const declared =
    type !== undefined
      ? type.value
      : language !== undefined && language.value !== ""
        ? `text/${language.value}`
        : "";
  if (declared === "") return "classic";
  const essence = declared
    .replace(/^[\t\n\f\r ]+|[\t\n\f\r ]+$/gu, "")
    .toLowerCase();
  if (JAVASCRIPT_MIME_TYPES.has(essence)) return "classic";
  return essence === "module" ? "module" : null;
};

/**
 * Extract inert HTML script references, inline JavaScript bodies, and the
 * first document base href.
 */
export const htmlArtifactReferences = (
  text: string,
): {
  readonly baseHref: string | null;
  readonly scripts: readonly HtmlScriptReference[];
  /** The first inline bodies in document order, up to the location limit. */
  readonly inlineScripts: readonly HtmlInlineScript[];
  readonly inlineScriptCount: number;
} => {
  const pending: DefaultTreeAdapterTypes.Node[] = [
    parse(text, { sourceCodeLocationInfo: true }),
  ];
  const scripts: HtmlScriptReference[] = [];
  const inlineScripts: HtmlInlineScript[] = [];
  let inlineScriptCount = 0;
  let baseHref: string | null = null;
  while (pending.length > 0) {
    const node = pending.pop();
    if (node === undefined) continue;
    if (
      defaultTreeAdapter.isElementNode(node) &&
      node.namespaceURI === "http://www.w3.org/1999/xhtml"
    ) {
      if (node.tagName === "base" && baseHref === null) {
        const href = node.attrs.find(({ name }) => name === "href");
        if (href !== undefined) baseHref = href.value;
      }
      if (node.tagName === "script") {
        const src = node.attrs.find(({ name }) => name === "src");
        const location = node.sourceCodeLocation?.startTag;
        if (src !== undefined && src.value !== "" && location !== undefined) {
          scripts.push({
            scriptPath: src.value,
            startOffset: location.startOffset,
            endOffset: location.endOffset,
          });
        }
        const inline = src === undefined ? inlineScriptBody(node) : undefined;
        const scriptType =
          inline === undefined ? null : inlineScriptType(node.attrs);
        if (inline !== undefined && scriptType !== null) {
          inlineScriptCount += 1;
          if (inlineScripts.length < HTML_INLINE_SCRIPT_LOCATION_LIMIT)
            inlineScripts.push({ scriptType, ...inline });
        }
      }
    }
    // Template content belongs to a separate inert document fragment. Only
    // traverse the actual document children, without recursion on deep input.
    if ("childNodes" in node) {
      for (const child of node.childNodes.toReversed()) pending.push(child);
    }
  }
  return { baseHref, scripts, inlineScripts, inlineScriptCount };
};

/** Locate a script element's non-blank body; browsers ignore it when src is set. */
const inlineScriptBody = (
  node: DefaultTreeAdapterTypes.Element,
): { readonly startOffset: number; readonly endOffset: number } | undefined => {
  const startTag = node.sourceCodeLocation?.startTag;
  if (startTag === undefined) return undefined;
  let blank = true;
  let endOffset: number | undefined;
  for (const child of node.childNodes) {
    if (!defaultTreeAdapter.isTextNode(child)) continue;
    if (blank && /\S/u.test(child.value)) blank = false;
    endOffset = child.sourceCodeLocation?.endOffset ?? endOffset;
  }
  // An unclosed script's element range ends at its opening tag, so the body's
  // own text location bounds it.
  if (blank || endOffset === undefined) return undefined;
  return { startOffset: startTag.endOffset, endOffset };
};
