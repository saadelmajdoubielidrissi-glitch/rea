import * as t from "@babel/types";

import type { JavaScriptModuleOrigin } from "./javascriptSemanticIr.js";
import {
  resolveSemanticBindingState,
  semanticResolutionBlocked,
  type JavaScriptSemanticAnalysisState,
} from "./javascriptSemanticState.js";
import {
  semanticStaticPropertyKey,
  unwrapJavaScriptExpression,
} from "./javascriptAstValues.js";
import { stringValue } from "./javascriptStaticAnalysisHelpers.js";

export interface JavaScriptRequireOrigin {
  readonly origin: JavaScriptModuleOrigin;
  readonly call: t.CallExpression;
}

/** Strip a static member chain, returning its innermost expression and path. */
export const semanticMemberChain = (
  node: t.Node | null | undefined,
):
  | { readonly root: t.Node | null | undefined; readonly members: string[] }
  | undefined => {
  const members: string[] = [];
  let current = node;
  while (current !== null && current !== undefined) {
    current = unwrapJavaScriptExpression(current).node;
    if (
      !t.isMemberExpression(current) &&
      !t.isOptionalMemberExpression(current)
    )
      break;
    const member = semanticStaticPropertyKey(
      current.property,
      current.computed,
    );
    if (member === null || !t.isNode(current.object)) return undefined;
    members.push(member);
    current = current.object;
  }
  return { root: current, members: members.reverse() };
};

/** Recover an unshadowed literal require origin and its exact member path. */
export const semanticRequireOrigin = (
  node: t.Node | null | undefined,
  state: JavaScriptSemanticAnalysisState,
): JavaScriptRequireOrigin | undefined => {
  const chain = semanticMemberChain(node);
  const current = chain?.root;
  if (
    chain === undefined ||
    !t.isCallExpression(current) ||
    !t.isIdentifier(current.callee, { name: "require" })
  )
    return undefined;
  if (
    resolveSemanticBindingState(state, current.callee, "require") !==
      undefined ||
    semanticResolutionBlocked(state, current.callee, "require")
  )
    return undefined;
  const specifier = stringValue(current.arguments[0]);
  return specifier === undefined
    ? undefined
    : {
        origin: {
          specifier,
          importedPath: chain.members,
          resolutionMode: "require",
        },
        call: current,
      };
};
