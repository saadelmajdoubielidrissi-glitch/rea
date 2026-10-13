import { z } from "zod";
import type { JsonValue } from "../jsonValue.js";

const responseSchema = z.object({
  response: z.object({
    status: z.unknown().optional(),
    content: z.unknown().optional(),
    headers: z.unknown().optional(),
  }),
});
const contentSchema = z.object({ mimeType: z.unknown().optional() });
const headerSchema = z.object({ name: z.string(), value: z.unknown() });

/** A duplicate or unreadable header cannot establish a single Content-Type. */
const sazContentType = (headers: unknown): string | undefined => {
  if (!Array.isArray(headers)) return undefined;
  let found = false;
  let value: string | undefined;
  for (const header of headers) {
    const parsed = headerSchema.safeParse(header);
    if (!parsed.success) return undefined;
    // Bound case folding to the one field name this projection consumes.
    if (
      parsed.data.name.length !== 12 ||
      parsed.data.name.toLowerCase() !== "content-type"
    )
      continue;
    if (found) return undefined;
    found = true;
    value =
      typeof parsed.data.value === "string" ? parsed.data.value : undefined;
  }
  return value;
};

/** Interpret retained format facts; never reparse HTTP bytes or inspect bodies. */
export const apiSurfaceResponse = (
  reported: JsonValue,
  format: "har" | "saz",
): { readonly status: number | null; readonly mime: string } => {
  const parsed = responseSchema.safeParse(reported);
  if (!parsed.success) return { status: null, mime: "" };
  const response = parsed.data.response;
  const status =
    format === "saz"
      ? typeof response.status === "string" &&
        /^[0-9]{3}$/u.test(response.status)
        ? Number(response.status)
        : null
      : typeof response.status === "number"
        ? response.status
        : null;
  const content = contentSchema.safeParse(response.content);
  const mime =
    format === "saz"
      ? sazContentType(response.headers)
      : content.success
        ? content.data.mimeType
        : undefined;
  return {
    status: status === 0 ? null : status,
    mime: typeof mime === "string" ? mime : "",
  };
};
