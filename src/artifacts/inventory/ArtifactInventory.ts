import { realpath } from "node:fs/promises";

import {
  artifactInventoryOutputSchema,
  type ArtifactInventoryOutput,
} from "../../domain/artifactGraph.js";
import { abortIfNeeded } from "../ArtifactHash.js";
import { ArtifactReaderFailure } from "../ArtifactReader.js";
import { scanCanonicalArtifactInventoryInScope } from "./scanCanonical.js";
import type { ArtifactInventoryOptions } from "./types.js";
import type { ArtifactInventorySnapshot } from "../../domain/artifactInventorySnapshot.js";

/** Inventory one local artifact and return every graph collection inline. */
export const inventoryArtifact = async (
  inputPath: string,
  options: ArtifactInventoryOptions,
): Promise<ArtifactInventoryOutput> => {
  const snapshot = await scanArtifactInventory(inputPath, options);
  return artifactInventoryOutputSchema.parse(snapshot);
};

/** Scan an artifact once and retain the complete immutable graph for projection. */
export const scanArtifactInventory = async (
  inputPath: string,
  options: ArtifactInventoryOptions,
): Promise<ArtifactInventorySnapshot> =>
  options.resourceScope.run(() =>
    scanArtifactInventoryInScope(inputPath, options),
  );

export const scanArtifactInventoryInScope = async (
  inputPath: string,
  options: ArtifactInventoryOptions,
): Promise<ArtifactInventorySnapshot> => {
  abortIfNeeded(options.signal);
  const path = await realpath(inputPath);
  const snapshot = await scanCanonicalArtifactInventoryInScope(path, options);
  if (
    options.expectedRootSha256 !== undefined &&
    snapshot.manifest.root_sha256 !== options.expectedRootSha256
  )
    throw new ArtifactReaderFailure(
      "integrity",
      `Active artifact digest changed: expected ${options.expectedRootSha256}, observed ${snapshot.manifest.root_sha256}`,
    );
  return snapshot;
};
