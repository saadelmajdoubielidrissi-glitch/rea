import { ArtifactResourceScope } from "../../src/artifacts/ArtifactResourceScope.js";
import { scanArtifactInventory } from "../../src/artifacts/inventory/ArtifactInventory.js";

/** Compute the root identity used by artifact-provider extraction fixtures. */
export const artifactGraphRootSha256 = async (
  path: string,
): Promise<string> => {
  const resources = new ArtifactResourceScope();
  try {
    const snapshot = await scanArtifactInventory(path, {
      resourceScope: resources,
      environment: process.env,
      integrity: { mode: "fail" },
    });
    return snapshot.manifest.root_sha256;
  } finally {
    await resources.close();
  }
};
