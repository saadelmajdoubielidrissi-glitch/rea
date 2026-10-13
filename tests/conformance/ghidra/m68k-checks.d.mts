export interface M68kFixtureFacts {
  architecture: "m68k";
  flags: number;
  entry: string;
  file_offset: number;
  segment_size: number;
  sha256: string;
}
export function parseM68kFixture(bytes: Buffer): M68kFixtureFacts;
export function assertM68kLoadedImage(
  observations: unknown,
  sha256: string,
): void;
export function assertM68kProbe(move: unknown, branch: unknown): void;
export function assertM68kGlobal(bytes: string): void;
export function assertM68kMarker(bytes: string): void;
