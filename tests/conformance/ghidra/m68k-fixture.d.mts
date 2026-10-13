export const M68K_FIXTURE: {
  readonly file_name: string;
  readonly architecture: "m68k";
  readonly language_id: string;
  readonly compiler_spec_id: string;
  readonly flags: number;
  readonly entry: number;
  readonly file_offset: number;
  readonly segment_size: number;
  readonly probe: {
    readonly move: { readonly address: number; readonly bytes: string };
    readonly branch: {
      readonly address: number;
      readonly bytes: string;
      readonly target: number;
    };
  };
  readonly global: { readonly address: number; readonly bytes: string };
  readonly marker: { readonly address: number; readonly text: string };
};
export function m68kFixtureBytes(): Buffer;
export function buildM68kFixture(directory: string): Promise<{
  path: string;
  bytes: Buffer;
  sha256: string;
}>;
