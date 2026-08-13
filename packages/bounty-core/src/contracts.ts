/**
 * RED checkpoint placeholder. The strict, versioned contracts are added only
 * after the remote runner has confirmed the focused contract test fails.
 */
export const labManifestSchema = {
  safeParse(value: unknown): { success: boolean } {
    void value;
    return { success: true };
  }
};
