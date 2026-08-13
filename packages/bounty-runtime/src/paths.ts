import { fileURLToPath } from 'node:url';

export const bountyRuntimeRoot = fileURLToPath(new URL('..', import.meta.url));
