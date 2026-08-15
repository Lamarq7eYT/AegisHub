import { stdin, stdout } from 'node:process';
import { createInterface, type Interface } from 'node:readline/promises';

export interface DeviceVerificationView {
  readonly verificationUri: string;
  readonly userCode: string;
  readonly expiresInSeconds: number;
}

export interface BountyTerminal {
  isInteractive(): boolean;
  showDeviceVerification?(verification: DeviceVerificationView): Promise<void>;
  approve(fingerprint: string, mutationCount: number): Promise<boolean>;
  print(message: string): void;
  warn(message: string): void;
  close(): void;
}

export class ReadlineBountyTerminal implements BountyTerminal {
  readonly #input: typeof stdin;
  readonly #output: typeof stdout;
  #readline: Interface | undefined;

  constructor(input: typeof stdin = stdin, output: typeof stdout = stdout) {
    this.#input = input;
    this.#output = output;
  }

  isInteractive(): boolean {
    return this.#input.isTTY === true && this.#output.isTTY === true;
  }

  async showDeviceVerification(verification: DeviceVerificationView): Promise<void> {
    this.print(`GitHub device verification: ${verification.verificationUri}`);
    this.print(`User code (expires in ${verification.expiresInSeconds}s): ${verification.userCode}`);
  }

  async approve(fingerprint: string, mutationCount: number): Promise<boolean> {
    if (mutationCount === 0) return true;
    if (!this.isInteractive()) return false;
    const readline = this.getReadline();
    const prefix = fingerprint.slice(0, 12);
    const answer = await readline.question(`Type RUN ${prefix} to approve ${mutationCount} mutation(s): `);
    return answer.trim() === `RUN ${prefix}`;
  }

  print(message: string): void {
    this.#output.write(`${message}\n`);
  }

  warn(message: string): void {
    this.#output.write(`Warning: ${message}\n`);
  }

  close(): void {
    this.#readline?.close();
    this.#readline = undefined;
  }

  private getReadline(): Interface {
    this.#readline ??= createInterface({ input: this.#input, output: this.#output });
    return this.#readline;
  }
}
