import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';

import type { GuardedHttpRequest, GuardedHttpResponse, LogicalHttpExecutor } from '../../src/transport/guarded-transport.js';

export type FakeDeviceMode = 'pending' | 'slow_down' | 'denied' | 'expired' | 'success';

export type FakeGithubFault =
  | 'unauthorized'
  | 'rate-limited'
  | 'secondary-limit'
  | 'redirect'
  | 'upstream'
  | 'timeout'
  | 'oversized'
  | 'secret'
  | 'pii'
  | 'out-of-lab'
  | 'drop-after-mutation'
  | 'cleanup-failure';

export interface FakeGithubRequestLog {
  readonly operationId: string | undefined;
  readonly method: string;
  readonly path: string;
  readonly actor: 'owner' | 'researcher' | 'anonymous';
  readonly bodySha256: string;
}

export interface FakeGithubServerOptions {
  readonly bindAddress?: string;
  readonly bypass?: boolean;
}

export class FakeGithubServer {
  readonly #bindAddress: string;
  readonly #bypass: boolean;
  readonly #server: Server;
  readonly #requests: FakeGithubRequestLog[] = [];
  readonly #tokens = new Map<string, 'owner' | 'researcher'>([
    ['owner-token', 'owner'],
    ['researcher-token', 'researcher']
  ]);
  #fault: FakeGithubFault | undefined;
  #port: number | undefined;
  #marker = false;
  #repositoryId = 3003;
  #repositoryName = 'lab-fixture';
  #repositoryNodeId = 'R_lab';
  #deviceMode: FakeDeviceMode = 'success';
  #devicePolls = 0;

  constructor(options: FakeGithubServerOptions = {}) {
    this.#bindAddress = options.bindAddress ?? '127.0.0.1';
    if (this.#bindAddress !== '127.0.0.1') throw new Error('fake_server_loopback_only');
    this.#bypass = options.bypass === true;
    this.#server = createServer((request, response) => {
      void this.handle(request, response);
    });
  }

  async start(): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      this.#server.once('error', reject);
      this.#server.listen({ host: this.#bindAddress, port: 0 }, () => resolve());
    });
    const address = this.#server.address();
    if (address === null || typeof address === 'string') throw new Error('fake_server_address_invalid');
    this.#port = address.port;
  }

  async stop(): Promise<void> {
    if (!this.#server.listening) return;
    await new Promise<void>((resolve, reject) => this.#server.close((error) => error === undefined ? resolve() : reject(error)));
  }

  get baseUrl(): string {
    if (this.#port === undefined) throw new Error('fake_server_not_started');
    return `http://${this.#bindAddress}:${this.#port}`;
  }

  get requests(): readonly FakeGithubRequestLog[] {
    return [...this.#requests];
  }

  get markerPresent(): boolean {
    return this.#marker;
  }

  get repositoryId(): number {
    return this.#repositoryId;
  }

  renameRepository(name: string): void {
    if (!/^[A-Za-z0-9_.-]+$/u.test(name)) throw new Error('fake_repository_name_invalid');
    this.#repositoryName = name;
  }

  reuseRepository(name: string): void {
    this.renameRepository(name);
    this.#repositoryId = 4004;
    this.#repositoryNodeId = 'R_lab_reused';
  }

  setFault(fault: FakeGithubFault | undefined): void {
    this.#fault = fault;
  }

  setDeviceMode(mode: FakeDeviceMode): void {
    this.#deviceMode = mode;
    this.#devicePolls = 0;
  }

  setBypassMarker(value: boolean): void {
    if (value !== true) throw new Error('fake_server_bypass_is_immutable');
    this.#fault = undefined;
  }

  executor(): LogicalHttpExecutor {
    return {
      execute: async (request: GuardedHttpRequest): Promise<GuardedHttpResponse> => {
        const url = `${this.baseUrl}${request.url.pathname}${request.url.search}`;
        const response = await fetch(url, {
          method: request.method,
          headers: request.headers,
          redirect: 'manual',
          ...(request.body === undefined ? {} : { body: request.body })
        });
        const responseHeaders: Record<string, string> = {};
        response.headers.forEach((value, key) => { responseHeaders[key] = value; });
        return { status: response.status, headers: responseHeaders, body: await response.text() };
      }
    };
  }

  private async handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const body = await readBody(request);
    const actor = this.actorFromAuthorization(request.headers.authorization);
    const operationId = typeof request.headers['x-aegishub-operation-id'] === 'string' ? request.headers['x-aegishub-operation-id'] : operationIdForPath(request.url ?? '');
    this.#requests.push({ operationId, method: request.method ?? 'GET', path: request.url ?? '/', actor, bodySha256: sha256(body) });

    if (request.url === '/login/device' && request.method === 'POST') {
      this.#devicePolls = 0;
      return sendJson(response, 200, { device_code: 'synthetic-device-code', user_code: 'ABCD-EFGH', verification_uri: 'https://github.com/login/device', expires_in: 600, interval: 1 });
    }
    if (request.url === '/login/oauth/access_token' && request.method === 'POST') {
      this.#devicePolls += 1;
      if (this.#deviceMode === 'denied') return sendJson(response, 403, { error: 'access_denied' });
      if (this.#deviceMode === 'expired') return sendJson(response, 400, { error: 'expired_token' });
      if (this.#deviceMode === 'slow_down' && this.#devicePolls === 1) return sendJson(response, 400, { error: 'slow_down' });
      if (this.#deviceMode === 'pending' || (this.#deviceMode === 'slow_down' && this.#devicePolls < 3) || (this.#deviceMode === 'success' && this.#devicePolls < 2)) return sendJson(response, 400, { error: 'authorization_pending' });
      return sendJson(response, 200, { access_token: 'synthetic-device-access-token', token_type: 'bearer' });
    }

    const faultResponse = await this.handleFault(request, response, body);
    if (faultResponse) return;
    if (this.#fault === 'unauthorized') return sendJson(response, 401, { message: 'unauthorized' });
    if (this.#fault === 'rate-limited') return sendJson(response, 429, { message: 'rate limited' });
    if (this.#fault === 'secondary-limit') return sendJson(response, 403, { message: 'secondary rate limit' }, { 'x-ratelimit-remaining': '0' });
    if (this.#fault === 'redirect') {
      response.writeHead(302, { location: 'https://example.invalid/redirect' });
      response.end();
      return;
    }
    if (this.#fault === 'upstream') return sendJson(response, 500, { message: 'synthetic upstream failure' });
    if (this.#fault === 'oversized') return sendJson(response, 200, { oversized: 'x'.repeat(300_000) });
    if (this.#fault === 'secret') return sendJson(response, 200, { token: 'ghp_SYNTHETIC_FAKE_TOKEN' });
    if (this.#fault === 'pii') return sendJson(response, 200, { email: 'synthetic@example.invalid' });
    if (this.#fault === 'out-of-lab') return sendJson(response, 200, { repository: { id: 9999, node_id: 'R_out_of_lab', private: true } });

    if (request.url === '/user' && request.method === 'GET') {
      if (actor === 'owner') return sendJson(response, 200, { id: 1001, node_id: 'U_owner', login: 'owner-fixture' });
      if (actor === 'researcher') return sendJson(response, 200, { id: 2002, node_id: 'U_researcher', login: 'researcher-fixture' });
      return sendJson(response, 401, { message: 'authentication required' });
    }

    const repositoryPath = `/repos/owner-fixture/${this.#repositoryName}`;
    const markerPath = `${repositoryPath}/contents/.aegishub-lab.json`;
    if (request.url === repositoryPath && request.method === 'GET') {
      if (actor === 'owner' || this.#bypass) return sendJson(response, 200, { id: this.#repositoryId, node_id: this.#repositoryNodeId, private: true, permissions: { pull: actor === 'owner' } });
      return sendJson(response, 404, { message: 'not found' });
    }

    if (request.url === markerPath && request.method === 'GET') {
      if (actor === 'owner' || this.#bypass) return sendJson(response, 200, { marker: { schemaVersion: 1, labId: '95f38cca-42e2-4b7d-82e6-f13f4549b2f3', repositoryId: this.#repositoryId, owner: { id: 1001 } }, sha: 'a'.repeat(40) });
      return sendJson(response, 404, { message: 'not found' });
    }

    if (request.url === '/graphql' && request.method === 'POST') {
      let parsed: { readonly operationName?: unknown } = {};
      try {
        parsed = JSON.parse(body) as { readonly operationName?: unknown };
      } catch {
        return sendJson(response, 400, { errors: [{ message: 'invalid graphql body' }] });
      }
      if (parsed.operationName !== 'RepositoryLabMarkerV1') return sendJson(response, 400, { errors: [{ message: 'unknown document' }] });
      if (actor === 'owner' || this.#bypass) {
        return sendJson(response, 200, {
          data: {
            repository: {
              databaseId: this.#repositoryId,
              isPrivate: true,
              object: { text: JSON.stringify({ schemaVersion: 1, labId: '95f38cca-42e2-4b7d-82e6-f13f4549b2f3', repositoryId: this.#repositoryId, ownerId: 1001, controlNonce: 'synthetic-control-nonce-123456' }) }
            }
          }
        });
      }
      return sendJson(response, 200, { data: { repository: null } });
    }

    if (request.url === markerPath && request.method === 'PUT') {
      this.#marker = true;
      if (this.#fault === 'drop-after-mutation') {
        response.destroy();
        return;
      }
      return sendJson(response, 201, { content: { sha: 'a'.repeat(40) } });
    }

    if (request.url === markerPath && request.method === 'DELETE') {
      if (this.#fault === 'cleanup-failure') return sendJson(response, 500, { message: 'cleanup failed' });
      this.#marker = false;
      return sendJson(response, 200, { deleted: true });
    }

    return sendJson(response, 404, { message: 'route not found' });
  }

  private async handleFault(request: IncomingMessage, response: ServerResponse, body: string): Promise<boolean> {
    if (this.#fault === 'timeout') {
      await new Promise((resolve) => setTimeout(resolve, 250));
      sendJson(response, 504, { message: 'timeout' });
      return true;
    }
    void body;
    void request;
    return false;
  }

  private actorFromAuthorization(value: string | undefined): 'owner' | 'researcher' | 'anonymous' {
    if (value === undefined) return 'anonymous';
    const token = value.replace(/^Bearer\s+/iu, '');
    return this.#tokens.get(token) ?? 'anonymous';
  }
}

async function readBody(request: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  return Buffer.concat(chunks).toString('utf8');
}

function sendJson(response: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  const serialized = JSON.stringify(body);
  response.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(serialized), ...headers });
  response.end(serialized);
}

function sha256(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function operationIdForPath(path: string): string | undefined {
  if (path === '/graphql') return 'github.graphql.contents.get-lab-marker.v1';
  if (path.includes('/contents/.aegishub-lab.json')) return 'github.rest.contents.get-lab-marker.v1';
  if (path.startsWith('/repos/')) return 'github.rest.repos.get.v1';
  if (path === '/user') return 'github.rest.users.get-authenticated.v1';
  return undefined;
}
