import {
  WebSocketClient,
  WebSocketServer,
} from "https://deno.land/x/websocket@v0.1.4/mod.ts";
import { create, verify } from "https://deno.land/x/djwt@v2.8/mod.ts";
import {
  join,
  resolve,
  fromFileUrl,
  dirname,
} from "https://deno.land/std@0.183.0/path/mod.ts";
import { getAvailablePort } from "https://deno.land/x/port@1.0.0/mod.ts";

const port = Deno.args[1]
  ? parseInt(Deno.args[1])
  : ((await getAvailablePort()) as number);

function getModuleDir(importMeta: ImportMeta): string {
  return resolve(dirname(fromFileUrl(importMeta.url)));
}

const rootPath = Deno.args[0];

interface TokenPayload {
  version: string;
  name: string;
  error: boolean;
}

interface ServerMessage {
  token: string;
  action: ServerAction;
}

type ServerAction =
  | CallAction
  | RetrieveAction
  | ConnectAction
  | ResponseAction;

interface CallAction {
  id: string;
  type: "call";
  name: string;
  arguments: unknown[];
}

interface RetrieveAction {
  id: string;
  type: "retrieve";
  name: string;
}

interface ConnectAction {
  id: string;
  name: string;
  type: "connect";
}

interface ResponseAction {
  id: string;
  type: "response";
  error: string | null;
  message: string;
}

type ServerResponse =
  | CallResponse
  | RetrieveResponse
  | ResponseResponse
  | ConnectResponse;

interface CallResponse {
  type: "call";
  id: string;
  error: string | null;
  message: unknown;
}

interface RetrieveResponse {
  type: "retrieve";
  id: string;
  error: string | null;
  message: unknown;
}

interface ResponseResponse {
  id: string;
  type: "response";
  error: string | null;
  message: unknown;
}

interface ConnectResponse {
  id: string;
  type: "connect";
  error: string | null;
  message: string;
}

class Server extends EventTarget {
  ws!: WebSocket;
  key!: CryptoKey;
  plugins: Map<
    string,
    {
      client: WebSocketClient;
      functions: Record<
        string,
        (...args: unknown[]) => Promise<unknown> | unknown
      >;
    }
  > = new Map();
  resolvers = new Map<string, (message: string) => unknown>();

  constructor(public port: number) {
    super();

    crypto.subtle
      .generateKey({ name: "HMAC", hash: "SHA-512" }, true, ["sign", "verify"])
      .then((key) => {
        this.key = key;
        this.dispatchEvent(new CustomEvent("ready"));
      });
  }

  handleMessage(data: string, client: WebSocketClient) {
    const message: ServerMessage = JSON.parse(data);

    switch (message.action.type) {
      case "call":
        this.callAction(message.token, message.action).then((response) => {
          this.send(response, client);
        });
        break;
      case "retrieve":
        this.retrieveAction(message.token, message.action).then((response) =>
          this.send(response, client)
        );
        break;
      case "connect":
        this.connectAction(message.action, client).then((response) =>
          this.send(response, client)
        );
        break;
      case "response":
        this.responseAction(message.token, message.action);
        break;
      default:
        this.send(
          this.createErrorResponse(message.action, "unknown action"),
          client
        );
        break;
    }
  }

  async authenticate(token: string): Promise<TokenPayload> {
    try {
      const payload = await verify(token, this.key);
      return {
        name: payload.name as string,
        version: payload.version as string,
        error: false,
      };
    } catch (_error) {
      return { name: "", version: "", error: true };
    }
  }

  async responseAction(token: string, action: ResponseAction) {
    const { error } = await this.authenticate(token);

    if (error) {
      return;
    }

    const resolver = this.resolvers.get(action.id);
    console.log(resolver, this.resolvers);

    if (!resolver) {
      return;
    }

    try {
      if (action.error) {
        console.log(error)
      }else {
        resolver(action.message);
      }
    } catch (_error) {
      console.log(error);
    }
  }

  async callAction(token: string, action: CallAction): Promise<ServerResponse> {
    const { error, name } = await this.authenticate(token);

    if (error) {
      return this.createErrorResponse(action, "unauthenticated");
    }

    const plugin = this.plugins.get(name);

    if (!plugin) {
      return this.createErrorResponse(action, `package '${name}' not found`);
    }

    const func = plugin.functions[action.name];

    if (!func) {
      return this.createErrorResponse(
        action,
        `function '${action.name}' not found in plugin '${name}'`
      );
    }

    try {
      const result = await func.call(globalThis, action.arguments);
      return this.createHealthyResponse(action, result || null);
    } catch (error) {
      return this.createErrorResponse(action, String(error));
    }
  }

  async retrieveAction(
    token: string,
    action: RetrieveAction
  ): Promise<ServerResponse> {
    const { error, name } = await this.authenticate(token);

    if (error) {
      return this.createErrorResponse(action, "unauthenticated");
    }

    const plugin = this.plugins.get(name);

    if (!plugin) {
      return this.createErrorResponse(action, `package '${name}' not found`);
    }

    const constant = plugin.functions[action.name];

    if (!constant) {
      return this.createErrorResponse(
        action,
        `constant '${action.name}' not found in plugin '${name}'`
      );
    }

    try {
      return this.createHealthyResponse(action, constant);
    } catch (error) {
      return this.createErrorResponse(action, String(error));
    }
  }

  async connectAction(
    action: ConnectAction,
    client: WebSocketClient
  ): Promise<ServerResponse> {
    try {
      const manifest = JSON.parse(
        await Deno.readTextFile(join(rootPath, action.name, "package.json"))
      );

      const { backend } = manifest.kasif;

      const scriptPath = join(
        rootPath,
        action.name,
        backend.dir,
        `${backend.entry}.ts`
      );

      // @ts-expect-error global
      globalThis[manifest.kasif.identifier] = {
        remote: {
          functions: new Proxy(
            {},
            {
              get: (_, key) => {
                return (...args: unknown[]) =>
                  new Promise((resolver) => {
                    const id = crypto.randomUUID();
                    this.resolvers.set(id, resolver);
                    this.send(
                      { type: "response", name: key, id, arguments: args },
                      client
                    );
                  });
              },
            }
          ),
        },
      };

      const mod = await import(scriptPath);
      this.plugins.set(manifest.kasif.identifier, { client, functions: mod });

      const token = await this.generateToken({
        name: manifest.kasif.identifier,
        version: "0.0.1",
      });

      return this.createHealthyResponse(action, token);
    } catch (error) {
      return this.createErrorResponse(action, String(error));
    }
  }

  send<T>(message: T, client: WebSocketClient) {
    client.send(JSON.stringify(message));
  }

  async generateToken(plugin: { name: string; version: string }) {
    const jwt = await create({ alg: "HS512", typ: "JWT" }, plugin, this.key);

    return jwt;
  }

  createHealthyResponse(
    action: ServerAction,
    message: unknown
  ): ServerResponse {
    return {
      id: action.id,
      error: null,
      message,
      type: action.type,
    } as ServerResponse;
  }

  createErrorResponse(action: ServerAction, error: string): ServerResponse {
    return {
      id: action.id,
      error: error,
      message: error,
      type: action.type,
    };
  }

  serve() {
    const wss = new WebSocketServer(this.port);
    wss.on("connection", (client: WebSocketClient) => {
      client.on("message", (message: string) =>
        this.handleMessage(message, client)
      );
    });
  }
}

const server = new Server(port);

server.addEventListener("ready", () => {
  Deno.writeTextFileSync(
    join(getModuleDir(import.meta), "stdout.json"),
    JSON.stringify({ port })
  );
  server.serve();
});
