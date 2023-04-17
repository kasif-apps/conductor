import {
  WebSocketClient,
  WebSocketServer,
} from "https://deno.land/x/websocket@v0.1.4/mod.ts";
import { create, verify } from "https://deno.land/x/djwt@v2.8/mod.ts";
import { join } from "https://deno.land/std@0.183.0/path/mod.ts";
import { getAvailablePort } from "https://deno.land/x/port@1.0.0/mod.ts";

const port = await getAvailablePort() as number;

const packages: Map<
  string,
  // deno-lint-ignore no-explicit-any
  Record<string, (...args: any[]) => Promise<any> | any>
> = new Map();

const rootPath = Deno.args[0];
const root = Deno.readDir(join(rootPath, "apps"));

for await (const plugin of root) {
  if (plugin.isDirectory) {
    const manifest = await readManifest(
      join(rootPath, "apps", plugin.name, "package.json")
    );
    const { backend } = manifest.kasif;

    const scriptPath = join(
      rootPath,
      "apps",
      plugin.name,
      backend.dir,
      `${backend.entry}.ts`
    );
    const mod = await import(scriptPath);
    packages.set(manifest.kasif.identifier, mod);
  }
}

async function readManifest(path: string) {
  const raw = await Deno.readFile(path);
  const decoder = new TextDecoder();
  const content = decoder.decode(raw);
  const parsed = JSON.parse(content);
  return parsed;
}

interface ServerMessage {
  token: string;
  action: ServerAction;
}

type ServerAction = ServerCallAction | ServerRetrieveAction;

interface ServerCallAction {
  id: string;
  type: "call";
  name: string;
  // deno-lint-ignore no-explicit-any
  arguments: any[];
}

interface ServerRetrieveAction {
  id: string;
  type: "retrieve";
  name: string;
}

interface ServerResponse {
  error: string | null;
  message: string;
}

class Server extends EventTarget {
  ws!: WebSocket;
  key!: CryptoKey;

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

    verify(message.token, this.key)
      .then(async (payload) => {
        const result = await this.handleAction(
          payload.name as string,
          message.action
        );

        this.send({ ...result, id: message.action.id }, client);
      })
      .catch((error) => {
        this.send(
          {
            error: "unauthorized",
            message: String(error),
            id: message.action.id,
          },
          client
        );
      });
  }

  async handleAction(
    name: string,
    action: ServerAction
  ): Promise<ServerResponse> {
    switch (action.type) {
      case "call":
        return await this.callAction(name, action);
      case "retrieve":
        return this.retrieveAction(name, action);
    }
  }

  async callAction(
    name: string,
    action: ServerCallAction
  ): Promise<ServerResponse> {
    const p = packages.get(name);

    if (p) {
      if (p[action.name]) {
        try {
          const result = await p[action.name].call(
            globalThis,
            action.arguments
          );
          return {
            error: null,
            message: result,
          };
        } catch (error) {
          return {
            error: String(error),
            message: "runtime error",
          };
        }
      } else {
        return {
          error: `no function named ${action.name} in ${name}`,
          message: `no function named ${action.name} in ${name}`,
        };
      }
    }

    return {
      error: `no package named ${name}`,
      message: `no package named ${name}`,
    };
  }

  retrieveAction(name: string, action: ServerRetrieveAction): ServerResponse {
    const p = packages.get(name);

    if (p) {
      if (p[action.name]) {
        return {
          error: null,
          message: p[action.name] as unknown as string,
        };
      } else {
        return {
          error: `no constant named ${action.name} in ${name}`,
          message: `no constant named ${action.name} in ${name}`,
        };
      }
    }

    return {
      error: `no package named ${name}`,
      message: `no package named ${name}`,
    };
  }

  send<T>(message: T, client: WebSocketClient) {
    client.send(JSON.stringify(message));
  }

  async generateToken(plugin: { name: string; version: string }) {
    const jwt = await create({ alg: "HS512", typ: "JWT" }, plugin, this.key);

    return jwt;
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

server.addEventListener("ready", async () => {
  const tokens: Record<string, string> = {};
  for await (const entry of packages.entries()) {
    tokens[entry[0]] = await server.generateToken({
      name: entry[0],
      version: "0.0.1",
    });
  }
  const encoder = new TextEncoder();
  const content = encoder.encode(JSON.stringify({ tokens, port }));
  await Deno.writeFile(join(rootPath, "remote", "stdout.json"), content);

  server.serve();
});
