// OpenClaw native plugin for sudo39
// Spawns `sudo39` and communicates via MCP JSON-RPC over stdio.

import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { Type } from "@sinclair/typebox";
import { spawn, type ChildProcess } from "node:child_process";
import { createInterface, type Interface as ReadlineInterface } from "node:readline";

const CALL_TIMEOUT_MS = 120_000;

// ---------------------------------------------------------------------------
// MCP JSON-RPC client - talks to `sudo39` over stdio
// ---------------------------------------------------------------------------

interface PendingEntry {
  resolve: (v: unknown) => void;
  reject: (e: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

interface McpClient {
  proc: ChildProcess;
  rl: ReadlineInterface;
  nextId: number;
  pending: Map<number, PendingEntry>;
  initialized: Promise<void>;
}

function destroyClient(client: McpClient) {
  client.rl.close();
  for (const [, entry] of client.pending) {
    clearTimeout(entry.timer);
    entry.reject(new Error("sudo39 process exited"));
  }
  client.pending.clear();
  if (client.proc.exitCode === null) {
    client.proc.kill();
  }
}

function createMcpClient(binaryPath: string, env: Record<string, string>): McpClient {
  const proc = spawn(binaryPath, [], {
    stdio: ["pipe", "pipe", "ignore"],
    env: { ...process.env, ...env },
  });

  const rl = createInterface({ input: proc.stdout! });
  const client: McpClient = {
    proc,
    rl,
    nextId: 0,
    pending: new Map(),
    initialized: Promise.resolve(),
  };

  rl.on("line", (line) => {
    try {
      const msg = JSON.parse(line);
      if (msg.id !== undefined) {
        const entry = client.pending.get(msg.id);
        if (entry) {
          clearTimeout(entry.timer);
          client.pending.delete(msg.id);
          if (msg.error) {
            entry.reject(new Error(msg.error.message || JSON.stringify(msg.error)));
          } else {
            entry.resolve(msg.result);
          }
        }
      }
    } catch {
      // ignore non-JSON lines
    }
  });

  proc.on("exit", () => destroyClient(client));

  // MCP initialize handshake
  client.initialized = (async () => {
    await rpcCall(client, "initialize", {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "openclaw-sudo39", version: "1.0.0" },
    });
    proc.stdin!.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
  })();

  return client;
}

function rpcCall(client: McpClient, method: string, params?: unknown): Promise<unknown> {
  return new Promise((resolve, reject) => {
    client.nextId++;
    const id = client.nextId;
    const timer = setTimeout(() => {
      client.pending.delete(id);
      reject(new Error(`sudo39 RPC timeout: ${method}`));
    }, CALL_TIMEOUT_MS);
    client.pending.set(id, { resolve, reject, timer });
    client.proc.stdin!.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
  });
}

interface ToolResult {
  content?: Array<{ type: string; text?: string }>;
  isError?: boolean;
}

async function callTool(client: McpClient, toolName: string, args?: Record<string, unknown>): Promise<string> {
  await client.initialized;
  const result = await rpcCall(client, "tools/call", { name: toolName, arguments: args ?? {} }) as ToolResult;

  if (result.isError) {
    const text = result.content?.map((c) => c.text ?? "").join("\n") || "Unknown error";
    throw new Error(text);
  }

  return result.content?.map((c) => c.text ?? "").join("\n") || "";
}

// ---------------------------------------------------------------------------
// Plugin entry
// ---------------------------------------------------------------------------

export default definePluginEntry({
  id: "sudo39",
  name: "sudo39",
  description: "Guarded privilege-elevation MCP server for AI agents",

  register(api) {
    const config = api.pluginConfig as {
      binaryPath?: string;
      allowedPrograms?: string;
      allowUnsafe?: boolean;
      timeoutSecs?: number;
      askpassPath?: string;
    };
    const binaryPath = config.binaryPath || "sudo39";

    // Build env overrides from plugin config
    const env: Record<string, string> = {};
    if (config.allowedPrograms) env.SUDO39_ALLOWED_PROGRAMS = config.allowedPrograms;
    if (config.allowUnsafe) env.SUDO39_ALLOW_UNSAFE = "1";
    if (config.timeoutSecs) env.SUDO39_TIMEOUT_SECS = String(config.timeoutSecs);
    if (config.askpassPath) env.SUDO39_ASKPASS = config.askpassPath;

    let client: McpClient | null = null;
    let clientCreating = false;

    function getClient(): McpClient {
      if (!client || client.proc.exitCode !== null) {
        if (clientCreating) return client!;
        clientCreating = true;
        client = createMcpClient(binaryPath, env);
        clientCreating = false;
      }
      return client;
    }

    function proxyTool(
      name: string,
      description: string,
      parameters: ReturnType<typeof Type.Object>,
    ) {
      api.registerTool({
        name,
        description,
        parameters,
        async execute(_id, params) {
          const text = await callTool(getClient(), name, params as Record<string, unknown>);
          return { content: [{ type: "text" as const, text }] };
        },
      });
    }

    // -- sudo_run -------------------------------------------------------------
    proxyTool("sudo_run",
      "Run a command through the host OS elevation mechanism (sudo, pkexec, osascript, or UAC)",
      Type.Object({
        command: Type.String({ description: "Program to run (single program path, no shell)" }),
        arguments: Type.Optional(Type.Array(Type.String(), { description: "Arguments passed to the program" })),
        mode: Type.Optional(Type.String({ description: "Elevation mode: auto, sudo, pkexec, macos_osascript, or windows_uac" })),
      }),
    );

    // -- sudo39_policy --------------------------------------------------------
    proxyTool("sudo39_policy",
      "Show the active sudo39 runtime policy (allowlist and flags)",
      Type.Object({}),
    );

    // -- sudo39_add_allowed_program -------------------------------------------
    proxyTool("sudo39_add_allowed_program",
      "Add a program to the runtime allowlist (requires confirmation phrase)",
      Type.Object({
        program: Type.String({ description: "Program path to add to the allowlist" }),
        confirmation: Type.String({ description: "Exact confirmation phrase from the confirm_add prompt" }),
      }),
    );

    // -- sudo39_remove_allowed_program ----------------------------------------
    proxyTool("sudo39_remove_allowed_program",
      "Remove a program from the runtime allowlist (requires confirmation phrase)",
      Type.Object({
        program: Type.String({ description: "Program path to remove from the allowlist" }),
        confirmation: Type.String({ description: "Exact confirmation phrase from the confirm_remove prompt" }),
      }),
    );

    // -- sudo39_set_allow_unsafe ----------------------------------------------
    proxyTool("sudo39_set_allow_unsafe",
      "Turn runtime unsafe mode on or off (requires confirmation phrase)",
      Type.Object({
        allow: Type.Boolean({ description: "true to enable unsafe mode, false to disable" }),
        confirmation: Type.String({ description: "Exact confirmation phrase from the confirm_unsafe prompt" }),
      }),
    );

    // -- sudo39_reload_policy_from_env ----------------------------------------
    proxyTool("sudo39_reload_policy_from_env",
      "Reload the runtime policy from SUDO39_ALLOWED_PROGRAMS and SUDO39_ALLOW_UNSAFE env vars",
      Type.Object({
        confirmation: Type.String({ description: "Exact confirmation phrase from the confirm_reload prompt" }),
      }),
    );

    // -- cleanup on gateway shutdown -----------------------------------------
    api.on("shutdown", () => {
      if (client) destroyClient(client);
    });

    api.logger.info("sudo39 plugin registered");
  },
});
