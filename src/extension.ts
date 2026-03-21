import * as vscode from "vscode";
import * as https from "https";
import * as http from "http";
import * as url from "url";

// ── Types ─────────────────────────────────────────────────────────────────────

interface HallucinatedAPI {
  api_ref: string;
  file: string;
  line: number;
  reason: string;
  confidence: number;
  suggestion: string;
  source: string;
}

interface SecurityFinding {
  rule_id: string;
  file: string;
  line: number;
  message: string;
  severity: string;
  cwe: string;
}

interface EvalResult {
  eval_id: string;
  score: number;
  grade: "PASS" | "WARN" | "BLOCK";
  hallucination: {
    score: number;
    findings: HallucinatedAPI[];
    model: string;
    latency_ms: number;
  };
  security: {
    score: number;
    findings: SecurityFinding[];
    model: string;
    latency_ms: number;
  };
  intent: {
    score: number;
    code_summary: string;
    mismatches: string[];
    model: string;
  };
  latency_ms: number;
}

// Stored per URI after an eval completes — used by the CodeLens provider.
interface EvalState {
  evalId: string;
  hallucinationFindings: Array<{ findingId: string; line: number; label: string }>;
  securityFindings: Array<{ findingId: string; line: number; label: string }>;
}

// ── Config helpers ─────────────────────────────────────────────────────────────

function cfg() {
  return vscode.workspace.getConfiguration("runlit");
}
// Secrets storage takes priority over settings.json — set via "runlit: Set API Key" command.
async function apiToken(secrets: vscode.SecretStorage): Promise<string> {
  return (await secrets.get("runlit.apiToken")) ?? cfg().get<string>("apiToken", "");
}
function apiUrl(): string {
  return cfg().get<string>("apiUrl", "https://api.runlit.dev");
}
function threshold(): number {
  return cfg().get<number>("threshold", 80);
}

// ── HTTP helpers ───────────────────────────────────────────────────────────────

function postEval(
  endpoint: string,
  body: unknown,
  token: string
): Promise<EvalResult> {
  return new Promise((resolve, reject) => {
    const parsed = url.parse(endpoint);
    const payload = JSON.stringify(body);
    const options: http.RequestOptions = {
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === "https:" ? 443 : 80),
      path: parsed.path,
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(payload),
        Authorization: `Bearer ${token}`,
      },
    };
    const lib = parsed.protocol === "https:" ? https : http;
    const req = lib.request(options, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => {
        if (res.statusCode && res.statusCode >= 400) {
          reject(new Error(`API error ${res.statusCode}: ${data}`));
          return;
        }
        try {
          resolve(JSON.parse(data));
        } catch {
          reject(new Error(`Parse error: ${data}`));
        }
      });
    });
    req.on("error", reject);
    req.write(payload);
    req.end();
  });
}

/** POST /v1/evals/{evalId}/feedback — returns true on success. */
async function postFeedback(
  evalId: string,
  feedbackType: "thumbs_up" | "finding_dismissed",
  findingId: string,
  token: string
): Promise<boolean> {
  return new Promise((resolve) => {
    const base = apiUrl().replace(/\/$/, "");
    const parsed = url.parse(`${base}/v1/evals/${evalId}/feedback`);
    const payload = JSON.stringify({
      finding_id: findingId,
      feedback_type: feedbackType,
      source: "vscode",
    });
    const options: http.RequestOptions = {
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === "https:" ? 443 : 80),
      path: parsed.path,
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(payload),
        Authorization: `Bearer ${token}`,
      },
    };
    const lib = parsed.protocol === "https:" ? https : http;
    const req = lib.request(options, (res) => {
      res.resume(); // drain
      resolve(res.statusCode === 201 || res.statusCode === 200);
    });
    req.on("error", () => resolve(false));
    req.write(payload);
    req.end();
  });
}

// ── Diff builder ──────────────────────────────────────────────────────────────

function asDiff(content: string, filename: string): string {
  const lines = content.split("\n");
  return [
    `--- /dev/null`,
    `+++ b/${filename}`,
    `@@ -0,0 +1,${lines.length} @@`,
    ...lines.map((l) => `+${l}`),
  ].join("\n");
}

async function gitDiffForFile(uri: vscode.Uri): Promise<string | null> {
  try {
    const gitExt = vscode.extensions.getExtension("vscode.git");
    if (!gitExt) return null;
    const git = gitExt.exports.getAPI(1);
    if (!git || git.repositories.length === 0) return null;
    const repo = git.repositories[0];
    const changes = [
      ...(repo.state.workingTreeChanges || []),
      ...(repo.state.indexChanges || []),
    ];
    const change = changes.find(
      (c: { uri: vscode.Uri }) => c.uri.fsPath === uri.fsPath
    );
    if (!change) return null;
    return (await repo.diff(change)) || null;
  } catch {
    return null;
  }
}

// ── Diagnostics ───────────────────────────────────────────────────────────────

const diagnosticCollection =
  vscode.languages.createDiagnosticCollection("runlit");

function toDiagnostics(
  result: EvalResult,
  document: vscode.TextDocument
): vscode.Diagnostic[] {
  const diags: vscode.Diagnostic[] = [];

  for (const f of result.hallucination?.findings ?? []) {
    const lineIdx = Math.min(
      Math.max(0, (f.line || 1) - 1),
      document.lineCount - 1
    );
    const diag = new vscode.Diagnostic(
      document.lineAt(lineIdx).range,
      `Hallucinated API: ${f.api_ref} — ${f.reason}${
        f.suggestion ? ` → use: ${f.suggestion}` : ""
      }`,
      vscode.DiagnosticSeverity.Error
    );
    diag.source = `runlit (${f.source || "llm"})`;
    diag.code = {
      value: "hallucinated-api",
      target: vscode.Uri.parse(
        "https://docs.runlit.dev/signals/hallucination"
      ),
    };
    diags.push(diag);
  }

  for (const f of result.security?.findings ?? []) {
    const lineIdx = Math.min(
      Math.max(0, (f.line || 1) - 1),
      document.lineCount - 1
    );
    const sev = ["critical", "high"].includes(f.severity)
      ? vscode.DiagnosticSeverity.Error
      : vscode.DiagnosticSeverity.Warning;
    const diag = new vscode.Diagnostic(
      document.lineAt(lineIdx).range,
      `Security [${f.severity?.toUpperCase()}]: ${f.message}${
        f.cwe ? ` (${f.cwe})` : ""
      }`,
      sev
    );
    diag.source = "runlit-security";
    diags.push(diag);
  }

  return diags;
}

// ── Status bar ────────────────────────────────────────────────────────────────

function gradeIcon(grade: string, score: number): string {
  if (grade === "PASS") return `$(pass) runlit ${score}`;
  if (grade === "WARN") return `$(warning) runlit ${score}`;
  return `$(error) runlit ${score}`;
}

// ── CodeLens provider ─────────────────────────────────────────────────────────

/** Per-document eval state keyed by URI string. Cleared on new eval. */
const evalStateMap = new Map<string, EvalState>();

/** Set of dismissed finding IDs — persisted to workspaceState between restarts. */
let dismissedFindings: Set<string>;
const DISMISSED_KEY = "runlit.dismissedFindings";

const codeLensEventEmitter = new vscode.EventEmitter<void>();

class RunlitCodeLensProvider implements vscode.CodeLensProvider {
  onDidChangeCodeLenses = codeLensEventEmitter.event;

  provideCodeLenses(document: vscode.TextDocument): vscode.CodeLens[] {
    const state = evalStateMap.get(document.uri.toString());
    if (!state) return [];

    const lenses: vscode.CodeLens[] = [];
    const all = [...state.hallucinationFindings, ...state.securityFindings];

    for (const finding of all) {
      if (dismissedFindings.has(finding.findingId)) continue;

      const lineIdx = Math.min(
        Math.max(0, finding.line - 1),
        document.lineCount - 1
      );
      const range = document.lineAt(lineIdx).range;

      lenses.push(
        new vscode.CodeLens(range, {
          title: "$(check) Confirm",
          tooltip: "Mark this finding as correct — sends thumbs_up feedback",
          command: "runlit.confirmFinding",
          arguments: [state.evalId, finding.findingId, document.uri],
        }),
        new vscode.CodeLens(range, {
          title: "$(x) Dismiss",
          tooltip: "Dismiss this finding — sends finding_dismissed feedback",
          command: "runlit.dismissFinding",
          arguments: [state.evalId, finding.findingId, document.uri],
        })
      );
    }

    return lenses;
  }
}

// ── Core eval ─────────────────────────────────────────────────────────────────

async function runEval(
  document: vscode.TextDocument,
  diff: string,
  statusBar: vscode.StatusBarItem,
  secrets: vscode.SecretStorage
): Promise<void> {
  const token = await apiToken(secrets);
  if (!token) {
    const action = await vscode.window.showWarningMessage(
      "runlit: API token not set. Run \"runlit: Set API Key\" from the Command Palette.",
      "Set API Key"
    );
    if (action === "Set API Key") {
      vscode.commands.executeCommand("runlit.setApiKey");
    }
    return;
  }

  statusBar.text = "$(sync~spin) runlit";
  statusBar.backgroundColor = undefined;
  statusBar.show();

  try {
    const result = await postEval(
      `${apiUrl()}/v1/eval`,
      { diff },
      token
    );

    statusBar.text = gradeIcon(result.grade, result.score);
    statusBar.tooltip = [
      `runlit — ${result.score}/100 (${result.grade})`,
      `Hallucination: ${Math.round((result.hallucination?.score ?? 1) * 100)}`,
      `Security: ${Math.round((result.security?.score ?? 1) * 100)}`,
      `Latency: ${result.latency_ms}ms`,
      `Eval ID: ${result.eval_id}`,
    ].join("\n");
    statusBar.backgroundColor =
      result.grade === "BLOCK"
        ? new vscode.ThemeColor("statusBarItem.errorBackground")
        : result.grade === "WARN"
        ? new vscode.ThemeColor("statusBarItem.warningBackground")
        : undefined;

    // Build CodeLens state for this document
    const state: EvalState = {
      evalId: result.eval_id,
      hallucinationFindings: (result.hallucination?.findings ?? []).map(
        (f, i) => ({
          findingId: `hal-${result.eval_id}-${i}`,
          line: f.line || 1,
          label: `${f.api_ref}: ${f.reason}`,
        })
      ),
      securityFindings: (result.security?.findings ?? []).map((f, i) => ({
        findingId: `sec-${result.eval_id}-${i}`,
        line: f.line || 1,
        label: f.message,
      })),
    };
    evalStateMap.set(document.uri.toString(), state);
    codeLensEventEmitter.fire();

    diagnosticCollection.set(document.uri, toDiagnostics(result, document));

    const hCount = result.hallucination?.findings?.length ?? 0;
    const sCount = result.security?.findings?.length ?? 0;

    if (result.grade === "BLOCK") {
      vscode.window.showErrorMessage(
        `runlit BLOCK — ${result.score}/100. ${hCount} hallucinated API(s), ${sCount} security issue(s).`
      );
    } else if (result.grade === "WARN" || result.score < threshold()) {
      const detail =
        hCount + sCount > 0
          ? `${hCount} hallucinated API(s), ${sCount} security issue(s).`
          : "";
      vscode.window.showWarningMessage(
        `runlit WARN — ${result.score}/100. ${detail}`
      );
    } else {
      vscode.window.showInformationMessage(
        `runlit PASS — ${result.score}/100 ✓`
      );
    }
  } catch (err: unknown) {
    statusBar.text = "$(circle-slash) runlit";
    vscode.window.showErrorMessage(
      `runlit: ${err instanceof Error ? err.message : String(err)}`
    );
  }
}

// ── Sidebar TreeView ──────────────────────────────────────────────────────────

type FindingNode =
  | { kind: "status"; label: string; icon: string }
  | { kind: "score"; score: number; grade: string; evalId: string }
  | { kind: "section"; label: string; count: number }
  | { kind: "finding"; findingId: string; evalId: string; label: string; detail: string; uri: vscode.Uri; line: number; dismissed: boolean };

class RunlitFindingsProvider implements vscode.TreeDataProvider<FindingNode> {
  private _onDidChangeTreeData = new vscode.EventEmitter<void>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  refresh() { this._onDidChangeTreeData.fire(); }

  getTreeItem(node: FindingNode): vscode.TreeItem {
    if (node.kind === "status") {
      const item = new vscode.TreeItem(node.label);
      item.iconPath = new vscode.ThemeIcon(node.icon);
      item.contextValue = "status";
      return item;
    }
    if (node.kind === "score") {
      const icon = node.grade === "PASS" ? "check" : node.grade === "WARN" ? "warning" : "error";
      const item = new vscode.TreeItem(
        `${node.grade} · ${node.score}/100`,
        vscode.TreeItemCollapsibleState.None
      );
      item.iconPath = new vscode.ThemeIcon(icon);
      item.description = `eval ${node.evalId.slice(0, 8)}`;
      item.contextValue = "score";
      return item;
    }
    if (node.kind === "section") {
      const item = new vscode.TreeItem(
        `${node.label} (${node.count})`,
        node.count > 0
          ? vscode.TreeItemCollapsibleState.Expanded
          : vscode.TreeItemCollapsibleState.None
      );
      item.iconPath = new vscode.ThemeIcon(
        node.label === "Hallucination" ? "symbol-method" : "shield"
      );
      return item;
    }
    // finding node
    const item = new vscode.TreeItem(node.label, vscode.TreeItemCollapsibleState.None);
    item.description = node.detail;
    item.iconPath = new vscode.ThemeIcon(node.dismissed ? "check" : "circle-filled");
    item.tooltip = node.dismissed ? "Dismissed" : node.label;
    item.command = {
      command: "vscode.open",
      title: "Go to finding",
      arguments: [node.uri, { selection: new vscode.Range(node.line, 0, node.line, 0) }],
    };
    if (!node.dismissed) {
      item.contextValue = "finding";
    }
    return item;
  }

  getChildren(node?: FindingNode): FindingNode[] {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
      return [{ kind: "status", label: "Open a file to evaluate", icon: "info" }];
    }

    const state = evalStateMap.get(editor.document.uri.toString());
    if (!state) {
      return [{ kind: "status", label: "Run 'Evaluate current file' to start", icon: "play" }];
    }

    if (!node) {
      // Root level: score row + two sections
      return [
        { kind: "section", label: "Hallucination", count: state.hallucinationFindings.length },
        { kind: "section", label: "Security", count: state.securityFindings.length },
      ];
    }

    if (node.kind === "section") {
      const state = evalStateMap.get(editor.document.uri.toString());
      if (!state) return [];
      const findings = node.label === "Hallucination"
        ? state.hallucinationFindings
        : state.securityFindings;
      return findings.map(f => ({
        kind: "finding" as const,
        findingId: f.findingId,
        evalId: state.evalId,
        label: f.label,
        detail: `line ${f.line + 1}`,
        uri: editor.document.uri,
        line: f.line,
        dismissed: dismissedFindings.has(f.findingId),
      }));
    }

    return [];
  }
}

// ── Extension lifecycle ───────────────────────────────────────────────────────

export function activate(context: vscode.ExtensionContext) {
  // Load persisted dismissed findings from workspace state
  dismissedFindings = new Set(
    context.workspaceState.get<string[]>(DISMISSED_KEY, [])
  );

  const statusBar = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Left,
    100
  );
  statusBar.command = "runlit.evalFile";
  statusBar.tooltip = "runlit — click to eval current file";

  // Register CodeLens provider for all languages
  const codeLensProvider = new RunlitCodeLensProvider();
  const codeLensDisposable = vscode.languages.registerCodeLensProvider(
    { scheme: "file" },
    codeLensProvider
  );

  // Register sidebar findings panel
  const findingsProvider = new RunlitFindingsProvider();
  const findingsTree = vscode.window.createTreeView("runlit.findings", {
    treeDataProvider: findingsProvider,
    showCollapseAll: false,
  });
  // Refresh sidebar whenever CodeLens refreshes (after eval or dismiss)
  codeLensEventEmitter.event(() => findingsProvider.refresh());
  // Also refresh when the active editor changes
  vscode.window.onDidChangeActiveTextEditor(() => findingsProvider.refresh(), null, context.subscriptions);

  context.subscriptions.push(statusBar, diagnosticCollection, codeLensDisposable, findingsTree);

  // runlit.evalFile
  context.subscriptions.push(
    vscode.commands.registerCommand("runlit.evalFile", async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) return;
      const filename =
        editor.document.fileName.split(/[\\/]/).pop() ?? "file";
      const diff =
        (await gitDiffForFile(editor.document.uri)) ??
        asDiff(editor.document.getText(), filename);
      await runEval(editor.document, diff, statusBar, context.secrets);
    }),

    // runlit.evalSelection
    vscode.commands.registerCommand("runlit.evalSelection", async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) return;
      const selected = editor.document.getText(editor.selection);
      if (!selected.trim()) {
        vscode.window.showWarningMessage("runlit: select some code first");
        return;
      }
      const filename =
        editor.document.fileName.split(/[\\/]/).pop() ?? "code";
      await runEval(
        editor.document,
        asDiff(selected, filename),
        statusBar,
        context.secrets
      );
    }),

    // runlit.confirmFinding — thumbs_up feedback
    vscode.commands.registerCommand(
      "runlit.confirmFinding",
      async (evalId: string, findingId: string, uri: vscode.Uri) => {
        const token = await apiToken(context.secrets);
        if (!token) {
          vscode.window.showWarningMessage("runlit: API token not set");
          return;
        }
        const ok = await postFeedback(evalId, "thumbs_up", findingId, token);
        if (ok) {
          vscode.window.showInformationMessage(
            "runlit: finding confirmed ✓ — thank you for the feedback"
          );
        } else {
          vscode.window.showWarningMessage("runlit: failed to send feedback");
        }
      }
    ),

    // runlit.dismissFinding — finding_dismissed feedback + suppress for session
    vscode.commands.registerCommand(
      "runlit.dismissFinding",
      async (evalId: string, findingId: string, uri: vscode.Uri) => {
        const token = await apiToken(context.secrets);
        if (!token) {
          vscode.window.showWarningMessage("runlit: API token not set");
          return;
        }
        // Suppress immediately (optimistic)
        dismissedFindings.add(findingId);
        await context.workspaceState.update(
          DISMISSED_KEY,
          Array.from(dismissedFindings)
        );
        codeLensEventEmitter.fire();

        const ok = await postFeedback(evalId, "finding_dismissed", findingId, token);
        if (!ok) {
          // Revert on failure
          dismissedFindings.delete(findingId);
          await context.workspaceState.update(
            DISMISSED_KEY,
            Array.from(dismissedFindings)
          );
          codeLensEventEmitter.fire();
          vscode.window.showWarningMessage("runlit: failed to send feedback");
        }
      }
    ),

    // runlit.setApiKey — prompt and store token in secrets
    vscode.commands.registerCommand("runlit.setApiKey", async () => {
      const token = await vscode.window.showInputBox({
        prompt: "Paste your runlit API token",
        password: true,
        placeHolder: "rl_live_...",
        ignoreFocusOut: true,
      });
      if (token !== undefined) {
        await context.secrets.store("runlit.apiToken", token);
        vscode.window.showInformationMessage("runlit: API key saved.");
      }
    }),

    // runlit.clearDiagnostics
    vscode.commands.registerCommand("runlit.clearDiagnostics", () => {
      diagnosticCollection.clear();
      evalStateMap.clear();
      codeLensEventEmitter.fire();
      statusBar.text = "$(circle-outline) runlit";
      statusBar.backgroundColor = undefined;
    }),

    vscode.window.onDidChangeActiveTextEditor((editor) => {
      if (editor) statusBar.show();
    }),

    vscode.workspace.onDidCloseTextDocument((doc) => {
      diagnosticCollection.delete(doc.uri);
      evalStateMap.delete(doc.uri.toString());
      codeLensEventEmitter.fire();
    })
  );

  if (vscode.window.activeTextEditor) statusBar.show();
}

export function deactivate() {
  diagnosticCollection.dispose();
  codeLensEventEmitter.dispose();
}
