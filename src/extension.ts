import * as vscode from "vscode";
import * as https from "https";
import * as http from "http";
import * as url from "url";

// ── Types — POST /v1/eval (lightweight scores) ───────────────────────────────

interface PostSignalResult {
  score: number;
  model?: string;
  latency_ms?: number;
}

interface PostEvalResult {
  eval_id: string;
  score: number;
  grade: "PASS" | "WARN" | "BLOCK";
  hallucination: PostSignalResult;
  intent: PostSignalResult;
  security: PostSignalResult;
  compliance: PostSignalResult;
  latency_ms: number;
}

// ── Types — GET /v1/evals/{id} (detailed findings) ───────────────────────────

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
  snippet: string;
  source: string;
}

interface ComplianceFinding {
  rule_id: string;
  pack: string;
  file: string;
  line: number;
  message: string;
  control: string;
  severity: string;
  remediation: string;
}

interface EvalDetailFindings {
  hallucination?: {
    score: number;
    findings: HallucinatedAPI[];
    model: string;
    latency_ms: number;
    input_tokens: number;
    output_tokens: number;
    reasoning: string;
  };
  intent?: {
    score: number;
    code_summary: string;
    stated_intent: string;
    mismatches: string[];
    model: string;
    latency_ms: number;
    input_tokens: number;
    output_tokens: number;
    reasoning: string;
  };
  security?: {
    score: number;
    findings: SecurityFinding[];
    model: string;
    latency_ms: number;
    input_tokens: number;
    output_tokens: number;
    reasoning: string;
  };
  compliance?: {
    score: number;
    findings: ComplianceFinding[];
    packs_evaluated: string[];
    latency_ms: number;
    input_tokens: number;
    output_tokens: number;
    reasoning: string;
  };
}

interface EvalDetail {
  id: string;
  score: number;
  grade: string;
  hallucination_score: number;
  intent_score: number;
  security_score: number;
  compliance_score: number;
  latency_ms: number;
  findings?: EvalDetailFindings;
}

// Stored per URI after an eval completes — used by the CodeLens provider.
interface EvalState {
  evalId: string;
  hallucinationFindings: Array<{ findingId: string; line: number; label: string }>;
  securityFindings: Array<{ findingId: string; line: number; label: string }>;
  complianceFindings: Array<{ findingId: string; line: number; label: string }>;
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

function httpRequest<T>(
  endpoint: string,
  method: string,
  token: string,
  body?: unknown
): Promise<T> {
  return new Promise((resolve, reject) => {
    const parsed = url.parse(endpoint);
    const payload = body ? JSON.stringify(body) : undefined;
    const headers: Record<string, string | number> = {
      Authorization: `Bearer ${token}`,
    };
    if (payload) {
      headers["Content-Type"] = "application/json";
      headers["Content-Length"] = Buffer.byteLength(payload);
    }
    const options: http.RequestOptions = {
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === "https:" ? 443 : 80),
      path: parsed.path,
      method,
      headers,
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
    if (payload) req.write(payload);
    req.end();
  });
}

function postEval(
  endpoint: string,
  body: unknown,
  token: string
): Promise<PostEvalResult> {
  return httpRequest<PostEvalResult>(endpoint, "POST", token, body);
}

/** GET /v1/evals/{evalId} — fetch detailed findings after eval completes. */
async function getEvalDetail(
  evalId: string,
  token: string
): Promise<EvalDetail | null> {
  const base = apiUrl().replace(/\/$/, "");
  // The eval is persisted async — wait briefly for the DB write to complete.
  await new Promise((r) => setTimeout(r, 800));
  try {
    return await httpRequest<EvalDetail>(
      `${base}/v1/evals/${encodeURIComponent(evalId)}`,
      "GET",
      token
    );
  } catch {
    return null;
  }
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

// ── Git helpers ───────────────────────────────────────────────────────────────

function getGitAPI(): { repositories: any[] } | null {
  const gitExt = vscode.extensions.getExtension("vscode.git");
  if (!gitExt) return null;
  const git = gitExt.exports.getAPI(1);
  if (!git || git.repositories.length === 0) return null;
  return git;
}

/** Extract "owner/repo" from the first git remote URL. */
function getRepoSlug(): string | undefined {
  try {
    const git = getGitAPI();
    if (!git) return undefined;
    const remotes = git.repositories[0]?.state?.remotes;
    if (!remotes || remotes.length === 0) return undefined;
    const remote = remotes.find((r: any) => r.name === "origin") ?? remotes[0];
    const fetchUrl: string | undefined = remote.fetchUrl ?? remote.pushUrl;
    if (!fetchUrl) return undefined;
    // Match SSH (git@github.com:owner/repo.git) or HTTPS (https://github.com/owner/repo.git)
    const match = fetchUrl.match(/[/:]([^/:]+\/[^/.]+?)(?:\.git)?$/);
    return match?.[1];
  } catch {
    return undefined;
  }
}

// ── .runlit.yml reader ────────────────────────────────────────────────────────

async function readRunlitYml(): Promise<Record<string, unknown> | undefined> {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders || folders.length === 0) return undefined;
  const ymlUri = vscode.Uri.joinPath(folders[0].uri, ".runlit.yml");
  try {
    const bytes = await vscode.workspace.fs.readFile(ymlUri);
    const text = Buffer.from(bytes).toString("utf-8");
    // Minimal YAML key: value parser — enough for flat config like
    //   compliance_packs: [pci-dss, soc2]
    //   block_on_compliance: true
    const obj: Record<string, unknown> = {};
    for (const line of text.split("\n")) {
      const m = line.match(/^\s*([a-z_]+)\s*:\s*(.+)/);
      if (!m) continue;
      const val = m[2].trim();
      if (val.startsWith("[") && val.endsWith("]")) {
        obj[m[1]] = val.slice(1, -1).split(",").map(s => s.trim().replace(/^["']|["']$/g, ""));
      } else if (val === "true") {
        obj[m[1]] = true;
      } else if (val === "false") {
        obj[m[1]] = false;
      } else if (/^\d+$/.test(val)) {
        obj[m[1]] = parseInt(val, 10);
      } else {
        obj[m[1]] = val.replace(/^["']|["']$/g, "");
      }
    }
    return Object.keys(obj).length > 0 ? obj : undefined;
  } catch {
    return undefined;
  }
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
    const git = getGitAPI();
    if (!git) return null;
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
  findings: EvalDetailFindings | undefined,
  document: vscode.TextDocument
): vscode.Diagnostic[] {
  const diags: vscode.Diagnostic[] = [];

  for (const f of findings?.hallucination?.findings ?? []) {
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

  for (const f of findings?.security?.findings ?? []) {
    const lineIdx = Math.min(
      Math.max(0, (f.line || 1) - 1),
      document.lineCount - 1
    );
    const sev = ["critical", "high"].includes((f.severity || "").toLowerCase())
      ? vscode.DiagnosticSeverity.Error
      : vscode.DiagnosticSeverity.Warning;
    const diag = new vscode.Diagnostic(
      document.lineAt(lineIdx).range,
      `Security [${(f.severity || "MEDIUM").toUpperCase()}]: ${f.message}${
        f.cwe ? ` (${f.cwe})` : ""
      }`,
      sev
    );
    diag.source = `runlit-security (${f.source || "llm"})`;
    diag.code = {
      value: f.rule_id || "security",
      target: vscode.Uri.parse("https://docs.runlit.dev/signals/security"),
    };
    diags.push(diag);
  }

  for (const f of findings?.compliance?.findings ?? []) {
    const lineIdx = Math.min(
      Math.max(0, (f.line || 1) - 1),
      document.lineCount - 1
    );
    const sev = ["critical", "high"].includes((f.severity || "").toLowerCase())
      ? vscode.DiagnosticSeverity.Error
      : vscode.DiagnosticSeverity.Warning;
    const diag = new vscode.Diagnostic(
      document.lineAt(lineIdx).range,
      `Compliance [${f.pack}] ${f.control}: ${f.message}${
        f.remediation ? ` — fix: ${f.remediation}` : ""
      }`,
      sev
    );
    diag.source = "runlit-compliance";
    diag.code = {
      value: f.rule_id || "compliance",
      target: vscode.Uri.parse("https://docs.runlit.dev/signals/compliance"),
    };
    diags.push(diag);
  }

  // Intent mismatches are file-level (no specific line)
  for (const m of findings?.intent?.mismatches ?? []) {
    const diag = new vscode.Diagnostic(
      document.lineAt(0).range,
      `Intent mismatch: ${m}`,
      vscode.DiagnosticSeverity.Warning
    );
    diag.source = "runlit-intent";
    diag.code = {
      value: "intent-mismatch",
      target: vscode.Uri.parse("https://docs.runlit.dev/signals/intent"),
    };
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
    const all = [...state.hallucinationFindings, ...state.securityFindings, ...state.complianceFindings];

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
    // Gather optional context for richer eval
    const repo = getRepoSlug();
    const runlitConfig = await readRunlitYml();

    // Phase 1: POST /v1/eval — get scores immediately
    const evalBody: Record<string, unknown> = { diff };
    if (repo) evalBody.repo = repo;
    if (runlitConfig) evalBody.config = runlitConfig;

    const result = await postEval(
      `${apiUrl()}/v1/eval`,
      evalBody,
      token
    );

    statusBar.text = gradeIcon(result.grade, result.score);
    statusBar.tooltip = [
      `runlit — ${result.score}/100 (${result.grade})`,
      `Hallucination: ${Math.round((result.hallucination?.score ?? 1) * 100)}`,
      `Intent: ${Math.round((result.intent?.score ?? 1) * 100)}`,
      `Security: ${Math.round((result.security?.score ?? 1) * 100)}`,
      `Compliance: ${Math.round((result.compliance?.score ?? 1) * 100)}`,
      `Latency: ${result.latency_ms}ms`,
      `Eval ID: ${result.eval_id}`,
      ``,
      `View in dashboard →`,
    ].join("\n");
    statusBar.backgroundColor =
      result.grade === "BLOCK"
        ? new vscode.ThemeColor("statusBarItem.errorBackground")
        : result.grade === "WARN"
        ? new vscode.ThemeColor("statusBarItem.warningBackground")
        : undefined;

    // Phase 2: GET /v1/evals/{id} — fetch detailed findings for diagnostics
    const detail = await getEvalDetail(result.eval_id, token);
    const findings = detail?.findings;

    // Build CodeLens state for this document
    const state: EvalState = {
      evalId: result.eval_id,
      hallucinationFindings: (findings?.hallucination?.findings ?? []).map(
        (f, i) => ({
          findingId: `hal-${result.eval_id}-${i}`,
          line: f.line || 1,
          label: `${f.api_ref}: ${f.reason}`,
        })
      ),
      securityFindings: (findings?.security?.findings ?? []).map((f, i) => ({
        findingId: `sec-${result.eval_id}-${i}`,
        line: f.line || 1,
        label: f.message,
      })),
      complianceFindings: (findings?.compliance?.findings ?? []).map(
        (f, i) => ({
          findingId: `cmp-${result.eval_id}-${i}`,
          line: f.line || 1,
          label: `[${f.pack}] ${f.control}: ${f.message}`,
        })
      ),
    };
    evalStateMap.set(document.uri.toString(), state);
    codeLensEventEmitter.fire();

    diagnosticCollection.set(document.uri, toDiagnostics(findings, document));

    const hCount = findings?.hallucination?.findings?.length ?? 0;
    const sCount = findings?.security?.findings?.length ?? 0;
    const cCount = findings?.compliance?.findings?.length ?? 0;
    const iCount = findings?.intent?.mismatches?.length ?? 0;
    const totalFindings = hCount + sCount + cCount + iCount;

    if (result.grade === "BLOCK") {
      const parts = [];
      if (hCount > 0) parts.push(`${hCount} hallucinated API(s)`);
      if (sCount > 0) parts.push(`${sCount} security issue(s)`);
      if (cCount > 0) parts.push(`${cCount} compliance violation(s)`);
      if (iCount > 0) parts.push(`${iCount} intent mismatch(es)`);
      const action = await vscode.window.showErrorMessage(
        `runlit BLOCK — ${result.score}/100. ${parts.join(", ") || "Score below threshold"}.`,
        "View in Dashboard"
      );
      if (action === "View in Dashboard") {
        vscode.env.openExternal(
          vscode.Uri.parse(`https://app.runlit.dev/evals/${result.eval_id}`)
        );
      }
    } else if (result.grade === "WARN" || result.score < threshold()) {
      const parts = [];
      if (hCount > 0) parts.push(`${hCount} hallucinated API(s)`);
      if (sCount > 0) parts.push(`${sCount} security issue(s)`);
      if (cCount > 0) parts.push(`${cCount} compliance violation(s)`);
      if (iCount > 0) parts.push(`${iCount} intent mismatch(es)`);
      const action = await vscode.window.showWarningMessage(
        `runlit WARN — ${result.score}/100. ${parts.join(", ") || "Score below threshold"}.`,
        "View in Dashboard"
      );
      if (action === "View in Dashboard") {
        vscode.env.openExternal(
          vscode.Uri.parse(`https://app.runlit.dev/evals/${result.eval_id}`)
        );
      }
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
      const iconMap: Record<string, string> = {
        Hallucination: "symbol-method",
        Security: "shield",
        Compliance: "law",
        Intent: "git-compare",
      };
      item.iconPath = new vscode.ThemeIcon(iconMap[node.label] ?? "info");
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
      return [
        { kind: "section", label: "Hallucination", count: state.hallucinationFindings.length },
        { kind: "section", label: "Security", count: state.securityFindings.length },
        { kind: "section", label: "Compliance", count: state.complianceFindings.length },
      ];
    }

    if (node.kind === "section") {
      const state = evalStateMap.get(editor.document.uri.toString());
      if (!state) return [];
      let findings: Array<{ findingId: string; line: number; label: string }>;
      switch (node.label) {
        case "Hallucination":
          findings = state.hallucinationFindings;
          break;
        case "Security":
          findings = state.securityFindings;
          break;
        case "Compliance":
          findings = state.complianceFindings;
          break;
        default:
          findings = [];
      }
      return findings.map(f => ({
        kind: "finding" as const,
        findingId: f.findingId,
        evalId: state.evalId,
        label: f.label,
        detail: `line ${f.line}`,
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

    // runlit.openInDashboard — open the latest eval in the dashboard
    vscode.commands.registerCommand("runlit.openInDashboard", () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) return;
      const state = evalStateMap.get(editor.document.uri.toString());
      if (!state) {
        vscode.window.showWarningMessage("runlit: no eval result — run an eval first");
        return;
      }
      vscode.env.openExternal(
        vscode.Uri.parse(`https://app.runlit.dev/evals/${state.evalId}`)
      );
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
