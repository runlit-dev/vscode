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

// ── Config helpers ─────────────────────────────────────────────────────────────

function cfg() {
  return vscode.workspace.getConfiguration("runlit");
}
function apiToken(): string {
  return cfg().get<string>("apiToken", "");
}
function apiUrl(): string {
  return cfg().get<string>("apiUrl", "https://api.runlit.dev");
}
function threshold(): number {
  return cfg().get<number>("threshold", 80);
}

// ── HTTP helper ───────────────────────────────────────────────────────────────

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

// ── Core eval ─────────────────────────────────────────────────────────────────

async function runEval(
  document: vscode.TextDocument,
  diff: string,
  statusBar: vscode.StatusBarItem
): Promise<void> {
  const token = apiToken();
  if (!token) {
    const action = await vscode.window.showWarningMessage(
      "runlit: API token not set. Go to Settings → runlit.apiToken",
      "Open Settings"
    );
    if (action === "Open Settings") {
      vscode.commands.executeCommand(
        "workbench.action.openSettings",
        "runlit.apiToken"
      );
    }
    return;
  }

  statusBar.text = "$(sync~spin) runlit";
  statusBar.backgroundColor = undefined;
  statusBar.show();

  try {
    const result = await postEval(
      `${apiUrl()}/v1/eval`,
      {
        diff,
        config: {
          hallucination_enabled: true,
          intent_enabled: false,
          security_enabled: true,
          compliance_enabled: false,
        },
      },
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

// ── Extension lifecycle ───────────────────────────────────────────────────────

export function activate(context: vscode.ExtensionContext) {
  const statusBar = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Left,
    100
  );
  statusBar.command = "runlit.evalFile";
  statusBar.tooltip = "runlit — click to eval current file";
  context.subscriptions.push(statusBar, diagnosticCollection);

  context.subscriptions.push(
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
        statusBar
      );
    }),

    vscode.commands.registerCommand("runlit.evalFile", async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) return;
      const filename =
        editor.document.fileName.split(/[\\/]/).pop() ?? "file";
      const diff =
        (await gitDiffForFile(editor.document.uri)) ??
        asDiff(editor.document.getText(), filename);
      await runEval(editor.document, diff, statusBar);
    }),

    vscode.commands.registerCommand("runlit.clearDiagnostics", () => {
      diagnosticCollection.clear();
      statusBar.text = "$(circle-outline) runlit";
      statusBar.backgroundColor = undefined;
    }),

    vscode.window.onDidChangeActiveTextEditor((editor) => {
      if (editor) statusBar.show();
    }),

    vscode.workspace.onDidCloseTextDocument((doc) => {
      diagnosticCollection.delete(doc.uri);
    })
  );

  if (vscode.window.activeTextEditor) statusBar.show();
}

export function deactivate() {
  diagnosticCollection.dispose();
}
