# runlit VS Code Extension

[![license: MIT](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
[![VS Code Marketplace](https://img.shields.io/visual-studio-marketplace/v/runlit.runlit?style=flat-square)](https://marketplace.visualstudio.com/items?itemName=runlit.runlit)

Real-time eval signal in your editor. Works in VS Code and Cursor.

## What it does

- **Inline warnings** on AI-generated code that scores below the warn threshold
- **Hallucination detection** — flags fabricated API calls with the correct alternative
- **Security findings** — inline diagnostics for security issues found by Opengrep + Gitleaks
- **CodeLens feedback** — "✓ Confirm" / "✗ Dismiss" actions above each finding
- **Status bar** — shows current file eval score (click to re-eval)
- **Command palette** — `runlit: Evaluate current file`, `runlit: Evaluate selection`

## Install

Search `runlit` in the VS Code Extensions panel, or:

```bash
code --install-extension runlit.runlit
```

[Install from Marketplace →](https://marketplace.visualstudio.com/items?itemName=runlit.runlit)

## Setup

1. Install the extension
2. Open Command Palette → `runlit: Set API Key`
3. Paste your API key from [app.runlit.dev](https://app.runlit.dev)

## CodeLens feedback

After an eval, each finding shows two inline actions:

```
line 42: stripe.PaymentMethod.attach_async(...)
         [✓ Confirm] [✗ Dismiss]
```

- **Confirm** → sends `thumbs_up` feedback (confidence weight 1.0) to the training pipeline
- **Dismiss** → sends `finding_dismissed` feedback (weight 0.8) and suppresses the finding immediately — no wait for API response (optimistic UI)

Dismissed finding IDs are persisted to VS Code `workspaceState` and survive editor restarts. They are cleared when you run a new eval on the file.

## Configuration

```json
// settings.json
{
  "runlit.apiToken": "",         // or set via command palette
  "runlit.apiUrl": "https://api.runlit.dev",
  "runlit.threshold": 80
}
```

## Commands

| Command | Description |
|---|---|
| `runlit.evalFile` | Evaluate current file (git diff or full content) |
| `runlit.evalSelection` | Evaluate selected code |
| `runlit.clearDiagnostics` | Clear all runlit diagnostics from the file |
| `runlit.confirmFinding` | Mark a specific finding as correct (CodeLens) |
| `runlit.dismissFinding` | Dismiss a specific finding (CodeLens) |

## Stack

- VS Code Extension API (compatible with Cursor)
- TypeScript
- Uses `POST /v1/eval` and `POST /v1/evals/{id}/feedback` from the runlit API
- Published to VS Code Marketplace + Cursor Marketplace

## Contributing

Issues and PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).
