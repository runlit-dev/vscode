# runlit VS Code Extension

[![license: MIT](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
[![VS Code Marketplace](https://img.shields.io/visual-studio-marketplace/v/runlit.runlit?style=flat-square)](https://marketplace.visualstudio.com/items?itemName=runlit.runlit)

Real-time eval signal in your editor. Works in VS Code and Cursor.

## What it does

- **Inline warnings** on AI-generated code that scores below the warn threshold
- **Hallucination detection** — flags fabricated API calls with the correct alternative
- **On-save eval** — optionally run eval when you save a file
- **Status bar** — shows current file eval score
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

## Configuration

```json
// settings.json
{
  "runlit.apiKey": "",              // or set via command palette
  "runlit.evalOnSave": true,        // run eval when file is saved
  "runlit.blockThreshold": 50,
  "runlit.warnThreshold": 70,
  "runlit.signals": ["hallucination", "intent", "security"]
}
```

## Stack

- VS Code Extension API (compatible with Cursor)
- TypeScript
- Generated TypeScript client from `core/contracts/openapi/api.yaml`
- Published to VS Code Marketplace + Cursor Marketplace

## Contributing

Issues and PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).
