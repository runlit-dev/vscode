import * as vscode from "vscode";

export function activate(context: vscode.ExtensionContext) {
  console.log("runlit extension activated");

  const evalSelection = vscode.commands.registerCommand(
    "runlit.evalSelection",
    async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) return;
      const selection = editor.document.getText(editor.selection);
      if (!selection) {
        vscode.window.showWarningMessage("runlit: no code selected");
        return;
      }
      vscode.window.showInformationMessage("runlit: eval coming soon");
    }
  );

  const evalFile = vscode.commands.registerCommand(
    "runlit.evalFile",
    async () => {
      vscode.window.showInformationMessage("runlit: file eval coming soon");
    }
  );

  context.subscriptions.push(evalSelection, evalFile);
}

export function deactivate() {}
