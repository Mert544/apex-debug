import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as path from 'path';

import { FindingsProvider, FindingItem } from './treeProvider';

let outputChannel: vscode.OutputChannel;
let findingsProvider: FindingsProvider;

function getConfig() {
    const cfg = vscode.workspace.getConfiguration('apex');
    return {
        pythonPath: cfg.get<string>('pythonPath', 'python'),
        minSeverity: cfg.get<string>('minSeverity', 'low'),
        categories: cfg.get<string[]>('categories', ['security', 'correctness', 'performance', 'style']),
    };
}

function runApex(args: string[], cwd: string): Promise<string> {
    return new Promise((resolve, reject) => {
        const { pythonPath } = getConfig();
        const cmd = `${pythonPath} -m apex_debug.cli.app ${args.join(' ')}`;
        cp.exec(cmd, { cwd, timeout: 120000 }, (err, stdout, stderr) => {
            if (err && !stdout) {
                reject(stderr || err.message);
                return;
            }
            resolve(stdout || stderr);
        });
    });
}

function runApexJson(args: string[], cwd: string): Promise<any[]> {
    return new Promise((resolve, reject) => {
        const { pythonPath } = getConfig();
        const cmd = `${pythonPath} -m apex_debug.cli.app ${args.join(' ')}`;
        cp.exec(cmd, { cwd, timeout: 120000 }, (err, stdout, stderr) => {
            if (err && !stdout) {
                reject(stderr || err.message);
                return;
            }
            try {
                const lines = (stdout || stderr).trim().split('\n');
                const jsonLine = lines.find(l => l.startsWith('[')) || lines[lines.length - 1];
                resolve(JSON.parse(jsonLine));
            } catch {
                resolve([]);
            }
        });
    });
}

export function activate(context: vscode.ExtensionContext) {
    outputChannel = vscode.window.createOutputChannel('Apex Debug');
    findingsProvider = new FindingsProvider();

    vscode.window.registerTreeDataProvider('apexFindings', findingsProvider);

    const analyzeFile = vscode.commands.registerCommand('apex.analyzeFile', async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showWarningMessage('Apex: No active file.');
            return;
        }
        const filePath = editor.document.uri.fsPath;
        const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || path.dirname(filePath);

        outputChannel.clear();
        outputChannel.show();
        outputChannel.appendLine(`[Apex] Analyzing ${filePath}...`);

        try {
            const { minSeverity, categories } = getConfig();
            const catFilter = categories.length === 4 ? '' : ` --category=${categories[0]}`;
            const output = await runApexJson(
                ['analyze', filePath, '--min-severity', minSeverity, catFilter, '--json'],
                workspaceRoot
            );

            const items: FindingItem[] = output.map((f: any) => ({
                label: `${f.severity} — ${f.title}`,
                description: `${path.basename(f.file)}:${f.line}`,
                tooltip: f.message,
                file: f.file,
                line: f.line - 1,
                severity: f.severity,
                message: f.message,
            }));

            findingsProvider.refresh(items);
            vscode.commands.executeCommand('setContext', 'apex.hasFindings', items.length > 0);

            outputChannel.appendLine(`[Apex] ${items.length} finding(s) found.`);
            if (items.length === 0) {
                vscode.window.showInformationMessage('Apex: No issues found.');
            } else {
                vscode.window.showWarningMessage(`Apex: ${items.length} issue(s) found.`);
            }
        } catch (err) {
            vscode.window.showErrorMessage(`Apex analysis failed: ${err}`);
            outputChannel.appendLine(`[Apex] Error: ${err}`);
        }
    });

    const analyzeWorkspace = vscode.commands.registerCommand('apex.analyzeWorkspace', async () => {
        const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
        if (!workspaceRoot) {
            vscode.window.showErrorMessage('Apex: No workspace open.');
            return;
        }
        outputChannel.clear();
        outputChannel.show();
        outputChannel.appendLine(`[Apex] Analyzing workspace...`);

        try {
            const output = await runApex(['analyze', workspaceRoot, '--json'], workspaceRoot);
            outputChannel.appendLine(output);
            vscode.window.showInformationMessage('Apex: Workspace analysis complete.');
        } catch (err) {
            vscode.window.showErrorMessage(`Apex workspace analysis failed: ${err}`);
        }
    });

    const openShell = vscode.commands.registerCommand('apex.openShell', async () => {
        const terminal = vscode.window.createTerminal('Apex Debug Shell');
        terminal.sendText('apex-debug shell');
        terminal.show();
    });

    const showFindings = vscode.commands.registerCommand('apex.showFindings', () => {
        vscode.commands.executeCommand('apexFindings.focus');
    });

    const goToFinding = vscode.commands.registerCommand('apex.goToFinding', async (item: FindingItem) => {
        if (!item.file) return;
        const doc = await vscode.workspace.openTextDocument(item.file);
        const editor = await vscode.window.showTextDocument(doc);
        const pos = new vscode.Position(item.line, 0);
        editor.selection = new vscode.Selection(pos, pos);
        editor.revealRange(new vscode.Range(pos, pos), vscode.TextEditorRevealType.InCenter);
    });

    context.subscriptions.push(analyzeFile, analyzeWorkspace, openShell, showFindings, goToFinding);
}

export function deactivate() {}
