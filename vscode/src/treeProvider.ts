import * as vscode from 'vscode';

export interface FindingItem {
    label: string;
    description?: string;
    tooltip?: string;
    file: string;
    line: number;
    severity: string;
    message: string;
}

export class FindingsProvider implements vscode.TreeDataProvider<FindingItem> {
    private _onDidChangeTreeData = new vscode.EventEmitter<FindingItem | undefined | void>();
    readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

    private findings: FindingItem[] = [];

    refresh(items: FindingItem[]) {
        this.findings = items;
        this._onDidChangeTreeData.fire();
    }

    getTreeItem(element: FindingItem): vscode.TreeItem {
        const treeItem = new vscode.TreeItem(
            element.label,
            vscode.TreeItemCollapsibleState.None
        );
        treeItem.description = element.description;
        treeItem.tooltip = element.tooltip;
        treeItem.command = {
            command: 'apex.goToFinding',
            title: 'Go to Finding',
            arguments: [element],
        };

        const colorMap: Record<string, string> = {
            CRITICAL: 'red',
            HIGH: 'orange',
            MEDIUM: 'yellow',
            LOW: 'blue',
            INFO: 'grey',
        };
        treeItem.iconPath = new vscode.ThemeIcon(
            'warning',
            new vscode.ThemeColor(colorMap[element.severity] || 'foreground')
        );

        return treeItem;
    }

    getChildren(): FindingItem[] {
        return this.findings;
    }
}
