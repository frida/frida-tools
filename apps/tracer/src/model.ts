export enum TraceSpecScope {
    Function = "function",
    RelativeFunction = "relative-function",
    Imports = "imports",
    Module = "module",
    ObjcMethod = "objc-method",
    SwiftFunc = "swift-func",
    JavaMethod = "java-method",
    DebugSymbol = "debug-symbol",
}

export interface Handler {
    id: HandlerId;
    scope: ScopeId;
    display_name: string;
}
export type HandlerId = number;
export type ScopeId = string;

export type StagedItem = [id: StagedItemId, scope: ScopeName, member: MemberName];
export type StagedItemId = number;

export type ScopeName = string;
export type MemberName = string | [string, string];

export type Event = [targetId: HandlerId, timestamp: number, threadId: number, depth: number, message: string, style: string[]];
