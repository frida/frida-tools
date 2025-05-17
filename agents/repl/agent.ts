class REPL {
    #quickCommands = new Map();

    registerQuickCommand(name: string, handler: QuickCommandHandler) {
        this.#quickCommands.set(name, handler);
    }

    unregisterQuickCommand(name: string) {
        this.#quickCommands.delete(name);
    }

    _invokeQuickCommand(tokens: string[]): any {
        const name = tokens[0];
        const handler = this.#quickCommands.get(name);
        if (handler !== undefined) {
            const { minArity, onInvoke } = handler;
            if (tokens.length - 1 < minArity) {
                throw Error(`${name} needs at least ${minArity} arg${(minArity === 1) ? "" : "s"}`);
            }
            return onInvoke(...tokens.slice(1));
        } else {
            throw Error(`Unknown command ${name}`);
        }
    }
}

const repl = new REPL();

const replScriptGlobals = globalThis as unknown as ReplScriptGlobals;
replScriptGlobals.cm = null;
replScriptGlobals.cs = {};
replScriptGlobals.REPL = repl;

interface ReplScriptGlobals {
    cm: CModule | null;
    cs: {
        [name: string]: NativePointerValue;
    };
    REPL: REPL;
}

interface QuickCommandHandler {
    minArity: number;
    onInvoke: (...args: string[]) => any;
}

const rpcExports: RpcExports = {
    fridaEvaluateExpression(expression: string) {
        return evaluate(() => globalThis.eval(expression));
    },
    fridaEvaluateQuickCommand(tokens: string[]) {
        return evaluate(() => repl._invokeQuickCommand(tokens));
    },
    fridaLoadCmodule(code: string | null, toolchain: CModuleToolchain) {
        const cs = replScriptGlobals.cs;

        if (cs._frida_log === undefined)
            cs._frida_log = new NativeCallback(onLog, "void", ["pointer"]);

        let codeToLoad: string | ArrayBuffer | null = code;
        if (code === null) {
            recv("frida:cmodule-payload", (message, data) => {
                codeToLoad = data;
            });
        }

        replScriptGlobals.cm = new CModule(codeToLoad!, cs, { toolchain });
    },
};

function evaluate(func: () => any) {
    try {
        const result = func();
        if (result instanceof ArrayBuffer) {
            return result;
        } else {
            const type = (result === null) ? "null" : typeof result;
            return [type, result];
        }
    } catch (exception) {
        const e = exception as Error;
        return ["error", {
            name: e.name,
            message: e.message,
            stack: e.stack
        }];
    }
}

Object.defineProperty(rpc, "exports", {
    get() {
        return rpcExports;
    },
    set(value) {
        for (const [k, v] of Object.entries(value)) {
            rpcExports[k] = v as AnyFunction;
        }
    }
});

function onLog(messagePtr: NativePointer) {
    const message = messagePtr.readUtf8String();
    console.log(message);
}
