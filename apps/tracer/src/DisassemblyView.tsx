import "./DisassemblyView.css";
import { Handler, HandlerId } from "./model.js";
import { useR2 } from "@frida/react-use-r2";
import { hideContextMenu, Menu, MenuItem, showContextMenu, Spinner } from "@blueprintjs/core";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

export interface DisassemblyViewProps {
    target?: DisassemblyTarget;
    handlers: Handler[];
    onSelectTarget: SelectTargetRequestHandler;
    onSelectHandler: SelectHandlerRequestHandler;
    onAddInstructionHook: AddInstructionHookRequestHandler;
    onSymbolicate: SymbolicateRequestHandler;
}

export type DisassemblyTarget = FunctionTarget | InstructionTarget;

export interface FunctionTarget {
    type: "function";
    name?: string;
    address: string;
}

export interface InstructionTarget {
    type: "instruction";
    address: string;
}

export type SelectTargetRequestHandler = (target: DisassemblyTarget) => void;
export type SelectHandlerRequestHandler = (id: HandlerId) => void;
export type AddInstructionHookRequestHandler = (address: bigint) => void;
export type SymbolicateRequestHandler = (addresses: bigint[]) => Promise<string[]>;

const ADDRESS_PATTERN = /\b0x[0-9a-f]+\b/;
const MINIMUM_PAGE_SIZE = 4096;

export default function DisassemblyView({ target, handlers, onSelectTarget, onSelectHandler, onAddInstructionHook, onSymbolicate }: DisassemblyViewProps) {
    const containerRef = useRef<HTMLDivElement>(null);
    const [data, setData] = useState<DisassemblyData | null>(null);
    const seenAddressesRef = useRef(new Set<bigint>());
    const [r2Output, setR2Output] = useState<string[]>([]);
    const [isLoading, setIsLoading] = useState(false);
    const highlightedAddressAnchorRef = useRef<HTMLAnchorElement | null>(null);
    const { executeR2Command } = useR2();

    useEffect(() => {
        if (target === undefined) {
            return;
        }

        let ignore = false;
        setIsLoading(true);

        const t = target;

        async function start() {
            let result = await disassemble(t, executeR2Command);
            if (ignore) {
                return;
            }

            const addressesToResolve: bigint[] = [];
            const seenAddresses = seenAddressesRef.current;
            const { operations } = result;
            for (const match of result.html.matchAll(new RegExp(ADDRESS_PATTERN, "g"))) {
                const val = BigInt(match[0]);
                if (val < MINIMUM_PAGE_SIZE || seenAddresses.has(val) || operations.has(val)) {
                    continue;
                }
                addressesToResolve.push(val);
                seenAddresses.add(val);
            }

            if (addressesToResolve.length !== 0) {
                const names = await onSymbolicate(addressesToResolve);
                const commands = names.reduce((result, name, i) => {
                    if (!name.startsWith("0x")) {
                        const mangledName = name.replace(/\b0x/g, "").replace(/[^\w]/g, "_");
                        const addr = addressesToResolve[i];
                        result.push(`f sym.${mangledName} @ 0x${addr.toString(16)}`);
                    }
                    return result;
                }, [] as string[]);
                await executeR2Command(commands.join(";"));
                result = await disassemble(t, executeR2Command);
                if (ignore) {
                    return;
                }
            }

            setData(result);
            setIsLoading(false);
        }

        start();

        return () => {
            ignore = true;
        };
    }, [target, executeR2Command]);

    useEffect(() => {
        if (data === null) {
            setR2Output([]);
            return;
        }
        const { html, operations } = data;

        let lines: string[];
        const handlerByAddress = handlers.reduce((result, handler) => {
            const { address } = handler;
            if (address === null) {
                return result;
            }
            return result.set(BigInt(address), handler);
        }, new Map<bigint, Handler>());

        lines =
            html
                .split("<br />")
                .map(line => {
                    let address: bigint | null = null;
                    line = line.replace(ADDRESS_PATTERN, rawAddress => {
                        address = BigInt(rawAddress);
                        const handler = handlerByAddress.get(address);
                        const attrs = (handler !== undefined)
                            ? ` class="disassembly-address-has-handler" data-handler="${handler.id}"`
                            : "";
                        return `<a data-address="0x${address.toString(16)}" ${attrs}>${rawAddress}</a>`;
                    });

                    if (address !== null) {
                        const op = operations.get(address);
                        if (op !== undefined) {
                            const targetAddress = op.jump;
                            if (targetAddress !== undefined) {
                                const targetLabel = op.disasm.split("&nbsp;")[1];
                                line = line.replace(targetLabel, _ => {
                                    return `<a data-target="${targetAddress}" data-type="${op.type}">${targetLabel}</a>`;
                                });
                            }
                        }
                    }

                    return line;
                });

        setR2Output(lines);
    }, [handlers, data]);

    const handleAddressMenuClose = useCallback(() => {
        hideContextMenu();

        highlightedAddressAnchorRef.current!.classList.remove("disassembly-menu-open");
        highlightedAddressAnchorRef.current = null;
    }, []);

    const unhookedAddressMenu = useMemo(() => (
        <Menu>
            <MenuItem
                text="Add instruction-level hook"
                icon="add"
                onClick={() => {
                    const address = BigInt(highlightedAddressAnchorRef.current!.innerText);
                    onAddInstructionHook(address);
                }}
            />
        </Menu>
    ), [onAddInstructionHook]);

    const hookedAddressMenu = useMemo(() => (
        <Menu>
            <MenuItem
                text="Go to handler"
                icon="arrow-up"
                onClick={() => {
                    const id: HandlerId = parseInt(highlightedAddressAnchorRef.current!.getAttribute("data-handler")!);
                    onSelectHandler(id);
                }}
            />
        </Menu>
    ), [onSelectHandler]);

    const handleAddressClick = useCallback((event: React.MouseEvent) => {
        const target = event.target;
        if (!(target instanceof HTMLAnchorElement)) {
            return;
        }

        event.preventDefault();

        const branchTarget = target.getAttribute("data-target");
        if (branchTarget !== null) {
            const anchor = containerRef.current!.querySelector(`a[data-address="${branchTarget}"]`);
            if (anchor !== null) {
                anchor.scrollIntoView();
                return;
            }

            onSelectTarget({
                type: (target.getAttribute("data-type") === "call") ? "function" : "instruction",
                address: branchTarget
            });
            return;
        }

        showContextMenu({
            content: target.hasAttribute("data-handler") ? hookedAddressMenu : unhookedAddressMenu,
            onClose: handleAddressMenuClose,
            targetOffset: {
                left: event.clientX,
                top: event.clientY
            },
        });

        highlightedAddressAnchorRef.current = target;
        target.classList.add("disassembly-menu-open");
    }, [handleAddressMenuClose, unhookedAddressMenu]);

    if (isLoading) {
        return (
            <Spinner className="disassembly-view" />
        );
    }

    return (
        <div ref={containerRef} className="disassembly-view" onClick={handleAddressClick}>
            {r2Output.map((line, i) => <div key={i} dangerouslySetInnerHTML={{ __html: line }} />)}
        </div>
    );
}

/*
interface R2Function {
    name: string;
    size: string;
    addr: string;
    ops: R2Operation[];
}
*/

interface R2Operation {
    offset: string;
    esil: string;
    refptr: number;
    fcn_addr: string;
    fcn_last: string;
    size: number;
    opcode: string;
    disasm: string;
    bytes: string;
    family: string;
    type: string;
    type_num: string;
    type2_num: string;
    jump?: string;
    fail?: string;
    reloc: boolean;
}

async function disassemble(
    target: DisassemblyTarget,
    executeR2Command: (command: string) => Promise<string>): Promise<DisassemblyData> {
    const command = [
        `s ${target!.address}`,
    ];
    if (target.type === "function") {
        command.push(...["af-", "af"]);
        if (target.name !== undefined) {
            command.push("afn base64:" + btoa(target.name));
        }
        command.push(...["pdf", "pdfj"]);
    } else {
        command.push(...["pd", "pdj"]);
    }

    let result = await executeR2Command(command.join(";"));
    if (result.startsWith("{")) {
        result = await executeR2Command("pd; pdj");
    }

    const lines = result.trimEnd().split("\n");

    const html = lines.slice(0, lines.length - 1).join("\n");

    const meta = JSON.parse(lines[lines.length - 1]);
    const opItems: R2Operation[] = Array.isArray(meta) ? meta : meta.ops;
    const operations = new Map<bigint, R2Operation>(opItems.map(op => [BigInt(op.offset), op]));

    return { html, operations };
}

interface DisassemblyData {
    html: string;
    operations: Map<bigint, R2Operation>;
}
