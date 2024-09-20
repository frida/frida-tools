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

export default function DisassemblyView({ target, handlers, onSelectTarget, onSelectHandler, onAddInstructionHook }: DisassemblyViewProps) {
    const containerRef = useRef<HTMLDivElement>(null);
    const [rawR2Output, setRawR2Output] = useState("");
    const [r2Ops, setR2Ops] = useState(new Map<bigint, R2Operation>());
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
            const command = [
                `s ${target!.address}`,
            ]
            if (t.type === "function") {
                command.push(...["af-", "af"]);
                if (t.name !== undefined) {
                    command.push("afn base64:" + btoa(t.name));
                }
                command.push(...["pdf", "pdfj"]);
            } else {
                command.push(...["pd", "pdj"]);
            }

            let result = await executeR2Command(command.join(";"));
            if (ignore) {
                return;
            }
            if (result.startsWith("{")) {
                result = await executeR2Command("pd; pdj");
                if (ignore) {
                    return;
                }
            }

            const lines = result.trimEnd().split("\n");

            setRawR2Output(lines.slice(0, lines.length - 1).join("\n"));

            const meta = JSON.parse(lines[lines.length - 1]);
            const opItems: R2Operation[] = Array.isArray(meta) ? meta : meta.ops;
            const opByAddress = new Map<bigint, R2Operation>(opItems.map(op => [BigInt(op.offset), op]));
            setR2Ops(opByAddress);

            setIsLoading(false);
        }

        start();

        return () => {
            ignore = true;
        };
    }, [target]);

    useEffect(() => {
        let lines: string[];
        if (rawR2Output.length > 0) {
            const handlerByAddress = handlers.reduce((result, handler) => {
                const { address } = handler;
                if (address === null) {
                    return result;
                }
                return result.set(BigInt(address), handler);
            }, new Map<bigint, Handler>());

            lines =
                rawR2Output
                .split("<br />")
                .map(line => {
                    let address: bigint | null = null;
                    line = line.replace(/\b0x[0-9a-f]+\b/, rawAddress => {
                        address = BigInt(rawAddress);
                        const handler = handlerByAddress.get(address);
                        const attrs = (handler !== undefined)
                            ? ` class="disassembly-address-has-handler" data-handler="${handler.id}"`
                            : "";
                        return `<a data-address="0x${address.toString(16)}" ${attrs}>${rawAddress}</a>`;
                    });

                    if (address !== null) {
                        const op = r2Ops.get(address);
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
        } else {
            lines = [];
        }

        setR2Output(lines);
    }, [handlers, rawR2Output]);

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
                    const id: HandlerId = parseInt(highlightedAddressAnchorRef.current!.getAttribute("data-handler")!)
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
