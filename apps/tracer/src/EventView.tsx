import "./EventView.css";
import { Event, HandlerId } from "./model.js";
import { Button, Card } from "@blueprintjs/core";
import { ReactElement, useEffect, useRef, useState } from "react";
import { useStayAtBottom } from "react-stay-at-bottom";

export interface EventViewProps {
    events: Event[];
    selectedIndex: number | null;
    onActivate: EventActionHandler;
    onDeactivate: EventActionHandler;
    onDisassemble: DisassembleHandler;
    onSymbolicate: SymbolicateHandler;
}

export type EventActionHandler = (handlerId: HandlerId, eventIndex: number) => void;
export type DisassembleHandler = (address: string) => void;
export type SymbolicateHandler = (addresses: bigint[]) => Promise<string[]>;

const NON_BLOCKING_SPACE = "\u00A0";
const INDENT = NON_BLOCKING_SPACE.repeat(3) + "|" + NON_BLOCKING_SPACE;

export default function EventView({
    events,
    selectedIndex = null,
    onActivate,
    onDeactivate,
    onDisassemble,
    onSymbolicate,
}: EventViewProps) {
    const containerRef = useRef<HTMLDivElement>(null);
    const selectedRef = useRef<HTMLDivElement>(null);
    const [selectedCallerSymbol, setSelectedCallerSymbol] = useState<string | null>("");
    const [selectedBacktraceSymbols, setSelectedBacktraceSymbols] = useState<string[] | null>(null);
    let lastTid: number | null = null;

    useStayAtBottom(containerRef, {
        initialStay: true,
        autoStay: true
    });

    useEffect(() => {
        const item = selectedRef.current;
        if (item === null) {
            return;
        }
        const itemRect = item.getBoundingClientRect();
        const containerRect = containerRef.current!.getBoundingClientRect();
        if (itemRect.top >= containerRect.top && itemRect.bottom <= containerRect.bottom) {
            return;
        }
        item.scrollIntoView({ block: "center" });
    }, [selectedRef, selectedIndex]);

    useEffect(() => {
        setSelectedCallerSymbol(null);
        setSelectedBacktraceSymbols(null);
    }, [selectedIndex]);

    useEffect(() => {
        if (selectedIndex === null) {
            return;
        }

        const [_targetId, _timestamp, _threadId, _depth, caller, backtrace, _message, _style] = events[selectedIndex];
        let ignore = false;

        async function symbolicate() {
            if (caller !== null && backtrace === null) {
                const [symbol] = await onSymbolicate([BigInt(caller)]);
                if (!ignore) {
                    setSelectedCallerSymbol(symbol);
                }
            }

            if (backtrace !== null) {
                const symbols = await onSymbolicate(backtrace.map(BigInt));
                if (!ignore) {
                    setSelectedBacktraceSymbols(symbols);
                }
            }
        }

        symbolicate();

        return () => {
            ignore = true;
        };
    }, [events, selectedIndex, onSymbolicate])

    let selectedEventDetails: ReactElement | undefined;
    if (selectedIndex !== null) {
        const [targetId, _timestamp, threadId, _depth, caller, backtrace, _message, _style] = events[selectedIndex];

        selectedEventDetails = (
            <Card className="event-details" interactive={true} compact={true}>
                <table>
                    <tbody>
                        <tr>
                            <td>Thread ID</td>
                            <td>0x{threadId.toString(16)}</td>
                            <td>
                            </td>
                        </tr>
                        {(caller !== null && backtrace === null) ? (
                            <tr>
                                <td>Caller</td>
                                <td>
                                    <Button onClick={() => onDisassemble(caller)}>{selectedCallerSymbol ?? caller}</Button>
                                </td>
                            </tr>
                        ) : null
                        }
                        {(backtrace !== null) ? (
                            <tr>
                                <td>Backtrace</td>
                                <td>
                                    {backtrace.map((address, i) => <Button key={address} alignText="left" onClick={() => onDisassemble(address)}>
                                        {(selectedBacktraceSymbols !== null) ? selectedBacktraceSymbols[i] : address}
                                    </Button>)}
                                </td>
                            </tr>
                        ) : null
                        }
                    </tbody>
                </table>
                <Button className="event-dismiss" intent="primary" onClick={() => onDeactivate(targetId, selectedIndex)}>Dismiss</Button>
            </Card>
        );
    }

    return (
        <div ref={containerRef} className="event-view">
            {
                events.reduce((result, [targetId, timestamp, threadId, depth, _caller, _backtrace, message, style], i) => {
                    let timestampStr = timestamp.toString();
                    const timestampPaddingNeeded = Math.max(6 - timestampStr.length, 0);
                    for (let i = 0; i !== timestampPaddingNeeded; i++) {
                        timestampStr = NON_BLOCKING_SPACE + timestampStr;
                    }

                    const colorClass = "ansi-" + style.join("-");

                    if (threadId !== lastTid) {
                        result.push(
                            <div key={i + "-heading"} className={"event-heading " + colorClass}>
                                /* TID 0x{threadId.toString(16)} */
                            </div>
                        );
                        lastTid = threadId;
                    }

                    const isSelected = i === selectedIndex;
                    const eventClasses = ["event-item"];
                    if (isSelected) {
                        eventClasses.push("event-selected");
                    }

                    result.push(
                        <div
                            key={i}
                            ref={isSelected ? selectedRef : undefined}
                            className={eventClasses.join(" ")}
                        >
                            <div className="event-summary">
                                <span className="event-timestamp">{timestampStr} ms</span>
                                <span className={"event-indent " + colorClass}>{INDENT.repeat(depth)}</span>
                                <Button
                                    className={"event-message " + colorClass}
                                    minimal={true}
                                    alignText="left"
                                    onClick={() => onActivate(targetId, i)}
                                >
                                    {message}
                                </Button>
                            </div>
                            {isSelected ? selectedEventDetails : null}
                        </div>
                    );

                    return result;
                }, [] as JSX.Element[])
            }
        </div>
    );
}