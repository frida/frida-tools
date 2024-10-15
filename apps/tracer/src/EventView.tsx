import "./EventView.css";
import { DisassemblyTarget, Event, HandlerId } from "./model.js";
import { Button, Card } from "@blueprintjs/core";
import Ansi from "@curvenote/ansi-to-react";
import { ReactElement, useCallback, useEffect, useRef, useState } from "react";
import { useStayAtBottom } from "react-stay-at-bottom";
import { ViewportList } from "react-viewport-list";

export interface EventViewProps {
    events: Event[];
    selectedIndex: number | null;
    onActivate: EventActionHandler;
    onDeactivate: EventActionHandler;
    onDisassemble: DisassembleHandler;
    onSymbolicate: SymbolicateHandler;
}

export type EventActionHandler = (handlerId: HandlerId, eventIndex: number) => void;
export type DisassembleHandler = (target: DisassemblyTarget) => void;
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
    const [items, setItems] = useState<(EventItem | ThreadIdMarkerItem)[]>([]);
    const [selectedCallerSymbol, setSelectedCallerSymbol] = useState<string | null>("");
    const [selectedBacktraceSymbols, setSelectedBacktraceSymbols] = useState<string[] | null>(null);

    useStayAtBottom(containerRef, {
        initialStay: true,
        autoStay: true
    });

    useEffect(() => {
        let lastTid: number | null = null;
        setItems(events.reduce((result, event, i) => {
            const [_targetId, _timestamp, threadId, _depth, _caller, _backtrace, _message, style] = event;
            if (threadId !== lastTid) {
                result.push([i, threadId, style]);
                lastTid = threadId;
            }
            result.push([i, event]);
            return result;
        }, [] as (EventItem | ThreadIdMarkerItem)[]));
    }, [events]);

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
    }, [events, selectedIndex, onSymbolicate]);

    const handleDisassemblyRequest = useCallback((rawAddress: string) => {
        onDisassemble({ type: "instruction", address: BigInt(rawAddress) });
    }, [onDisassemble]);

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
                                    <Button onClick={() => handleDisassemblyRequest(caller)}>{selectedCallerSymbol ?? caller}</Button>
                                </td>
                            </tr>
                        ) : null
                        }
                        {(backtrace !== null) ? (
                            <tr>
                                <td>Backtrace</td>
                                <td>
                                    {backtrace.map((address, i) =>
                                        <Button key={address} alignText="left" onClick={() => handleDisassemblyRequest(address)}>
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
            <ViewportList items={items}>
                {(item) => {
                    if (item.length === 3) {
                        const [index, threadId, style] = item;
                        const colorClass = "ansi-" + style.join("-");
                        return (
                            <div key={`${index}-heading`} className={"event-heading " + colorClass}>
                                /* TID 0x{threadId.toString(16)} */
                            </div>
                        );
                    }

                    const [index, event] = item;
                    const [targetId, timestamp, _threadId, depth, _caller, _backtrace, message, style] = event;

                    const isSelected = index === selectedIndex;
                    const eventClasses = ["event-item"];
                    if (isSelected) {
                        eventClasses.push("event-selected");
                    }

                    let timestampStr = timestamp.toString();
                    const timestampPaddingNeeded = Math.max(6 - timestampStr.length, 0);
                    for (let i = 0; i !== timestampPaddingNeeded; i++) {
                        timestampStr = NON_BLOCKING_SPACE + timestampStr;
                    }

                    const colorClass = "ansi-" + style.join("-");

                    return (
                        <div
                            key={index}
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
                                    onClick={() => onActivate(targetId, index)}
                                >
                                    <Ansi>{message}</Ansi>
                                </Button>
                            </div>
                            {isSelected ? selectedEventDetails : null}
                        </div>
                    );
                }}
            </ViewportList>
        </div>
    );
}

type EventItem = [index: number, event: Event];
type ThreadIdMarkerItem = [index: number, threadId: number, style: string[]];
