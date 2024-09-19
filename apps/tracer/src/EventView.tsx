import "./EventView.css";
import { Event, HandlerId } from "./model.js";
import { Button } from "@blueprintjs/core";
import { useEffect, useRef } from "react";
import { useStayAtBottom } from "react-stay-at-bottom";

export interface EventViewProps {
    events: Event[];
    highlightedIndex: number | null;
    onActivate: ActivateEventHandler;
}

export type ActivateEventHandler = (id: HandlerId) => void;

const NON_BLOCKING_SPACE = "\u00A0";
const INDENT = NON_BLOCKING_SPACE.repeat(3) + "|" + NON_BLOCKING_SPACE;

export default function EventView({ events, highlightedIndex = null, onActivate }: EventViewProps) {
    const containerRef = useRef<HTMLDivElement>(null);
    const highlightedRef = useRef<HTMLDivElement>(null);
    let lastTid: number | null = null;

    useStayAtBottom(containerRef, {
        initialStay: true,
        autoStay: true
    });

    useEffect(() => {
        highlightedRef.current?.scrollIntoView({ block: "center" });
    }, [highlightedRef, highlightedIndex]);

    return (
        <div ref={containerRef} className="event-view">
            {
                events.reduce((result, [targetId, timestamp, threadId, depth, message, style], i) => {
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

                    const isHighlighted = i === highlightedIndex;

                    result.push(
                        <div
                            key={i}
                            ref={isHighlighted ? highlightedRef : undefined}
                            className={isHighlighted ? "event-highlighted" : ""}
                        >
                            <span className="event-timestamp">{timestampStr} ms</span>
                            <span className={"event-indent " + colorClass}>{INDENT.repeat(depth)}</span>
                            <Button
                                className={"event-message " + colorClass}
                                minimal={true}
                                alignText="left"
                                onClick={() => onActivate(targetId)}
                            >
                                {message}
                            </Button>
                        </div>
                    );

                    return result;
                }, [] as JSX.Element[])
            }
        </div>
    );
}