import "./EventView.css";
import { Event, HandlerId } from "./model.js";
import { Button } from "@blueprintjs/core";
import ScrollToBottom from "react-scroll-to-bottom";

export interface EventViewProps {
    events: Event[];
    onActivate: ActivateEventHandler;
}

export type ActivateEventHandler = (id: HandlerId) => void;

const NON_BLOCKING_SPACE = "\u00A0";
const INDENT = NON_BLOCKING_SPACE.repeat(3) + "|" + NON_BLOCKING_SPACE;

export default function EventView({ events, onActivate }: EventViewProps) {
    let lastTid: number | null = null;

    return (
        <ScrollToBottom className="event-view">
            <div className="event-items">
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

                        result.push(
                            <div key={i}>
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
        </ScrollToBottom>
    );
}