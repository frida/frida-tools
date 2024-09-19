import "./App.css";
import AddTargetsDialog from "./AddTargetsDialog.tsx";
import EventView from "./EventView.tsx";
import HandlerEditor from "./HandlerEditor.tsx";
import HandlerList from "./HandlerList.tsx";
import {
    Event,
    Handler,
    HandlerId,
    ScopeId,
    StagedItem,
    StagedItemId,
    TraceSpecScope
} from "./model.js";
import {
    BlueprintProvider,
    Callout,
    Button,
    ButtonGroup,
} from "@blueprintjs/core";
import { useEffect, useState } from "react";
import { Resplit } from 'react-resplit';
import useWebSocket, { ReadyState } from "react-use-websocket";

export default function App() {
    const [spawnedProgram, setSpawnedProgram] = useState<string | null>(null);
    const [handlers, setHandlers] = useState<Handler[]>([]);
    const [selectedScope, setSelectedScope] = useState<ScopeId>("");
    const [selectedHandler, setSelectedHandler] = useState<HandlerId>(-1);
    const [handlerCode, setHandlerCode] = useState("");
    const [draftedCode, setDraftedCode] = useState("");
    const [addingTargets, setAddingTargets] = useState(false);
    const [events, setEvents] = useState<Event[]>([]);
    const [latestMatchingEventIndex, setLatestMatchingEventIndex] = useState<number | null>(null);
    const [highlightedEventIndex, setHighlightedEventIndex] = useState<number | null>(null);
    const [stagedItems, setStagedItems] = useState<StagedItem[]>([]);
    const { sendJsonMessage, lastJsonMessage, readyState } = useWebSocket<TracerMessage>(
        (import.meta.env.MODE === "development")
            ? "ws://localhost:1337"
            : `ws://${window.location.host}`);

    function handleHandlerSelection(id: HandlerId) {
        setSelectedHandler(id);
        setHighlightedEventIndex(null);
        sendJsonMessage({ type: "handler:load", id });
    }

    function deploy(code: string) {
        setHandlerCode(code);
        setDraftedCode(code);
        sendJsonMessage({ type: "handler:save", id: selectedHandler, code });
    }

    function handleEventActivation(id: HandlerId) {
        const handler = handlers.find(h => h.id === id);
        setSelectedScope(handler!.scope);
        handleHandlerSelection(id);
    }

    function handleAddTargetsClose() {
        setAddingTargets(false);
        setStagedItems([]);
    }

    function handleAddTargetsQuery(scope: TraceSpecScope, query: string) {
        if (query.length === 0 || query === "*") {
            return;
        }

        const spec = [
            ["include", scope, query],
        ];
        sendJsonMessage({ type: "targets:stage", profile: { spec } });
    }

    function handleAddTargetsCommit(id: StagedItemId | null) {
        handleAddTargetsClose();
        sendJsonMessage({ type: "targets:commit", id });
    }

    function handleRespawnRequest() {
        sendJsonMessage({ type: "tracer:respawn" });
    }

    useEffect(() => {
        if (lastJsonMessage === null) {
            return;
        }

        switch (lastJsonMessage.type) {
            case "tracer:sync":
                setSpawnedProgram(lastJsonMessage.spawned_program);
                setHandlers(lastJsonMessage.handlers);
                break;
            case "handlers:add":
                setHandlers(handlers.concat(lastJsonMessage.handlers));
                break;
            case "handler:loaded": {
                const { code } = lastJsonMessage;
                setHandlerCode(code);
                setDraftedCode(code);
                break;
            }
            case "targets:staged":
                setStagedItems(lastJsonMessage.items);
                break;
            case "events:add":
                setEvents(events.concat(lastJsonMessage.events));
                break;
            default:
                console.log("TODO:", lastJsonMessage);
                break;
        }

    }, [lastJsonMessage]);

    useEffect(() => {
        for (let i = events.length - 1; i !== -1; i--) {
            const event = events[i];
            if (event[0] === selectedHandler) {
                setLatestMatchingEventIndex(i);
                return;
            }
        }
        setLatestMatchingEventIndex(null);
    }, [selectedHandler, events]);

    const connectionError = (readyState === ReadyState.CLOSED)
        ? <Callout
            title="Lost connection to frida-trace"
            intent="danger"
        />
        : null;

    return (
        <>
            <Resplit.Root className="app-content" direction="vertical">
                <Resplit.Pane className="top-area" order={0} initialSize="0.7fr">
                    <section className="navigation-area">
                        <HandlerList
                            handlers={handlers}
                            selectedScope={selectedScope}
                            onScopeSelect={scope => setSelectedScope(scope)}
                            selectedHandler={selectedHandler}
                            onHandlerSelect={handleHandlerSelection}
                        />
                        <ButtonGroup className="target-actions" vertical={true} minimal={true} alignText="left">
                            <Button intent="success" icon="add" onClick={() => setAddingTargets(true)}>Add</Button>
                            {(spawnedProgram !== null) ? <Button intent="danger" icon="reset" onClick={handleRespawnRequest}>Respawn</Button> : null}
                        </ButtonGroup>
                    </section>
                    <section className="work-area">
                        {connectionError}
                        <ButtonGroup minimal={true}>
                            <Button
                                icon="rocket-slant"
                                disabled={draftedCode === handlerCode}
                                onClick={() => deploy(draftedCode)}
                            >
                                Deploy
                            </Button>
                            <Button
                                icon="arrow-down"
                                disabled={latestMatchingEventIndex === null}
                                onClick={() => setHighlightedEventIndex(latestMatchingEventIndex)}
                            >
                                Latest Event
                            </Button>
                        </ButtonGroup>
                        <HandlerEditor
                            handlerId={selectedHandler}
                            handlerCode={handlerCode}
                            onChange={setDraftedCode}
                            onSave={deploy}
                        />
                    </section>
                </Resplit.Pane>
                <Resplit.Splitter className="app-splitter" order={1} size="5px" />
                <Resplit.Pane className="bottom-area" order={2} initialSize="0.3fr">
                    <EventView
                        events={events}
                        highlightedIndex={highlightedEventIndex}
                        onActivate={handleEventActivation}
                    />
                </Resplit.Pane>
            </Resplit.Root>
            <AddTargetsDialog
                isOpen={addingTargets}
                stagedItems={stagedItems}
                onClose={handleAddTargetsClose}
                onQuery={handleAddTargetsQuery}
                onCommit={handleAddTargetsCommit}
            />
            <BlueprintProvider>
                <div />
            </BlueprintProvider>
        </>
    );
}

type TracerMessage =
    | TracerSyncMessage
    | HandlersAddMessage
    | HandlerLoadedMessage
    | TargetsStagedMessage
    | EventsAddMessage
    ;

interface TracerSyncMessage {
    type: "tracer:sync";
    spawned_program: string | null;
    handlers: Handler[];
}

interface HandlersAddMessage {
    type: "handlers:add";
    handlers: Handler[];
}

interface HandlerLoadedMessage {
    type: "handler:loaded";
    code: string;
}

interface TargetsStagedMessage {
    type: "targets:staged";
    items: StagedItem[];
}

interface EventsAddMessage {
    type: "events:add";
    events: Event[];
}