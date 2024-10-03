import "./App.css";
import AddTargetsDialog from "./AddTargetsDialog.tsx";
import DisassemblyView, { type DisassemblyTarget } from "./DisassemblyView.tsx";
import EventView from "./EventView.tsx";
import HandlerEditor from "./HandlerEditor.tsx";
import HandlerList from "./HandlerList.tsx";
import { useModel } from "./model.js";
import {
    BlueprintProvider,
    Callout,
    Button,
    ButtonGroup,
    Switch,
    Tabs,
    Tab,
} from "@blueprintjs/core";
import { useRef, useState } from "react";
import { Resplit } from "react-resplit";

export default function App() {
    const {
        lostConnection,

        spawnedProgram,
        respawn,

        handlers,
        selectedScope,
        selectScope,
        selectedHandler,
        setSelectedHandlerId,
        handlerCode,
        draftedCode,
        setDraftedCode,
        deployCode,
        captureBacktraces,
        setCaptureBacktraces,

        events,
        latestMatchingEventIndex,
        selectedEventIndex,
        setSelectedEventIndex,

        addingTargets,
        startAddingTargets,
        finishAddingTargets,
        stageItems,
        stagedItems,
        commitItems,

        addInstructionHook,

        symbolicate,
    } = useModel();
    const captureBacktracesSwitchRef = useRef<HTMLInputElement>(null);
    const [selectedTabId, setSelectedTabId] = useState("events");
    const [disassemblyTarget, setDisassemblyTarget] = useState<DisassemblyTarget>();

    const connectionError = lostConnection
        ? <Callout
            title="Lost connection to frida-trace"
            intent="danger"
        />
        : null;

    const eventView = (
        <EventView
            events={events}
            selectedIndex={selectedEventIndex}
            onActivate={(handlerId, eventIndex) => {
                setSelectedHandlerId(handlerId);
                setSelectedEventIndex(eventIndex);
            }}
            onDeactivate={() => {
                setSelectedEventIndex(null);
            }}
            onDisassemble={address => {
                setSelectedTabId("disassembly");
                setDisassemblyTarget({ type: "instruction", address });
            }}
            onSymbolicate={symbolicate}
        />
    );

    const disassemblyView = (
        <DisassemblyView
            target={disassemblyTarget}
            handlers={handlers}
            onSelectTarget={setDisassemblyTarget}
            onSelectHandler={setSelectedHandlerId}
            onAddInstructionHook={addInstructionHook}
            onSymbolicate={symbolicate}
        />
    );

    return (
        <>
            <Resplit.Root className="app-content" direction="vertical">
                <Resplit.Pane className="top-area" order={0} initialSize="0.5fr">
                    <section className="navigation-area">
                        <HandlerList
                            handlers={handlers}
                            selectedScope={selectedScope}
                            onScopeSelect={selectScope}
                            selectedHandler={selectedHandler?.id ?? null}
                            onHandlerSelect={setSelectedHandlerId}
                        />
                        <ButtonGroup className="target-actions" vertical={true} minimal={true} alignText="left">
                        <Button intent="success" icon="add" onClick={startAddingTargets}>Add</Button>
                            {(spawnedProgram !== null) ? <Button intent="danger" icon="reset" onClick={respawn}>Respawn</Button> : null}
                        </ButtonGroup>
                    </section>
                    <section className="editor-area">
                        {connectionError}
                        <section className="editor-toolbar">
                            <ButtonGroup minimal={true}>
                                <Button
                                    icon="rocket-slant"
                                    disabled={draftedCode === handlerCode}
                                    onClick={() => deployCode(draftedCode)}
                                >
                                    Deploy
                                </Button>
                                <Button
                                    icon="arrow-down"
                                    disabled={latestMatchingEventIndex === null}
                                    onClick={() => {
                                        setSelectedTabId("events");
                                        setSelectedEventIndex(latestMatchingEventIndex);
                                    }}
                                >
                                    Latest Event
                                </Button>
                                <Button
                                    icon="code"
                                    disabled={lostConnection || selectedHandler === null || selectedHandler.address === null}
                                    onClick={() => {
                                        setSelectedTabId("disassembly");
                                        setDisassemblyTarget({
                                            type: (selectedHandler!.flavor === "insn") ? "instruction" : "function",
                                            name: selectedHandler!.display_name,
                                            address: selectedHandler!.address!
                                        });
                                    }}
                                >
                                    Disassemble
                                </Button>
                            </ButtonGroup>
                            <Switch
                                inputRef={captureBacktracesSwitchRef}
                                checked={captureBacktraces}
                                onChange={() => setCaptureBacktraces(captureBacktracesSwitchRef.current!.checked)}
                            >
                                Capture Backtraces
                            </Switch>
                        </section>
                        <HandlerEditor
                            handlerId={selectedHandler?.id ?? null}
                            handlerCode={handlerCode}
                            onChange={setDraftedCode}
                            onSave={deployCode}
                        />
                    </section>
                </Resplit.Pane>
                <Resplit.Splitter className="app-splitter" order={1} size="5px" />
                <Resplit.Pane className="bottom-area" order={2} initialSize="0.5fr">
                    <Tabs className="bottom-tabs" selectedTabId={selectedTabId} onChange={tabId => setSelectedTabId(tabId as string)} animate={false}>
                        <Tab id="events" title="Events" panel={eventView} panelClassName="bottom-tab-panel" />
                        <Tab id="disassembly" title="Disassembly" panel={disassemblyView} panelClassName="bottom-tab-panel" />
                    </Tabs>
                </Resplit.Pane>
            </Resplit.Root>
            <AddTargetsDialog
                isOpen={addingTargets}
                stagedItems={stagedItems}
                onClose={finishAddingTargets}
                onQuery={stageItems}
                onCommit={commitItems}
            />
            <BlueprintProvider>
                <div />
            </BlueprintProvider>
        </>
    );
}
