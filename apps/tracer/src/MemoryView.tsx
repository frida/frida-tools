import "./MemoryView.css";
import { SegmentedControl, Spinner } from "@blueprintjs/core";
import { useR2 } from "@frida/react-use-r2";
import { useEffect, useState } from "react";

export interface MemoryViewProps {
    address?: bigint;
}

export default function MemoryView({ address }: MemoryViewProps) {
    const [format, setFormat] = useState("x");
    const [data, setData] = useState("");
    const [isLoading, setIsLoading] = useState(false);
    const { executeR2Command } = useR2();

    useEffect(() => {
        if (address === undefined) {
            return;
        }

        let ignore = false;
        setIsLoading(true);

        async function start() {
            const data = await executeR2Command(`${format} @ 0x${address!.toString(16)}`);
            if (ignore) {
                return;
            }

            setData(data);
            setIsLoading(false);
        }

        start();

        return () => {
            ignore = true;
        };
    }, [format, address, executeR2Command]);

    if (isLoading) {
        return (
            <Spinner className="memory-view" />
        );
    }

    return (
        <div className="memory-view">
            <SegmentedControl
                small={true}
                options={[
                    {
                        label: "Raw",
                        value: "x",
                    },
                    {
                        label: "64",
                        value: "pxq"
                    },
                    {
                        label: "32",
                        value: "pxw"
                    },
                ]}
                defaultValue="x"
                onValueChange={setFormat}
            />
            <div dangerouslySetInnerHTML={{ __html: data }} />
        </div>
    );
}
