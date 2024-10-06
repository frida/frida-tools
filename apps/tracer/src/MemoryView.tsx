import "./MemoryView.css";
import { Spinner } from "@blueprintjs/core";
import { useR2 } from "@frida/react-use-r2";
import { useEffect, useState } from "react";

export interface MemoryViewProps {
    address?: bigint;
}

export default function MemoryView({ address }: MemoryViewProps) {
    const [data, setData] = useState<string>("");
    const [isLoading, setIsLoading] = useState(false);
    const { executeR2Command } = useR2();

    useEffect(() => {
        if (address === undefined) {
            return;
        }

        let ignore = false;
        setIsLoading(true);

        async function start() {
            const data = await executeR2Command(`x @ 0x${address!.toString(16)}`);
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
    }, [address, executeR2Command]);

    if (isLoading) {
        return (
            <Spinner className="memory-view" />
        );
    }

    return (
        <div className="memory-view" dangerouslySetInnerHTML={{ __html: data }} />
    );
}
