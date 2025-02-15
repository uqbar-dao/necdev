import { printToTerminal, receive, sendResponse } from "hyperware:process/standard@0.7.0";

function parseAddress(addressString) {
    const [node, rest] = addressString.split('@');
    const [process, packageName, publisher] = rest.split(':');
    return { node, process, packageName, publisher };
}

function inputBytesToString(byteObject) {
    // Determine the size of the Uint8Array
    const size = Object.keys(byteObject).length;
    const byteArray = new Uint8Array(size);

    // Assign the bytes to the array
    for (let i = 0; i < size; i++) {
        byteArray[i] = byteObject[i];
    }

    // Convert the Uint8Array to a string
    const string = new TextDecoder().decode(byteArray);

    return { bytes: byteArray, string: string };
}

function handleMessage(ourNode, messageArchive) {
    const [source, message] = receive();

    if (message.tag == 'response') {
        throw new Error(`unexpected Response: ${JSON.stringify(message.val)}`);
    } else if (message.tag == 'request') {
        const { bytes: bodyBytes, string: body0 } = inputBytesToString(message.val.body)
        const body = JSON.parse(body0);
        const encoder = new TextEncoder();
        printToTerminal(0, `echo: got message ${JSON.stringify(body)}`);
        sendResponse(
            {
                inherit: false,
                body: encoder.encode("Ack"),
                metadata: null,
                capabilities: [],
            },
            null,
        );
    }
}

export function init(our) {
    printToTerminal(0, `echo: begin (javascript)`);

    const { node: ourNode } = parseAddress(our);

    while (true) {
        try {
            handleMessage(ourNode);
        } catch (error) {
            printToTerminal(0, `echo: got error ${error}`);
        }
    }
}
