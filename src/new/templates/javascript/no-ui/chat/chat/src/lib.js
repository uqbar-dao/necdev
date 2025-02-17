import { printToTerminal, receive, sendAndAwaitResponse, sendResponse } from "hyperware:process/standard@0.7.0";

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

function addToArchive(conversation, author, content, messageArchive) {
    const message = {
        author: author,
        content: content
    };
    if (messageArchive.hasOwnProperty(conversation)) {
        messageArchive[conversation].push(message);
    } else {
        messageArchive[conversation] = [message];
    }
    return messageArchive;
}

function handleMessage(ourNode, messageArchive) {
    const [source, message] = receive();

    if (message.tag == 'response') {
        throw new Error(`unexpected Response: ${JSON.stringify(message.val)}`);
    } else if (message.tag == 'request') {
        const { bytes: bodyBytes, string: body0 } = inputBytesToString(message.val.body)
        const body = JSON.parse(body0);
        const encoder = new TextEncoder();
        if (body.Send) {
            const { target, message: messageText } = body.Send;
            if (target === ourNode) {
                printToTerminal(0, `chat|${source.node}: ${messageText}`);
                messageArchive = addToArchive(
                    source.node,
                    source.node,
                    messageText,
                    messageArchive,
                );
            } else {
                sendAndAwaitResponse(
                    {
                        node: target,
                        process: {
                            processName: "chat",
                            packageName: "chat",
                            publisherNode: "template.os"
                        }
                    },
                    {
                        inherit: false,
                        expectsResponse: 5,
                        body: bodyBytes,
                        metadata: null
                    },
                    null
                );
                messageArchive = addToArchive(
                    target,
                    ourNode,
                    messageText,
                    messageArchive,
                );
            }
            sendResponse(
                {
                    inherit: false,
                    body: encoder.encode(JSON.stringify({ Ack: null })),
                    metadata: null,
                    capabilities: [],
                },
                null
            );
        } else if (body.History) {
            sendResponse(
                {
                    inherit: false,
                    body: encoder.encode(JSON.stringify({ History: { messages: messageArchive } })),
                    metadata: null,
                    capabilities: [],
                },
                null
            );
        } else {
            throw new Error(`Unexpected Request: ${body}`)
        }
    }
    return messageArchive;
}

export function init(our) {
    printToTerminal(0, `chat: begin (javascript)`);

    const { node: ourNode } = parseAddress(our);
    let messageArchive = {};

    while (true) {
        try {
            messageArchive = handleMessage(ourNode, messageArchive);
        } catch (error) {
            printToTerminal(0, `chat: got error ${error}`);
        }
    }
}
