import { componentize } from '@bytecodealliance/componentize-js';
import { readFile, writeFile } from 'node:fs/promises';

// Retrieve the package name from command line arguments
const processName = process.argv[2];
const worldName = process.argv[3];
if (!processName || !worldName) {
    console.error('usage:\nnode componentize.mjs processName worldName');
    process.exit(1);
}

const jsSource = await readFile('src/lib.js', 'utf8');
const witPath = 'target/wit';

const { component } = await componentize(
    jsSource,
    { witPath: witPath, worldName: worldName, debug: false, disableFeatures: ['http'] },
);

await writeFile(`../pkg/${processName}.wasm`, component);
