# kit

Tool**kit** for developing on [Hyperware](https://hyperware.ai).

Documentation in the [Hyperware Book](https://book.hyperware.ai/kit/kit-dev-toolkit.html); example usage [here](https://book.hyperware.ai/my_first_app/chapter_1.html).

## Installing

Install with cargo:

```bash
cargo install --git https://github.com/hyperware-ai/kit --locked
```

### Updating

To update, re-run

```bash
cargo install --git https://github.com/hyperware-ai/kit --locked
```

or use
```bash
kit update
```

## Usage

```bash
# Create a Rust package template (default no UI):
kit new my_package

# Build the package:
kit build my_package

# Start a fake node, by default, on port 8080:
kit boot-fake-node

# Start the package in a running node (requires a node or fake node running at, default, localhost:8080; can specify port of a localhost node with `--port` or can specify entire URL with `--url`):
kit start-package my_package

# Or build, start a node, and start a package from inside the project...
cd my_package
kit build
kit boot-fake-node
kit start-package

# Bonus: create a Python package template (it `build`s & `start-package`s just like a Rust package!):
kit new my_py_package -l python
cd my_py_package
kit build
kit start-package

# Bonus: create a Rust package template with UI (it `build`s & `start-package`s just like a Rust package!):
kit new my_package_with_ui --ui
cd my_package_with_ui
kit build
kit start-package

# Print usage

kit --help
```

`kit boot-fake-node` can also accept a `--runtime-path` argument that compiles the fake node binary from a local [Hyperdrive](https://github.com/hyperware-ai/hyperdrive) repository.
Use like (substituting path to Hyperdrive repo):

```bash
kit boot-fake-node --runtime-path ~/git/hyperdrive
```

`kit` also contains tools for running tests.
For details and examples, please see
1. [Hyperdrive Book's example code](https://github.com/hyperware-ai/hyperware-book/tree/main/code).
2. `kit`s templates, available through `kit new` or [here](https://github.com/hyperware-ai/kit/tree/master/src/new/templates/rust).
3. [https://github.com/hyperware-ai/core_tests](https://github.com/hyperware-ai/core_tests).

## UI Development

The simplest way to work on the UI is to use `kit dev-ui` which develops against a running node.
Under the hood, `kit dev-ui` is just `cd ui && npm install && npm run dev`.

The UI should open on port `3000` (or next available port) and will proxy all websocket and HTTP requests to `http://localhost:8080` by default.
You can choose to proxy to any URL using the `-u` flag:
```bash
kit dev-ui my_package -u http://localhost:8081
```
This is the same as prepending the environment variable:
```bash
VITE_NODE_URL=http://localhost:8081 npm run dev
```

NodeJS (v18 or higher) and NPM are required to build and develop the UI.

The UI is written in React with Vite as the bundler + reloader.

To use `npm start` instead of `npm run dev`, use `kit dev-ui --release`.
