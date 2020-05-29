Finds reasons of bloat in the WebAssembly binaries.

### Prerequisites

Install Octopus from https://github.com/pventuzelo/octopus with `python3 setup.py install`.
Works OK on macOS with python3 installed from brew.

Then install couple more libs:

    /usr/local/bin/pip3 install numpy matplotlib
    brew install graphviz

### Running

Run `sizer.py`, it could either show what instructions are most popular in largest functions,
or show the control flow graph, marking few largest functions per `--count` parameter in red.