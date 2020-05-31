Finds reasons of bloat in the WebAssembly binaries.

### Prerequisites

Install dependencies:

    /usr/local/bin/pip3 install octopus numpy matplotlib
    brew install graphviz

### Running

Run `sizer.py`, it could either show what instructions are most popular in largest functions,
or show the control flow graph, marking few largest functions per `--count` parameter in red.