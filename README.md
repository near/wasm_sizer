Finds reasons of bloat in the WebAssembly binaries.

### Prerequisites

Install dependencies:

    pip3 install octopus numpy matplotlib itanium-demangler
    brew install graphviz

On Linux machines with evince PDF viewer use this command to allow zooming in.

    gsettings set org.gnome.Evince page-cache-size 1000

### Running

Run `sizer.py`, it could either show what instructions are most popular in largest functions,
or show the control flow graph, marking few largest functions per `--count` parameter in red.
