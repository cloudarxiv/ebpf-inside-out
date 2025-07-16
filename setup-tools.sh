make install-dependencies
make get-tools

TOOLS_PATH="${PWD}/tools"
if [ ":$PATH:" != *":$TOOLS_PATH:"* ]; then
    export PATH="$PATH:$TOOLS_PATH"
fi