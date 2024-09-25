#!/bin/bash

# Define the directories
DIR0="./contracts/lib/eigenlayer-middleware/lib/eigenlayer-contracts"
DIR1="./contracts/lib/eigenlayer-middleware"
DIR2="./contracts"
DIR3="./avs/incredible-squaring-avs/contracts"

# Function to run forge commands in a directory
run_forge_commands() {
    local dir=$1
    echo "Running forge commands in $dir"
    cd "$dir" || exit
    forge build
    cd - || exit
}

# Run forge commands in all listed directories
run_forge_commands "$DIR0"
run_forge_commands "$DIR1"
run_forge_commands "$DIR2"
run_forge_commands "$DIR3"