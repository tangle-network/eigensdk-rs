#!/bin/bash

# Check if the script is being sourced
(return 0 2>/dev/null) && sourced=1 || sourced=0

if [ $sourced -eq 0 ]; then
    echo "Error: This script needs to be sourced. Run it as:"
    echo "  source $0"
    echo "  or"
    echo "  . $0"
    exit 1
fi

# Export the environment variables
export OPERATOR_ECDSA_KEY_PASSWORD="ECDSA_PASSWORD"
export OPERATOR_BLS_KEY_PASSWORD="BLS_PASSWORD"

echo "Environment variables have been set."