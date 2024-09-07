#!/bin/bash

# Make sure we're in the project directory
cd "$(dirname "$0")"

# Install dependencies
npm install

# Link the package
npm link

echo "Package linked successfully. You can now use 'pltech-scanner' command."