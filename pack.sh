#!/bin/bash

# Directory of the add-on sources
ADDON_DIR="."

# Name of the output file (e.g. my-addon.xpi)
OUTPUT_FILE="Suke.EmailValidationAddon.xpi"

# Remove the output file if it already exists
if [ -f "$OUTPUT_FILE" ]; then
    rm "$OUTPUT_FILE"
    echo "Removed old $OUTPUT_FILE."
fi

# Compress the add-on code into a ZIP (XPI) archive
zip -r "$OUTPUT_FILE" "$ADDON_DIR" -x "*.zip" "*.xpi" "*.sh" ".git/*" ".gitignore" "node_modules/*" "package.json" "package-lock.json" "README.md" "LICENSE"

echo "Add-on successfully packed into $OUTPUT_FILE."
