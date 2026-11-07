#!/bin/bash

# Das Verzeichnis des Add-ons
ADDON_DIR="."

# Der Name der Ausgabedatei (z.B. my-addon.xpi)
OUTPUT_FILE="Suke.EmailValidationAddon.xpi"

# Überprüfen, ob die Ausgabedatei bereits existiert und löschen
if [ -f "$OUTPUT_FILE" ]; then
    rm "$OUTPUT_FILE"
    echo "Alte $OUTPUT_FILE gelöscht."
fi

# Komprimieren des Add-on-Codes in eine ZIP-Datei
zip -r "$OUTPUT_FILE" "$ADDON_DIR" -x "*.zip" "*.xpi" "*.sh" ".git/*" ".gitignore" "node_modules/*" "package.json" "package-lock.json" "README.md" "LICENSE"

echo "Add-on erfolgreich in $OUTPUT_FILE verpackt."