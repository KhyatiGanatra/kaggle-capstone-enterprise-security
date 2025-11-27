#!/bin/bash
# Script to remove extended attributes from .md files for Cursor compatibility

cd "$(dirname "$0")"

echo "Removing extended attributes from .md files..."

# Remove extended attributes from all .md files
find . -name "*.md" -type f -exec xattr -c {} \; 2>/dev/null

# Recreate files to ensure clean state
for file in CHANGELOG.md CHANGES_SUMMARY.md TESTING_GUIDE.md README.md; do
    if [ -f "$file" ]; then
        cat "$file" > "/tmp/${file}.tmp" && mv "/tmp/${file}.tmp" "$file"
        xattr -c "$file" 2>/dev/null
    fi
done

echo "Done! Try opening the files in Cursor now."
echo ""
echo "Note: Google Drive may re-add extended attributes. If files still don't open:"
echo "  1. Use 'cat filename.md' in terminal to view"
echo "  2. Or open with: open -a 'Visual Studio Code' filename.md"
echo "  3. Or copy files outside Google Drive folder temporarily"



