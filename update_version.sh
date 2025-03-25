#!/bin/bash

# Check if version argument is provided
if [ $# -ne 1 ]; then
    echo "Usage: $0 <new_version>"
    echo "Example: $0 1.2.3"
    exit 1
fi

NEW_VERSION=$1

# Validate version format (x.y.z)
if ! [[ $NEW_VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Error: Version must be in format x.y.z (e.g., 1.2.3)"
    exit 1
fi

# Update version in __init__.py
sed -i "s/__version__ = '[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*'/__version__ = '$NEW_VERSION'/" file_monitor/__init__.py
echo "Updated version in __init__.py"

# Update version in debian/control, build_deb.sh and file_monitor.py
sed -i "s/^Version: .*/Version: $NEW_VERSION/" debian/control
sed -i "s/^VERSION=\".*\"/VERSION=\"$NEW_VERSION\"/" build_deb.sh
sed -i "s/^VERSION = \".*\"/VERSION = \"$NEW_VERSION\"/" file_monitor/file_monitor.py
echo "Updated version in debian/control, build_deb.sh and file_monitor.py"

# Create new changelog entry
TEMP_CHANGELOG=$(mktemp)
cat > "$TEMP_CHANGELOG" << EOF
file-monitor ($NEW_VERSION) unstable; urgency=medium

  * Version $NEW_VERSION release.

 -- $(git config user.name) <$(git config user.email)>  $(date -R)

EOF
cat debian/changelog >> "$TEMP_CHANGELOG"
mv "$TEMP_CHANGELOG" debian/changelog
echo "Updated debian/changelog"

# Build new .deb package
echo "Building new .deb package..."
./build_deb.sh
echo "Complete! New version $NEW_VERSION has been set and package built."
