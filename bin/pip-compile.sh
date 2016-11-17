#!/bin/bash

set -e

reqs=( "requirements.txt" )
project_root=$(dirname $0)/..

# Run pip-compile, then make vcs packages not editable.
# This is required to keep tests from testing third party packages
for req in "${reqs[@]}"; do
    pip-compile -o "$project_root/$req" "$project_root/reqs/$req"
    sed -E -i '' 's/^-e[[:space:]]+//' "$project_root/$req"
done
