#!/bin/bash
export LD_LIBRARY_PATH=/usr/local/lib/:$LD_LIBRARY_PATH
set -e
PACKAGE_NAME="torch"
PACKAGE_PATH=$(pip show "$PACKAGE_NAME" 2>/dev/null | grep -i "^Location:" | awk '{print $2}')
export LD_LIBRARY_PATH="${PACKAGE_PATH}/${PACKAGE_NAME}/lib":$LD_LIBRARY_PATH

./face_id/face_id
