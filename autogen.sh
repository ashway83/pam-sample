#!/bin/sh

SCRIPT_PATH="$(cd "$(dirname "$0")" >/dev/null 2>&1; pwd -P)"

if [ ! -d "$SCRIPT_PATH/m4" ]; then
  mkdir "$SCRIPT_PATH/m4"
fi

autoreconf -fvi
