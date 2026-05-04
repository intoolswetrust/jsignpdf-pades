#!/bin/bash
set -euo pipefail

# Follow symlinks until we get the real file.
SOURCE="$0"
while [ -L "$SOURCE" ]; do
  DIR="$(cd -P "$(dirname "$SOURCE")" >/dev/null 2>&1 && pwd -P)"
  TARGET="$(readlink "$SOURCE")"
  case "$TARGET" in
    /*) SOURCE="$TARGET" ;;
    *)  SOURCE="$DIR/$TARGET" ;;
  esac
done
DIR="$(cd -P "$(dirname "$SOURCE")" >/dev/null 2>&1 && pwd -P)"

[ "${OSTYPE:-}" = "cygwin" ] && DIR="$( cygpath -m "$DIR" )"

JAVA_HOME="${JAVA_HOME-}"
JAVA_OPTS="${JAVA_OPTS-}"

JAVA=java
if [ -n "$JAVA_HOME" ]; then
  JAVA="$JAVA_HOME/bin/java"
fi

"$JAVA" $JAVA_OPTS -jar "$DIR/jsignpdf-pades-validator.jar" "$@"
