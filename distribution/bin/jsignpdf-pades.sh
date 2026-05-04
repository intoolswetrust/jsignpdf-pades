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

JAVA_OPTS="$JAVA_OPTS \
  --add-exports jdk.crypto.cryptoki/sun.security.pkcs11=ALL-UNNAMED \
  --add-exports jdk.crypto.cryptoki/sun.security.pkcs11.wrapper=ALL-UNNAMED \
  --add-exports java.base/sun.security.action=ALL-UNNAMED \
  --add-exports java.base/sun.security.rsa=ALL-UNNAMED \
  --add-opens java.base/java.security=ALL-UNNAMED \
  --add-opens java.base/sun.security.util=ALL-UNNAMED"

"$JAVA" $JAVA_OPTS -jar "$DIR/jsignpdf-pades.jar" "$@"
