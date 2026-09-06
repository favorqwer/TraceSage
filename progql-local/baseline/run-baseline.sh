#!/usr/bin/env bash
# Builds and runs the deterministic investigation baseline.
#
# Usage:
#   bash progql-local/baseline/run-baseline.sh [dbName] [outDir]
#   dbName defaults to 1_Multi_Stage_Data_Exfiltration
#   outDir defaults to output/baseline/<dbName>   (relative to the repo root)
#
# The engine sources are compiled WITHOUT src/main/java/main/Main.java, which
# still references the removed ProGQL parser. A stub main.Main (baseline/stub)
# provides the static members the engine reads; see README.md.
set -euo pipefail

BASELINE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROGQL_DIR="$(cd "$BASELINE_DIR/.." && pwd)"
ROOT_DIR="$(cd "$PROGQL_DIR/.." && pwd)"

DB_NAME="${1:-1_Multi_Stage_Data_Exfiltration}"
OUT_DIR_ARG="${2:-output/baseline/${DB_NAME}}"
if [[ "$OUT_DIR_ARG" != /* && "$OUT_DIR_ARG" != [A-Za-z]:* ]]; then
   OUT_DIR_ARG="$ROOT_DIR/$OUT_DIR_ARG"
fi
if command -v cygpath >/dev/null 2>&1; then
   OUT_DIR_ARG="$(cygpath -m "$OUT_DIR_ARG")"
fi

M2_REPO="${M2_REPO:-$HOME/.m2/repository}"
if command -v cygpath >/dev/null 2>&1; then
   M2_REPO="$(cygpath -m "$M2_REPO")"
fi

# Canonical entry-ranking weights (impact 0.55 / time 0.45), see README.md.
CFG_PATH="$BASELINE_DIR/progql-llm.properties"
if command -v cygpath >/dev/null 2>&1; then
   CFG_PATH="$(cygpath -m "$CFG_PATH")"
fi

# Compile with paths relative to PROGQL_DIR so that POSIX/Windows path
# conversion cannot mangle the javac @file list.
BUILD_DIR=".baseline-build"
trap 'rm -rf "$PROGQL_DIR/$BUILD_DIR"' EXIT
mkdir -p "$PROGQL_DIR/$BUILD_DIR/classes"

CP="$M2_REPO/org/jgrapht/jgrapht-core/1.1.0/jgrapht-core-1.1.0.jar"
CP="$CP;$M2_REPO/org/jgrapht/jgrapht-ext/1.1.0/jgrapht-ext-1.1.0.jar"
CP="$CP;$M2_REPO/org/jgrapht/jgrapht-io/1.1.0/jgrapht-io-1.1.0.jar"
# The Bolt driver must precede the embedded neo4j-3.5.11 jar: that uber jar
# bundles an ancient org.neo4j.driver (1.7) which cannot talk to the current
# server. Keeping traversal/neo4j (embedded API) compilable still needs the
# 3.5.11 jar for org.neo4j.graphdb.*.
CP="$CP;$M2_REPO/org/neo4j/driver/neo4j-java-driver/4.1.1/neo4j-java-driver-4.1.1.jar"
CP="$CP;$M2_REPO/org/reactivestreams/reactive-streams/1.0.4/reactive-streams-1.0.4.jar"
NETTY="$M2_REPO/io/netty"
CP="$CP;$NETTY/netty-buffer/4.1.105.Final/netty-buffer-4.1.105.Final.jar"
CP="$CP;$NETTY/netty-common/4.1.105.Final/netty-common-4.1.105.Final.jar"
CP="$CP;$NETTY/netty-transport/4.1.105.Final/netty-transport-4.1.105.Final.jar"
CP="$CP;$NETTY/netty-resolver/4.1.105.Final/netty-resolver-4.1.105.Final.jar"
CP="$CP;$NETTY/netty-handler/4.1.105.Final/netty-handler-4.1.105.Final.jar"
CP="$CP;$NETTY/netty-codec/4.1.105.Final/netty-codec-4.1.105.Final.jar"
CP="$CP;$M2_REPO/org/neo4j/neo4j-graphdb-api/3.5.11/neo4j-graphdb-api-3.5.11.jar"
CP="$CP;$M2_REPO/org/neo4j/neo4j-resource/3.5.11/neo4j-resource-3.5.11.jar"
CP="$CP;$M2_REPO/org/neo4j/neo4j/3.5.11/neo4j-3.5.11.jar"
CP="$CP;$M2_REPO/com/fathzer/javaluator/3.0.3/javaluator-3.0.3.jar"
CP="$CP;$M2_REPO/org/apache/commons/commons-jexl3/3.0/commons-jexl3-3.0.jar"
CP="$CP;$M2_REPO/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar"
CP="$CP;$M2_REPO/org/apache/commons/commons-math3/3.6.1/commons-math3-3.6.1.jar"
CP="$CP;$M2_REPO/guru/nidi/graphviz-java/0.18.1/graphviz-java-0.18.1.jar"
CP="$CP;$M2_REPO/org/json/json/20180813/json-20180813.jar"
CP="$CP;$M2_REPO/com/google/guava/guava/32.1.0-jre/guava-32.1.0-jre.jar"
CP="$CP;$M2_REPO/junit/junit/4.13.2/junit-4.13.2.jar"
CP="$CP;$M2_REPO/org/slf4j/slf4j-api/1.7.36/slf4j-api-1.7.36.jar"

(
   cd "$PROGQL_DIR"
   find src/main/java -name '*.java' ! -name 'BreadthFirstIterator.java' ! -path '*main/Main.java' > "$BUILD_DIR/sources.txt"
   {
      echo "baseline/stub/main/Main.java"
      echo "baseline/BaselineRunner.java"
   } >> "$BUILD_DIR/sources.txt"

   MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' javac -encoding UTF-8 -nowarn \
      -d "$BUILD_DIR/classes" -cp "$CP" "@$BUILD_DIR/sources.txt"
)

cd "$PROGQL_DIR"
MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' java -Dprogql.llm.config="$CFG_PATH" \
   -cp "$BUILD_DIR/classes;$CP" baseline.BaselineRunner "$DB_NAME" "$OUT_DIR_ARG"
