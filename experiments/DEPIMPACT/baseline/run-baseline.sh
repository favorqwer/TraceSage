#!/usr/bin/env bash
# Builds and runs the deterministic investigation baseline.
#
# Usage:
#   bash experiments/DEPIMPACT/baseline/run-baseline.sh <scenarioName> [outDir] [poi options...]
#   scenarioName is required (e.g. 1_Web_Exploit_Ransomware; names in
#   provenance/config/scenarios.json) and is written into meta.scenario.
#   outDir defaults to output/engine-baseline/<scenarioName>   (relative to the repo root)
#   POI options are required (no default) and are forwarded to
#   baseline.BaselineRunner: --poi-srcip v --poi-srcport v --poi-dstip v
#   --poi-dstport v --poi-optype v, or --poi-file path
#
# The engine sources are compiled against src/main/java and baseline/BaselineRunner.java.
set -euo pipefail

BASELINE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROGQL_DIR="$(cd "$BASELINE_DIR/.." && pwd)"
ROOT_DIR="$(cd "$PROGQL_DIR/../.." && pwd)"

DB_NAME="${1:?用法: run-baseline.sh <场景名> [outDir] [POI 参数...]（POI 无默认值）}"
OUT_DIR_ARG="${2:-output/engine-baseline/${DB_NAME}}"
shift 2 2>/dev/null || shift $#
POI_ARGS=("$@")
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
   find src/main/java -name '*.java' ! -name 'BreadthFirstIterator.java' > "$BUILD_DIR/sources.txt"
   echo "baseline/BaselineRunner.java" >> "$BUILD_DIR/sources.txt"

   MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' javac -encoding UTF-8 -nowarn \
      -d "$BUILD_DIR/classes" -cp "$CP" "@$BUILD_DIR/sources.txt"
)

cd "$PROGQL_DIR"
MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' java \
   -cp "$BUILD_DIR/classes;$CP" baseline.BaselineRunner "$DB_NAME" "$OUT_DIR_ARG" ${POI_ARGS[@]+"${POI_ARGS[@]}"}
