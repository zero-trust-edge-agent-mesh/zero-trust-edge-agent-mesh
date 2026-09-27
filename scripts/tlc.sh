#!/usr/bin/env bash
set -euo pipefail
if ! command -v java >/dev/null 2>&1; then echo "SKIP TLC: java not found"; exit 0; fi
JAR="${TLA2TOOLS_JAR:-../_tools/tla2tools.jar}"
if [ ! -f "$JAR" ]; then echo "SKIP TLC: tla2tools.jar not found"; exit 0; fi
java -XX:+UseParallelGC -cp "$JAR" tlc2.TLC -workers auto -config specs/EdgePolicyCRDT.cfg specs/EdgePolicyCRDT.tla
