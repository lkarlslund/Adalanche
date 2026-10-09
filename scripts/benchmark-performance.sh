#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$repo_root"

go test ./modules/engine -run '^$' -bench 'Benchmark(EdgeImporterCommit|FindAdjacentSIDUniqueHit|FindOrAddAdjacentSIDFound.*|FrozenGraphFind|FrozenGraphFindTwo|FrozenGraphFindAdjacentSID|GraphIterate|GraphIterateStable|GraphIterateParallelStable|FrozenGraphIterateLarge|FreezeLarge|FrozenGraphIterateEdgesLarge|CalculateGraphValuesSyntheticIndexedGraph|CalculateGraphValuesSyntheticFrozenGraph|NodeGet|AttributesAndValuesGet|NodePatchSetApply|NodePatchSetSetFlex|NodeSetFlex|NodeSet|ReindexObject)' -benchmem
go test ./modules/integrations/localmachine/analyze -run '^$' -bench . -benchmem
