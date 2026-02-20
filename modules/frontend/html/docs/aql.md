# Adalanche Query Language (AQL)

AQL queries traverse the internal graph by selecting start nodes, traversing edges, and matching target nodes.

## AQL Syntax

Note: `[]` is literal syntax. In the grammar below, optional parts use `%...%`, and repeatable parts use `%%...%%`.

```text
aql = query %%UNION query%%

query = %searchtype% %label:%(nodefilter)-[edgefilter]%{n,m}%->%label:%(nodefilter)%%-[edgefilter]->%label:%(nodefilter)%%
```

## Graph search types (searchtype)

Traversal is shortest-path-first.

| Keyword | Description |
|---------|-------------|
| WALK | All traversals allowed, including loops (not recommended). |
| TRAIL | Already-used edges in current result graph are not reused. |
| ACYCLIC | Already-used nodes in current result graph are not reused (default). |
| SIMPLE | Neither reused nodes nor reused edges are allowed. |

## Labels

You can label node sets with `label:` before node filters. The UI highlights `start` and `end` labels specially.

## Node filters (nodefilter)

Node filters use LDAP-like syntax with Adalanche extensions:

```text
name:(ldapfilter) ORDER BY attribute SKIP n LIMIT m
```

Use `LIMIT` to reduce large start-node sets.

### LDAP filter extensions

Supported extensions include:
- case-insensitive attribute names
- existence checks (`member=*`)
- case-insensitive string equality matching
- numeric comparisons: `<`, `<=`, `>`, `>=`
- glob matching when value contains `?` or `*`
- regexp matching with `/.../` syntax
- extensible matches:
  - `1.2.840.113556.1.4.803` (`:and:`)
  - `1.2.840.113556.1.4.804` (`:or:`)
  - `1.2.840.113556.1.4.1941` (`:dnchain:`)
- custom extensible matches:
  - `count`
  - `length`
  - `since`
  - `timediff`
  - `caseExactMatch`
- synthetic attributes:
  - `_limit`
  - `_random100`
  - `out` / `_canpwn`
  - `in` / `_pwnable`
- attribute-name globbing (`*name=something`, or `*` for all attributes)

## Edge filters

Edge filters define which edge types are traversed. Empty filter (`[]`) means default edge behavior.

| Example | Edge filter |
|---------|-------------|
| Group memberships, depth 1-5 | `[MemberOfGroup,MemberOfGroupIndirect]{1,5}` |
| Next edge must be 100 probability | `[probability=100]` |
| Match two of X, Y, Z | `[X,Y,Z,match=2]` |
| Optional edge X | `[X]{0,1}` |
| Don't match X | `[X,match=0]` |
