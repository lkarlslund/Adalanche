# Adalanche Query Language (AQL)

AQL queries traverse the internal graph by selecting start nodes, traversing edges, and matching target nodes.

## AQL Syntax

Note: `[]` is literal syntax. In the grammar below, optional parts use `%...%`, and repeatable parts use `%%...%%`.

```text
aql = query %%UNION query%%

query = %searchtype% %label:%(nodefilter)-[edgefilter]%{n,m}%->%label:%(nodefilter)%%-[edgefilter]->%label:%(nodefilter)%%
```

## Graph search types (searchtype)

A query with no search-type keyword uses **REACH** (and, when the query is a single step in one direction, **REACH CHEAPEST** — one route per start/end pair). REACH finds every edge on a route at once, without enumerating paths, so it is polynomial and bounded in memory: it is the right choice for "how can A reach B".

WALK, TRAIL and ACYCLIC instead enumerate individual paths and traverse shortest-path-first. Path enumeration grows exponentially with depth and fan-out, so a broad query such as `ACYCLIC start:(type=Machine)-[]{1,10}->end:(...)` can exhaust memory. Use them only with tight node filters and a small depth, and ask for them by name; otherwise prefer REACH.

A route acts as the nearest account before each step: entering a user or computer makes it the one acting, and groups and other objects keep the account before them. WALK, TRAIL and ACYCLIC leave out a path when an ACL deny refuses one of its steps every edge type to the account acting there; an edge from a group can be refused to members who are also in a denied group. A path starting at a group stands for every member, and nothing is refused to it. Paths that change direction are not checked.

| Keyword | Description |
|---------|-------------|
| WALK | Enumerates paths with all traversals allowed, including loops (not recommended; can be very expensive). |
| TRAIL | Enumerates paths; a path never uses an edge twice, and edges already in the result graph are not reused. Can be very expensive. |
| ACYCLIC | Enumerates paths; a path never visits a node twice, and nodes already in the result graph are not reused. Can be very expensive on deep, broad queries. |
| REACH | The default. Every edge that lies on at least one route from a start node to an end node within the query's rules and the depth limit. Routes may revisit nodes. The result does not depend on search order. Over the node limit, only the shortest routes that fit are kept. For a query of one step, an edge's flow is the number of routes through it, and a route an ACL deny refuses to the account using it is not counted: an edge from a group can be refused to members who are also in a denied group. Other REACH queries give every edge a flow of 1. |

### Which REACH routes to keep

Written as a bare `REACH`, it keeps every route. For a query of one step in one direction, with at most one edge required and no `via` counts (`through`, `avoid`, `via 0` and `via all` are fine), two keywords after REACH keep fewer. **REACH CHEAPEST is what a query with no search-type keyword uses** when the query has that single-step shape; a multi-step or bidirectional query with no keyword keeps every route (plain REACH):

| Keyword | Keeps |
|---------|-------|
| REACH CHEAPEST | One route between each start and end node: the fewest edges, then the most likely (the product of edge probabilities), then a fixed node order. A route a deny refuses to the account acting on it is replaced by the cheapest one no deny refuses, or left out. An edge's flow is the number of start and end pairs whose route uses it, so removing it takes away that many routes. With too many pairs to search each, one route is kept for each node on the larger side, from the nearest node on the smaller side, and the result says so. |
| REACH SHORTEST | Every shortest route between each start and end node. Flow counts the routes no deny refuses over the edges kept, as for REACH. |

Example: `REACH CHEAPEST start:(objectSid=S-1-5-21-*-512)<-[]{1,8}-end:(type=Person)` draws one route from each user that can become a domain admin.

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

### Edge subqueries (`out`, `in`)

`(out=Edge,(filter))` matches a node with an outgoing edge of that type to a node matching the filter; `in=` is the same for incoming edges, `*` matches any edge type, and the filter is optional. The subquery is checked against the whole graph, once, before any search starts.

Any edge of the type matches, whatever its probability. To only count likely edges, put a comparator and a probability after the edge name:

| Example | Matches |
|---------|---------|
| `(out=ResetPassword,(name=DC01))` | can reset DC01's password, by any edge however unlikely |
| `(out=ResetPassword>=100,(name=DC01))` | only by an edge of probability 100 |
| `(in=*>50)` | has some incoming edge more likely than 50 |

This matters most inside a negation such as `avoid (out=…)`: there, counting an unlikely edge rules out more nodes and so hides routes.

## Edge filters

Edge filters define which edge types are traversed. Empty filter (`[]`) means default edge behavior.

| Example | Edge filter |
|---------|-------------|
| Group memberships, depth 1-5 | `[MemberOfGroup,MemberOfGroupIndirect]{1,5}` |
| Next edge must be 100 probability | `[probability=100]` |
| Match two of X, Y, Z | `[X,Y,Z,match=2]` |
| Optional edge X | `[X]{0,1}` |
| Don't match X | `[X,match=0]` |

## Transit constraints (via, through, avoid)

The nodes a route passes through within an edge step are its **transit nodes**: every node on the step except where it starts and where it lands. The start and end of a query (and a named node between two steps) are never transit nodes, so they need not meet a step's transit constraints. That way a node you rule out as a stepping stone can still be a start or end node.

Transit constraints go inside the edge brackets, separated by commas, alongside edge types and each other. Each one counts the transit nodes that match a node filter and puts a bound on the count:

| Constraint | Means |
|------------|-------|
| `avoid (F)` | no transit node matches F (the same as `via 0 (F)`) |
| `through (F)` | every transit node matches F (the same as `via all (F)`) |
| `(F)` | the same as `through (F)` |
| `via N (F)` | exactly N transit nodes match F |
| `via >=N (F)` | at least N; `>`, `<=`, `<` and `=` work too |
| `via all (F)` | every transit node matches F, however many hops the route takes |
| `via all but N (F)` | every transit node matches F except at most N |

`via all but N` allows at most N exceptions, so a route with none also qualifies: `via all` is `via all but 0`.

| Example | Routes kept |
|---------|-------------|
| `[via >=1 (type=Group)]{1,8}` | pass through at least one group |
| `[via <=1 (type=Group)]{1,8}` | pass through at most one group |
| `[avoid (name=DC01)]{1,8}` | never pass through DC01 |
| `[via >=1 (type=Group), avoid (name=DC01)]{1,8}` | both |
| `[via all but 1 (tag=tier0)]{1,8}` | stay in tier 0, with at most one step outside it |
| `[MemberOfGroup, through (type=Group)]{1,5}` | group memberships, only ever passing through groups |

For example, to see what can still reach DCsync when nodes that can reset DC01's password, by an edge certain to work, are taken out as stepping stones:

```text
start:(&(name=DCsync)(type=Callable-Service-Point))<-[avoid (out=ResetPassword>=100,(name=DC01))]{1,8}-end:(|(type=Person)(type=Group))
```

A count is of hops through matching nodes. REACH and WALK allow a route to pass the same node twice, and then it is counted twice; ACYCLIC never revisits a node, so there each matching node counts once. With several steps, each step has its own constraints and its own count.

Search cost: `avoid`, `through`, `via 0` and `via all` only decide which nodes a route may pass through, so they cost nothing extra and work with every search type, including REACH CHEAPEST and SHORTEST. A real count (`via 1`, `via >=2`, `via all but 1` and so on) depends on the whole route: REACH tracks it alongside each node, which multiplies its work by the number of count values it can tell apart (two for `via >=1`, three for `via <=2`, and so on, multiplied together for several counts in one step). A query whose counts would make REACH track too much is refused with an error rather than run. REACH CHEAPEST and SHORTEST cannot keep counts, so a query with one uses plain REACH by default, and asking for CHEAPEST or SHORTEST with one is an error.
