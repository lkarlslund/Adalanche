# Adalanche Query Language (AQL)

AQL queries traverse the internal graph by selecting start nodes, traversing edges, and matching target nodes.

## AQL Syntax

Note: `[]` is literal syntax. In the grammar below, optional parts use `%...%`, and repeatable parts use `%%...%%`.

```text
aql = query %%UNION query%%

query = %searchtype% %label:%(nodefilter)-[edgefilter]%{n,m}%->%label:%(nodefilter)%%-[edgefilter]->%label:%(nodefilter)%%
```

## Graph search types (searchtype)

WALK, TRAIL and ACYCLIC traverse shortest-path-first. REACH finds all routes at once.

A route acts as the nearest account before each step: entering a user or computer makes it the one acting, and groups and other objects keep the account before them. WALK, TRAIL and ACYCLIC leave out a path when an ACL deny refuses one of its steps every edge type to the account acting there; an edge from a group can be refused to members who are also in a denied group. A path starting at a group stands for every member, and nothing is refused to it. Paths that change direction are not checked.

| Keyword | Description |
|---------|-------------|
| WALK | All traversals allowed, including loops (not recommended). |
| TRAIL | A path never uses an edge twice, and edges already in the result graph are not reused. |
| ACYCLIC | A path never visits a node twice, and nodes already in the result graph are not reused (default). |
| REACH | Every edge that lies on at least one route from a start node to an end node within the query's rules and the depth limit. Routes may revisit nodes. The result does not depend on search order. Over the node limit, only the shortest routes that fit are kept. For a query of one step, an edge's flow is the number of routes through it, and a route an ACL deny refuses to the account using it is not counted: an edge from a group can be refused to members who are also in a denied group. Other REACH queries give every edge a flow of 1. |

### Which REACH routes to keep

REACH keeps every route by default. For a query of one step in one direction, with no path node filter and at most one edge required, two keywords after REACH keep fewer:

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

## Edge filters

Edge filters define which edge types are traversed. Empty filter (`[]`) means default edge behavior.

| Example | Edge filter |
|---------|-------------|
| Group memberships, depth 1-5 | `[MemberOfGroup,MemberOfGroupIndirect]{1,5}` |
| Next edge must be 100 probability | `[probability=100]` |
| Match two of X, Y, Z | `[X,Y,Z,match=2]` |
| Optional edge X | `[X]{0,1}` |
| Don't match X | `[X,match=0]` |
