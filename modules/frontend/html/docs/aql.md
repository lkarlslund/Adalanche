# Adalanche Query Language (AQL)

In order to query the internal Adalanche graph, you express your targets by issuing a search for starting nodes traversing zero to many edges and ending at a certain node.

Searches for nodes are defined more or less using LDAP query syntax, so the same options and requirements as when using eg. PowerShell with LDAP filters apply. Adalanche offers some more filters and expressions though in addition to standard AD LDAP filters.

## AQL Syntax

(nodefilter)-[edgefilter]{n,m}->(nodefilter)

## Node filters

A node filter tells the query engine how to find targets that are either a starting, middle or ending node. You can use basic LDAP syntax queryes, with these additional extensions:

<code>
name:(ldapfilter) ORDER BY attribute SKIP n LIMIT m
</code>

The name allows you to tag a group of nodes with a name, which currently is just used for highlighting the nodes in the UI, using the names "start" and "end". Later on this will become more useful for the queries themselves.

You might get too many results from a query - limit the selection of starting nodes with LIMIT 10 to just get the first 10 nodes (see LDAP queries below)

## Edge filters

The edge filters allow you to specify one or more edge types that it needs to match in order to continue the search. If you don't specify anything (using blank filter <code>[]</code>), then Adalanche will use default edges, require at least 1 match, only traverse one edge and have no requirements for probabilities.

| Example | Edge filter |
|---------|-------------|
| Group memberships, depth 1-5 | [MemberOfGroup,MemberOfGroupIndirect]{1,5} |
| Next edge must have a of 100 | [probability=100] |
| Match two of X, Y and Z | [X,Y,Z,match=2] |
| Optional edge X | [X]{0,1} |
| Don't match X | [X,match=0] |

