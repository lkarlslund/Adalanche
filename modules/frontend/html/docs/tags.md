# Tags

Tags mark nodes and edges. Analysis sets some itself (system tags): `hvt` on high value targets, `account_active` on accounts in use, and more. In the enterprise version\* users can add their own tags too, to nodes and to edges, and they are kept: they hold across restarts and snapshot loads, and queries see them at once.

\* Enterprise version, with the `tags` license feature.

## Using tags in queries

| Query | Finds |
|-------|-------|
| `(tag=hvt)` | nodes tagged `hvt`, by analysis or a user |
| `[edgetag=accepted]`\* | only edges tagged `accepted` |
| `[!edgetag=accepted]`\* | only edges not tagged `accepted` |

A typical use is marking edges you have reviewed and accepted, and leaving them out of an attack path search:

```text
start:(tag=hvt)<-[!edgetag=accepted]{1,8}-end:(type=Person)
```

`tag=` inside edge brackets is a different thing: it selects edge *types* by their tags, such as `[tag=Pivot]`. See [AQL](aql.md).

## Node tags\*

Right-click a node and choose *Edit tags…*, or use the Tags section of a node's details window. Tags users added are highlighted, each with a button to remove it; system tags have none, as they can not be removed. Removing all of a node's added tags puts it back to what analysis gives it.

Node tags are up to 64 letters, digits, `_ . : -`, starting with a letter or digit.

## Edge tags\*

Right-click an edge and choose *Edit edge tags…*, or use the Tags section of the edge details window. A tag goes on one edge type from one node to another (such as the `WriteDACL` edge from a group to a user), or on every edge between the two nodes (*All edges between them*), including edge types a later load adds. The window has a row for each, with its tags and a field to add one.

Edge tags are up to 64 letters, digits, `_` or `-`, starting with a letter or `_`, so queries can name them.

## How tags are kept\*

Tags users add are kept in the persistence database in the data path, and applied again after analysis each time the graph loads. A node is kept by its key: its distinguishedName, or else its objectGUID, or else its objectSid; an edge by the keys of its two nodes and its edge type. So a node with none of these, or whose SID is not unique (such as a built-in group, which each machine has its own of), can not be tagged, nor can its edges. Tags kept for a node or edge a load does not have, such as one since deleted or moved, stay, listed as not found, until they are forgotten.

Users can only remove tags users added. If analysis later sets a tag a user added, it becomes a system tag.

## API\*

A node is named by `nodeid=<id>` or `key=<key>`; an edge by `from=<id>&to=<id>` or `fromkey=<key>&tokey=<key>`, and where it matters `edge=<edge type>`, or `*` for every edge between the nodes.

| Request | Does |
|---------|------|
| `GET /api/tags` | every node with added tags, and whether the loaded graph has it |
| `GET /api/tags/node?nodeid=…` | a node's tags: `tags`, which users `added`, which are `system`, and whether they can be kept (`editable`, or `reason`) |
| `POST /api/tags/node?nodeid=…` | change them: `{"add": ["crownjewel"], "remove": ["reviewed"], "reset": false}`; removing a system tag is an error, and then nothing changes; `reset` first removes every added tag |
| `DELETE /api/tags/node?key=…` | remove every added tag, also for a node not in the loaded graph |
| `GET /api/tags/edges` | every edge with added tags, with its `id`, and whether the loaded graph has it |
| `GET /api/tags/edge?from=…&to=…` | the tags on the edges between two nodes, per edge type and for `*` |
| `POST /api/tags/edge?from=…&to=…&edge=WriteDACL` | change one edge type's (or `*`'s) tags, as for nodes |
| `DELETE /api/tags/edge?from=…&to=…&edge=*` | remove every added tag there; `?id=<id>` for an edge not in the loaded graph |

## MCP\*

The `tags` tool reads tags (actions `get` and `list`), and `tag_edit` changes them (actions `set` and `forget`), for nodes (`id`) and edges (`from` and `to`). See [MCP](mcp.md).
