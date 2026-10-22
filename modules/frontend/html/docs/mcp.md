# MCP

Adalanche serves the [Model Context Protocol](https://modelcontextprotocol.io) at `/mcp` on the web service, so AI assistants can explore the graph: find nodes, explain how one can reach another and why, and run queries. Add it to a client as a streamable HTTP server, such as `http://127.0.0.1:8080/mcp`.

The server is stateless, so clients keep working when Adalanche restarts. Node ids (`123@k3f9`) only hold for one load of the graph; to name a node across loads, use its key (`objectSid=S-1-5-…`), which every node carries and every tool takes in place of an id. Passwords, hashes and keys are never returned.

## Tools

Tools are grouped by subject. Each takes an `action` argument and the fields that action takes; the tool's description lists them. Tools that only read are marked read-only, so clients may run them without asking; changes go through tools of their own.

| Tool | Actions | |
|------|---------|---|
| `graph` | `status`, `schema` | whether data is loaded; node types, edge types and attributes |
| `nodes` | `find`, `details`, `neighbors`, `acl` | find nodes by filter; a node's attributes, edges (with `causes`, why each exists) and ACL |
| `routes` | `explain`, `edge_details`, `reach_summary` | how one node reaches another, and why each edge on the way exists |
| `aql` | `run`, `validate`, `saved_list`, `saved_run` | [AQL](aql.md) queries |
| `docs` | `list`, `get` | this documentation |
| `impact`\* | `get`, `rank` | impact and exposure scores |
| `tiering`\* | `get`, `violations` | tier assignments and violations |
| `tags`\* | `get`, `list` | tags on nodes and edges, see [Tags](tags.md) |
| `tag_edit`\* | `set`, `forget` | add tags, and remove tags users added (changes the data) |

\* Enterprise version, with the license features they need.

For example, to find the high value targets and see what reaches the first one:

```json
{"name": "nodes", "arguments": {"action": "find", "filter": "(tag=hvt)"}}
{"name": "routes", "arguments": {"action": "explain", "from": {"id": "objectSid=S-1-5-21-…-1104"}, "to_filter": "(tag=hvt)"}}
```

The documentation is also offered as resources, `adalanche://docs/<name>`, as is the schema.
