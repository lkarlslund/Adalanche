# Analysis

Put your collected data in the configured datapath (`data` by default), either directly or in subfolders.

Adalanche loads and correlates recognized files automatically.

For multi-domain or forest analysis, keep each domain's AD object/GPO files in separate subfolders so merge logic can distinguish domains.

Example:

```bash
adalanche --datapath=data/domain1 collect activedirectory --domain=domain1
```

Recognized file extensions:
- `.localmachine.json` - Windows collector data
- `.gpodata.json` - Active Directory GPO data
- `.objects.msgp.lz4` - Active Directory object/schema data (MsgPack + LZ4)

Run analysis:

```bash
adalanche analyze
```

See options with:

```bash
adalanche analyze --help
```
