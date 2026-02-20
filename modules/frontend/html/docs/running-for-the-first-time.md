# Running Adalanche for the first time

## Run with sample data

If you want to test safely first, use sample data from [adalanche-sampledata](https://github.com/lkarlslund/adalanche-sampledata). Follow the instructions in that repository.

## Quick start / Easy mode

On a Windows domain-joined machine, running Adalanche with no arguments often works because autodetection is enabled.

For more advanced use, collect explicitly first, then analyze. Data files are written to `data` by default (or use `--datapath dir`).

Use command help for details:

```bash
adalanche --help
adalanche collect --help
adalanche analyze --help
```

## Run with your own data

See [collecting data from Active Directory](collecting-active-directory.md), [collecting data from Windows machines](collecting-windows-machines.md), and [analysis](analysis.md).
