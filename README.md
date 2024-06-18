# verke-chunking-analysis

This is a tool that process a folder of generated _PC traces_ from a Geth [custom live tracer](https://github.com/jsign/go-ethereum/commit/152f63f98f94ecc2e189a2b74bdac091effccb89).

You can read more about a mainnet analysis done with this tool looking at [this document](https://hackmd.io/@jsign/verkle-code-mainnet-chunking-analysis).

## Run

You can run it with:

```bash
$ go run ./... --tracespath /data/pctraces_live
Loading contract bytecodes... OK
Processing traces... 0%
Processing traces... 12%
Processing traces... 24%
Processing traces... 37%
Processing traces... 49%
Processing traces... 62%
Processing traces... 74%
Processing traces... 87%
Processing traces... 99%
```

## LICENSE

MIT
