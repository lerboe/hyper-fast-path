# hyper-fast-path

This is an eBPF-based fast path for [hyper](https://github.com/hyperium/hyper). It parses HTTP/1.1 and HTTP/2 in the kernel using [beeper](https://github.com/lerboe/beeper), and serves requests for static assets.

Serving static assets with the fast path improves the max throughput by **up to 2.8x**.

## Running the Example

Use the following example to run the HTTP server:
```bash
RUST_LOG=trace cargo run --bin example
```

Then, in another terminal, make a request to the server:
```bash
curl -vv http://127.0.0.1:8080/8KB.txt
```

In the logs of the server, you should find a line that indicates that the request was served directly from the kernel:
```
Served request
```

## Benchmarking

Run `script/bench-local.sh -n <name>` to benchmark the server locally, and `LOAD_GEN_HOST=OTHER_HOST script/bench-remote.sh -n <name>` to benchmark the server from another host.
Note that you need to install [oha](https://github.com/hatoo/oha) on the machine that generates the load.

You can visualize the results using `uv run script/vis.py <name>`
