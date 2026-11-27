# network_processor

A C11 network packet processor. The `libnp` library parses Ethernet II frames
carrying IPv4 with TCP or UDP headers, and the `network_processor` CLI prints a
one-line summary per frame.

## Build and test

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

## Usage

`network_processor` reads one hex-encoded Ethernet frame per line from a file
or stdin:

```sh
./build/network_processor tests/data/sample_frames.hex
cat tests/data/sample_frames.hex | ./build/network_processor
```

Example output:

```
frame 1: 192.168.1.10:51234 -> 10.0.0.1:443 proto=tcp payload=5 checksum=ok
frame 2: 192.168.1.10:40000 -> 10.0.0.1:53 proto=udp payload=10 checksum=ok
```

The program exits with status 1 if any line is not valid hex.
