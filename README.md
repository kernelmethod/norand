# norand

## What is this?

`norand` is a command-line utility for Linux that replaces your processes'
sources of OS cryptographic randomness with your own. For instance, the default
behavior of `norand` is to hook all calls to the `getrandom` syscall so that
they instead fill buffers with bytes from `/dev/zero`:

```bash
$ ./target/release/norand run python3 -c "import os; print(os.urandom(16));"
b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
```

## ... Why would you make something like this?

This idea came to my feverish mind one night, and once it had I couldn't get any
sleep until I'd implemented it.

## How do I use it?

Start by cloning this repository and building `norand` with `cargo`:

```bash
$ git clone https://github.com/kernelmethod/norand.git
$ cargo build --release
```

You can then run the `norand` binary from `./target/release/norand`. `norand`
has two primary modes of operation:

- `norand run`: start a new process with a custom source of randomness.
- `norand attach`: attach `norand` to an existing PID. Note that you may need to
  either change the value of the `kernel.yama.ptrace_scope` kernel parameter or
  run `norand` with elevated privileges in order to run this subcommand.

For instance, in the following snippet, I read "random" bytes from
`/dev/urandom` under norand with `head -c 16 /dev/urandom`:

```bash
$ ./target/release/norand run head -c 16 /dev/urandom | xxd
00000000: 0000 0000 0000 0000 0000 0000 0000 0000  ................
```

In the next snippet, I attach `norand` to an already-existing process and then
detach it.

```bash
$ python3
Python 3.7.3 (default, Jan 22 2021, 20:04:44) 
[GCC 8.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import os
>>> os.getpid()
7575
>>> os.urandom(8)
b'O\xd2\x90\x0f\x9a \x18\xb1'
>>> 
[1]+  Stopped                 python3
$ ./target/release/norand attach 7575 &
[2] 7576
$ Attaching to Pid(7575)

$ fg %1
python3


>>> os.urandom(8)
b'\x00\x00\x00\x00\x00\x00\x00\x00'
```

Run `norand --help` for more details.

## Limitations

`norand` works by intercepting reads to `/dev/random` and `/dev/urandom`, as
well as calls to the `getrandom` syscall. There are many ways that programs can
generate randomness (cryptographic or not) without having to resort to the OS
randomness, such as creating a PRNG with a deterministic seed (e.g., the current
Unix timestamp), or by seeding a secure PRF with an external source of
cryptographic randomness (such as
[Lavarand](https://en.wikipedia.org/wiki/Lavarand)).

That said, it's a common pattern for applications to use the OS randomness to
generate an initial seed, and then use their own PRNG to generate more
randomness from that seed, which is where `norand` can reveal some interesting
behaviors. For instance, the [default
behavior](https://docs.python.org/3/using/cmdline.html#envvar-PYTHONHASHSEED) of
the Python interpreter is to use an initial OS randomness to seed hashes.
`norand` can make these hashes deterministic:

```bash
$ python3 -c 'print(hash("hello, world!"))'
-5770606422388815684
$ python3 -c 'print(hash("hello, world!"))'
-7221195102593754712
$ ./target/release/norand run python3 -c 'print(hash("hello, world!"))'
-6537003263111702803
$ ./target/release/norand run python3 -c 'print(hash("hello, world!"))'
-6537003263111702803
```

Here are some other limitations:

- `norand` is currently only able to attach itself to a single process, which
  means that any forked processes will be able to get access to OS randomness
  again.
- If a process opens a handle to `/dev/random` or `/dev/urandom` before `norand`
  attaches to it, it can still read from those devices through that handle after
  `norand` starts running (this is only relevant when you run `norand attach`).
- `norand` does not (currently) intercept reads to symlinks to `/dev/random` or
  `/dev/urandom`.
- There are probably some more obscure ways that a program can read from the OS
  randomness that aren't intercepted by `norand`. I'll patch these cases as I
  find them.
