# Frida CLI tools

CLI tools for [Frida](https://frida.re).

### Installing Fish completions

Currently there is no mechanism to install Fish completions through the setup.py
script so if you want to have completions in Fish you will have to install it
manually. Unless you've changed your XDG_CONFIG_HOME location, you should just
copy the completion file into `~/.config/fish/completions` like so:

    cp completions/frida.fish ~/.config/fish/completions

### frida-itrace file format

File starts with a 4-byte magic: "ITR2"

Then, following that, there are two different types of records, MESSAGE and
CHUNK. Each record starts with a big-endian uint32 specifying the type of
record, where 1 means MESSAGE, 2 means CHUNK.

#### MESSAGE

- `length`: uint32 (big-endian)
- `message`: JSON, UTF-8 encoded
- `data_size`: uint32 (big-endian)
- `data_values`: uint8[data_size]

There are two different kinds of MESSAGEs:

- "itrace:lost": Signals that records were dropped because the buffer was
  full. The JSON portion contains the total number of records lost so far.
- "itrace:end": Signals that the endpoint was reached, when specifying a range
  with an end address included.

#### CHUNK

- `size`: uint32 (big-endian)
- `data`: uint8[size]

The CHUNK records combine to the stream of trace records and events written to
frida-itrace's ringbuffer, as documented in its
[buffer format](https://github.com/frida-packages/frida-itrace#buffer-format).
