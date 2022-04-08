# lavida-judger

Uses seccomp to limit syscall. Uses libseccomp for simplicity.

Requires cmake to compile and install.

## Usage

```sh
mkdir build
cd build
cmake ..
make
make install

lavidajudger-cli \
    --exec-path "" \
    --exec-args "arg1" "arg2" "arg3" "..." \
    --input-path "" \
    --output-path "" \
    --validater-path "" \
    --cpu-limit 1 \
    --real-limit 1 \
    --mem-limit $((256*1024*1024))
    --json
```

```sh
lavidajudger-cli --help
```

`--exec-path` must be provided.

If `--input-path` and `--output-path` are provided, it just compares contents of
`--output-path` and result of `--exec-path`. Can be used for normal judge.

If `--input-path` and `--validater-path` are provided, stdout of exec file
will be redirected to validater and validater will returns exitcode 0 if the
output is valid and returns something else if it is not. `--output-path` will be
ignored. Can be used for special judge.

If `--validater-path` is provided, stdout of validater will be stdin of
exec file and stdout of exec file will be stdin of validater.
Validater will returns exitcode 0 on success. Can be used for interactive judge.

### Validater

```cpp
#include <cstdio>

using namespace std;

// argv = { input_file_path, output_file_path, NULL }
// Use argv if you need.
int main(int argc, char* argv[]) {
    // stdin is stdout of exec file.
    // stdout will be stdin of exec file if input file is not provided.

    // do something

    // Return 0 on success, something else on failure.
    return 0;
}

```

## Todos

- [ ] docker?
- [ ] seccomp profile per languages.
