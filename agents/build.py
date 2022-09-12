#!/usr/bin/env python3

import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path


def build(inputs, output_js, priv_dir):
    pkg_file = next((f for f in inputs if f.name == "package.json"))
    pkg_parent = pkg_file.parent
    entrypoint = inputs[0].relative_to(pkg_parent)

    for srcfile in inputs:
        subpath = Path(os.path.relpath(srcfile, pkg_parent))

        dstfile = priv_dir / subpath
        dstdir = dstfile.parent
        if not dstdir.exists():
            dstdir.mkdir()

        shutil.copyfile(srcfile, dstfile)

    npm = os.environ.get("NPM", "npm")
    try:
        subprocess.run([npm, "install"], capture_output=True, cwd=priv_dir, check=True)
    except Exception as e:
        message = "\n".join(
            [
                "",
                "***",
                f"Failed to build {inputs[0].name}:",
                "\t" + str(e),
                "This is most likely because Node.js is not installed.",
                "We need it for processing JavaScript code at build-time.",
                "Check PATH or set NPM to the absolute path of your npm binary.",
                "***\n",
            ]
        )
        raise EnvironmentError(message)

    frida_compile = Path("node_modules") / ".bin" / ("frida-compile" + script_suffix())

    subprocess.run([frida_compile, entrypoint, "-c", "-o", output_js], cwd=priv_dir, check=True)


def script_suffix():
    build_os = platform.system().lower()
    return ".cmd" if build_os == "windows" else ""


if __name__ == "__main__":
    paths = [Path(p).resolve() for p in sys.argv[1:]]
    inputs = paths[:-2]
    output_js = paths[-2]
    priv_dir = paths[-1]

    try:
        build(inputs, output_js, priv_dir)
    except Exception as e:
        print(e, file=sys.stderr)
        sys.exit(1)
