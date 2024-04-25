import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path


def main(argv: list[str]):
    npm = argv[1]
    paths = [Path(p).resolve() for p in argv[2:]]
    inputs = paths[:-2]
    output_js = paths[-2]
    priv_dir = paths[-1]

    try:
        build(npm, inputs, output_js, priv_dir)
    except Exception as e:
        print(e, file=sys.stderr)
        sys.exit(1)


def build(npm: Path, inputs: list[Path], output_js: Path, priv_dir: Path):
    pkg_file = next((f for f in inputs if f.name == "package.json"))
    pkg_parent = pkg_file.parent
    entrypoint = inputs[0].relative_to(pkg_parent)

    for srcfile in inputs:
        subpath = Path(os.path.relpath(srcfile, pkg_parent))

        dstfile = priv_dir / subpath
        dstdir = dstfile.parent
        if not dstdir.exists():
            dstdir.mkdir()

        shutil.copy(srcfile, dstfile)

    subprocess.run([npm, "install"], capture_output=True, cwd=priv_dir, check=True)

    frida_compile = priv_dir / "node_modules" / ".bin" / f"frida-compile{script_suffix()}"
    subprocess.run([frida_compile, entrypoint, "-c", "-o", output_js], cwd=priv_dir, check=True)


def script_suffix() -> str:
    return ".cmd" if platform.system() == "Windows" else ""


if __name__ == "__main__":
    main(sys.argv)
