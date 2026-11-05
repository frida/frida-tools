#!/usr/bin/env python3

import argparse
import os
import shlex
import subprocess


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("version", type=str)
    args = parser.parse_args()
    set_dist_version(args.version)


def set_dist_version(version: str) -> None:
    subprocess.run(
        [
            *shlex.split(os.environ["MESONREWRITE"]),
            "--sourcedir",
            os.environ["MESON_PROJECT_DIST_ROOT"],
            "kwargs",
            "set",
            "project",
            "/",
            "version",
            version,
        ],
        check=True,
    )


if __name__ == "__main__":
    main()
