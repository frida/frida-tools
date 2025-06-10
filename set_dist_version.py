#!/usr/bin/env python3

import argparse
import os
import shlex
import subprocess
import sys
from typing import List


def main(argv: List[str]) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("version", type=str)
    args = parser.parse_args()
    set_dist_version(args.version)


def set_dist_version(version: str) -> None:
    """
    Used to replace the version in the meson.build file when building a dist build
    """
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
    print(version)
    return


if __name__ == "__main__":
    main(sys.argv)
