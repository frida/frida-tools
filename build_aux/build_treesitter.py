#!/usr/bin/env python3

import os

from tree_sitter import Language


def build() -> None:
    Language.build_library(
        os.path.join("frida_tools", "treesitter.so"),
        [
            os.path.join("vendor", "tree-sitter-javascript"),
        ],
    )


if __name__ == "__main__":
    build()
