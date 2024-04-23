# -*- coding: utf-8 -*-

import glob
from pathlib import Path

from setuptools import setup


PACKAGE_DIR = Path(__file__).resolve().parent


agents = []
agents_builddir = PACKAGE_DIR / "build" / "agents"
if agents_builddir.exists():
    for child in agents_builddir.iterdir():
        if child.is_dir():
            agents += [str(f) for f in child.glob("*_agent.js")]

setup(
    name="frida-tools",
    version="12.3.0",
    description="Frida CLI tools",
    long_description="CLI tools for [Frida](https://frida.re).",
    long_description_content_type="text/markdown",
    author="Frida Developers",
    author_email="oleavr@frida.re",
    url="https://frida.re",
    install_requires=[
        "colorama >= 0.2.7, < 1.0.0",
        "frida >= 16.0.9, < 17.0.0",
        "prompt-toolkit >= 2.0.0, < 4.0.0",
        "pygments >= 2.0.2, < 3.0.0",
    ],
    license="wxWindows Library Licence, Version 3.1",
    zip_safe=False,
    keywords="frida debugger dynamic instrumentation inject javascript windows macos linux ios iphone ipad android qnx",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Environment :: MacOS X",
        "Environment :: Win32 (MS Windows)",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved",
        "Natural Language :: English",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: JavaScript",
        "Topic :: Software Development :: Debuggers",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    packages=["frida_tools"],
    package_data={
        "frida_tools": agents,
    },
    entry_points={
        "console_scripts": [
            "frida = frida_tools.repl:main",
            "frida-ls-devices = frida_tools.lsd:main",
            "frida-ps = frida_tools.ps:main",
            "frida-kill = frida_tools.kill:main",
            "frida-ls = frida_tools.ls:main",
            "frida-rm = frida_tools.rm:main",
            "frida-pull = frida_tools.pull:main",
            "frida-push = frida_tools.push:main",
            "frida-discover = frida_tools.discoverer:main",
            "frida-trace = frida_tools.tracer:main",
            "frida-itrace = frida_tools.itracer:main",
            "frida-join = frida_tools.join:main",
            "frida-create = frida_tools.creator:main",
            "frida-compile = frida_tools.compiler:main",
            "frida-apk = frida_tools.apk:main",
        ]
    },
)
