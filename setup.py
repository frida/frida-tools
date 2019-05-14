# -*- coding: utf-8 -*-

from setuptools import setup

setup(
    name="frida-tools",
    version="2.0.0",
    description="Frida CLI tools",
    long_description="CLI tools for [Frida](http://www.frida.re).",
    long_description_content_type="text/markdown",
    author="Frida Developers",
    author_email="oleavr@frida.re",
    url="https://www.frida.re",
    install_requires=[
        "colorama >= 0.2.7, < 1.0.0",
        "frida >= 12.5.3, < 13.0.0",
        "prompt-toolkit >= 2.0.0, < 3.0.0",
        "pygments >= 2.0.2, < 3.0.0"
    ],
    license="wxWindows Library Licence, Version 3.1",
    zip_safe=True,
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
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: JavaScript",
        "Topic :: Software Development :: Debuggers",
        "Topic :: Software Development :: Libraries :: Python Modules"
    ],
    packages=['frida_tools'],
    entry_points={
        'console_scripts': [
            "frida = frida_tools.repl:main",
            "frida-ls-devices = frida_tools.lsd:main",
            "frida-ps = frida_tools.ps:main",
            "frida-kill = frida_tools.kill:main",
            "frida-discover = frida_tools.discoverer:main",
            "frida-trace = frida_tools.tracer:main"
        ]
    }
)
