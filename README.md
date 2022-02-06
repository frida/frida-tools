# Frida CLI tools

CLI tools for [Frida](https://frida.re).

### Making dev changes to frida-tools

**You do not need to build this repo** in order to make changes (for a pull
request, or for local development).

Simply set your PYTHONPATH environment variable to wherever you've cloned
this repo to.

For example, on Windows, assuming you clone to `C:\src`:

    git clone https://github.com/frida/frida-tools.git
    cd frida-tools
    SET PYTHONPATH=C:\src\frida-tools

Now when you run frida.exe, these scripts and any changes you make will be
referenced instead!

### Loading your custom frida-java-bridge

Add the following lines to `agents/tracer/agent.ts`:

    Object.defineProperty(global, 'Java', { value: require('frida-java-bridge') });

Run live reload:

    cd agents/tracer; npm link frida-java-bridge; npm run watch

Now you can:

1. make changes to `agents/tracer/node_modules/frida-java-bridge/*`
2. run your frida-tools from this repo and see how it works!
