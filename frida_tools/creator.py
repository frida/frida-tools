# -*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function


def main():
    import codecs
    import os
    import platform

    import frida

    from frida_tools.application import ConsoleApplication

    class CreatorApplication(ConsoleApplication):
        def _usage(self):
            return "%(prog)s [options] -t agent|cmodule"

        def _add_options(self, parser):
            default_project_name = os.path.basename(os.getcwd())
            parser.add_argument("-n", "--project-name", help="project name", dest="project_name", default=default_project_name)
            parser.add_argument("-o", "--output-directory", help="output directory", dest="outdir", default=".")
            parser.add_argument("-t", "--template", help="template file: cmodule|agent", dest="template", default=None)

        def _initialize(self, parser, options, args):    
            args = parser.parse_args()
            if not args.template:
                parser.error("template must be specified")
            impl = getattr(self, "_generate_" + args.template, None)
            if impl is None:
                parser.error("unknown template type")
            self._generate = impl

            self._project_name = options.project_name
            self._outdir = options.outdir

        def _needs_device(self):
            return False

        def _start(self):
            (assets, message) = self._generate()

            outdir = self._outdir
            for name, data in assets.items():
                asset_path = os.path.join(outdir, name)

                asset_dir = os.path.dirname(asset_path)
                try:
                    os.makedirs(asset_dir)
                except:
                    pass

                with codecs.open(asset_path, 'wb', 'utf-8') as f:
                    f.write(data)

                self._print("Created", asset_path)

            self._print("\n" + message)

            self._exit(0)

        def _generate_agent(self):
            assets = {}

            assets["package.json"] = """{{
  "name": "{project_name}-agent",
  "version": "1.0.0",
  "description": "Frida agent written in TypeScript",
  "private": true,
  "main": "agent/index.ts",
  "scripts": {{
    "prepare": "npm run build",
    "build": "frida-compile agent/index.ts -o _agent.js -c",
    "watch": "frida-compile agent/index.ts -o _agent.js -w"
  }},
  "devDependencies": {{
    "@types/frida-gum": "^16.2.0",
    "@types/node": "^14.14.10",
    "frida-compile": "^10.0.0"
  }}
}}
""".format(project_name=self._project_name)

            assets["tsconfig.json"] = """{
  "compilerOptions": {
    "target": "es2020",
    "lib": ["es2020"],
    "allowJs": true,
    "noEmit": true,
    "strict": true,
    "esModuleInterop": true
  }
}
"""

            assets["agent/index.ts"] = """import { log } from "./logger";

const header = Memory.alloc(16);
header
    .writeU32(0xdeadbeef).add(4)
    .writeU32(0xd00ff00d).add(4)
    .writeU64(uint64("0x1122334455667788"));
log(hexdump(header.readByteArray(16) as ArrayBuffer, { ansi: true }));

Process.getModuleByName("libSystem.B.dylib")
    .enumerateExports()
    .slice(0, 16)
    .forEach((exp, index) => {
        log(`export ${index}: ${exp.name}`);
    });

Interceptor.attach(Module.getExportByName(null, "open"), {
    onEnter(args) {
        const path = args[0].readUtf8String();
        log(`open() path="${path}"`);
    }
});
"""

            assets["agent/logger.ts"] = """export function log(message: string): void {
    console.log(message);
}
"""

            assets[".gitignore"] = "/node_modules/\n"

            message = """Run `npm install` to bootstrap, then:
- Keep one terminal running: npm run watch
- Inject agent using the REPL: frida Calculator -l _agent.js
- Edit agent/*.ts – REPL will live-reload on save

Tip: Use an editor like Visual Studio Code for code completion, inline docs,
     instant type-checking feedback, refactoring tools, etc.
"""

            return (assets, message)

        def _generate_cmodule(self):
            assets = {}

            assets["meson.build"] = """project('{project_name}', 'c',
  default_options: 'buildtype=release',
)

shared_module('{project_name}', '{project_name}.c',
  name_prefix: '',
  include_directories: include_directories('include'),
)
""".format(project_name=self._project_name)

            assets[self._project_name + ".c"] = """#include <gum/guminterceptor.h>

static void frida_log (const char * format, ...);
extern void _frida_log (const gchar * message);

void
init (void)
{
  frida_log ("init()");
}

void
finalize (void)
{
  frida_log ("finalize()");
}

void
on_enter (GumInvocationContext * ic)
{
  gpointer arg0;

  arg0 = gum_invocation_context_get_nth_argument (ic, 0);

  frida_log ("on_enter() arg0=%p", arg0);
}

void
on_leave (GumInvocationContext * ic)
{
  gpointer retval;

  retval = gum_invocation_context_get_return_value (ic);

  frida_log ("on_leave() retval=%p", retval);
}

static void
frida_log (const char * format,
           ...)
{
  gchar * message;
  va_list args;

  va_start (args, format);
  message = g_strdup_vprintf (format, args);
  va_end (args);

  _frida_log (message);

  g_free (message);
}
"""

            assets[".gitignore"] = "/build/\n"

            session = frida.attach(0)
            script = session.create_script("rpc.exports.getBuiltins = () => CModule.builtins;")
            script.load()
            builtins = script.exports.get_builtins()
            script.unload()
            session.detach()

            for name, data in builtins['headers'].items():
                assets["include/" + name] = data

            system = platform.system()
            if system == 'Windows':
                module_extension = 'dll'
            elif system == 'Darwin':
                module_extension = 'dylib'
            else:
                module_extension = 'so'

            cmodule_path = os.path.join(self._outdir, "build", self._project_name + "." + module_extension)

            message = """Run `meson build && ninja -C build` to build, then:
- Inject CModule using the REPL: frida Calculator -C {cmodule_path}
- Edit *.c, and build incrementally through `ninja -C build`
- REPL will live-reload whenever {cmodule_path} changes on disk
""".format(cmodule_path=cmodule_path)

            return (assets, message)

    app = CreatorApplication()
    app.run()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
