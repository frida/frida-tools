project('frida-tools', 'c',
  version: '0.0.0',
)

subproject('frida-python')

python = import('python').find_installation()

subdir('agents')
subdir('frida_tools')
subdir('scripts')
subdir('completions')

pathsep = host_machine.system() == 'windows' ? ';' : ':'

test('frida-tools', python,
  args: ['-m', 'unittest', 'discover'],
  workdir: meson.current_source_dir(),
  env: {
    'PYTHONPATH': pathsep.join([
      meson.current_source_dir() / 'subprojects' / 'frida-python',
      meson.current_build_dir() / 'subprojects' / 'frida-python' / 'src',
    ]),
  },
  timeout: 30,
)
