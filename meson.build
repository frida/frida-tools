project('frida-tools', 'c',
  version: run_command(find_program('python3'), meson.global_source_root() / 'releng' / 'frida_version.py',
    capture: true,
    check: true).stdout().strip(),
  meson_version: '>=1.1.0',
)

meson.add_dist_script(find_program('python3'), files('set_dist_version.py'), meson.project_version())

python = import('python').find_installation()

node = find_program('node', version: '>=18.0.0', native: true, required: false)
if not node.found()
  error('Need Node.js >= 18.0.0 to process JavaScript code at build time')
endif
npm = find_program('npm', native: true, required: false)
if not npm.found()
  error('Need npm to process JavaScript code at build time')
endif

subdir('agents')
subdir('bridges')
subdir('apps')
subdir('frida_tools')
if get_option('scripts')
  subdir('scripts')
endif
subdir('completions')

test('frida-tools', python,
  args: ['-m', 'unittest', 'discover'],
  workdir: meson.current_source_dir(),
  timeout: 30,
)
