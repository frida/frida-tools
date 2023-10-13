project('frida-tools', 'c', version: '1.0.0')

python = get_option('python')
if python == ''
  python_program = find_program('python3', required: false)
  if python_program.found()
    python = python_program.full_path()
  else
    python = find_program('python').full_path()
  endif
endif

result = run_command(python, '-c',
  'import sys; sys.stdout.write("%d.%d" % (sys.version_info[0], sys.version_info[1]))',
  check: true)
python_version = result.stdout()

python_name = 'python' + python_version
python_site_packages = get_option('libdir') / python_name / 'site-packages'

pkgdir = python_site_packages / 'frida_tools'

subdir('agents')
subdir('frida_tools')
subdir('scripts')
subdir('completions')
subdir('build_aux')
