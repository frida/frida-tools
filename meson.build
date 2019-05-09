project('frida-tools', 'c', version: '1.0.0')

python = get_option('python')
if python == ''
  python = find_program('python3', required: false)
  if not python.found()
    python = find_program('python')
  endif
endif

result = run_command(python, '-c',
  'import sys; sys.stdout.write("%d.%d" % (sys.version_info[0], sys.version_info[1]))')
if result.returncode() != 0
  error('Unable to detect Python version: ' + result.stdout() + result.stderr())
endif
python_version = result.stdout()

python_name = 'python' + python_version
python_site_packages = join_paths(get_option('libdir'), python_name, 'site-packages')

subdir('frida_tools')
subdir('scripts')
