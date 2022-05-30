function get_process_names
	ps axco command,pid | awk '{print $1","$2}' | sort -u -t, -k1,1 | awk -F ',' '{print $1"\t"$2}'
end

function get_frida_devices
	frida-ls-devices | tail -n +3 | awk '{print $1"\t"substr($0, index($0,$3))}'
end

function get_frida_names
	frida-ls-devices | tail -n +3 | awk '{print substr($0, index($0,$3))"\t"$1}'
end

function add_base_arguments
	complete --command "$argv[1]" --force-files --require-parameter --short-option=O --long-option=options-file --description="text file containing additional command line options"
	complete --command "$argv[1]" --no-files --long-option=version --description="show program's version number and exit"
	complete --command "$argv[1]" --no-files --short-option=h --long-option=help --description="show this help message and exit"
end

function add_device_arguments
	complete --command "$argv[1]" --no-files --require-parameter --short-option=D --long-option=device --description="connect to device with the given ID" --arguments="(get_frida_devices)"
	complete --command "$argv[1]" --no-files --short-option=U --long-option=usb --description="connect to USB device"
	complete --command "$argv[1]" --no-files --short-option=R --long-option=remote --description="connect to remote frida-server"
	complete --command "$argv[1]" --no-files --require-parameter --short-option=H --long-option=host --description="connect to remote frida-server on HOST"
	complete --command "$argv[1]" --force-files --require-parameter --long-option=certificate --description="speak TLS with HOST, expecting CERTIFICATE"
	complete --command "$argv[1]" --no-files --require-parameter --long-option=origin --description="connect to remote server with “Origin” header set to ORIGIN"
	complete --command "$argv[1]" --no-files --require-parameter --long-option=token --description="authenticate with HOST using TOKEN"
	complete --command "$argv[1]" --no-files --require-parameter --long-option=keepalive-interval --description="set keepalive interval in seconds, or 0 to disable (defaults to -1 to auto-select based on transport)"
	complete --command "$argv[1]" --no-files --long-option=p2p --description="establish a peer-to-peer connection with target"
	complete --command "$argv[1]" --no-files --require-parameter --long-option=stun-server --description="set STUN server ADDRESS to use with --p2p"
	complete --command "$argv[1]" --no-files --require-parameter --long-option=relay --description="add relay to use with --p2p"
end

function add_target_arguments
	complete --command "$argv[1]" --no-files --require-parameter --short-option=f --long-option=file --description="Spawn FILE"
	complete --command "$argv[1]" --no-files --short-option=F --long-option=attach-frontmost --description="attach to frontmost application"
	complete --command "$argv[1]" --no-files --require-parameter --short-option=n --long-option=attach-name --description="attach to NAME" --arguments="(get_frida_names)"
	complete --command "$argv[1]" --no-files --require-parameter --short-option=p --long-option=attach-pid --description="attach to PID" --arguments="(__fish_complete_pids)"
	complete --command "$argv[1]" --no-files --require-parameter --short-option=W --long-option=await --description="await spawn matching PATTERN"
	complete --command "$argv[1]" --no-files --require-parameter --long-option=stdio --description="stdio behavior when spawning" --arguments="inherit pipe"
	complete --command "$argv[1]" --no-files --require-parameter --long-option=aux --description="set aux option when spawning"
	complete --command "$argv[1]" --no-files --require-parameter --long-option=realm --description="realm to attach in" --arguments="native emulated"
	complete --command "$argv[1]" --no-files --require-parameter --long-option=runtime --description="script runtime to use" --arguments="qjs v8"
	complete --command "$argv[1]" --no-files --long-option=debug --description="enable the Node.js compatible script debugger"
	complete --command "$argv[1]" --no-files --long-option=squelch-crash --description="if enabled, will not dump crash report to console"
	complete --command "$argv[1]" --force-files --arguments "(__fish_complete_pids) (get_process_names)"
end


######## frida ########
add_base_arguments frida
add_device_arguments frida
add_target_arguments frida
complete --command frida --force-files --require-parameter --short-option=l --long-option=load --description="load SCRIPT"
complete --command frida --no-files --require-parameter --short-option=P --long-option=parameters --description="parameters as JSON, same as Gadget"
complete --command frida --no-files --require-parameter --short-option=C --long-option=cmodule --description="load CMODULE"
complete --command frida --no-files --require-parameter --long-option=toolchain --description="CModule toolchain to use when compiling from source code" --arguments="any internal external"
complete --command frida --no-files --require-parameter --short-option=c --long-option=codeshare --description="load CODESHARE_URI"
complete --command frida --no-files --require-parameter --short-option=e --long-option=eval --description="evaluate CODE"
complete --command frida --no-files --short-option=q --description="quiet mode (no prompt) and quit after -l and -e"
complete --command frida --no-files --long-option=no-pause --description="automatically start main thread after startup"
complete --command frida --force-files --require-parameter --short-option=o --long-option=output --description="output to log file"
complete --command frida --no-files --long-option=eternalize --description="eternalize the script before exit"
complete --command frida --no-files --long-option=exit-on-error --description="exit with code 1 after encountering any exception in the SCRIPT"
complete --command frida --no-files --long-option=auto-perform --description="wrap entered code with Java.perform"


######## frida-ls-devices ########
add_base_arguments frida-ls-devices


######## frida-ps ########
add_base_arguments frida-ps
add_device_arguments frida-ps
complete --command frida-ps --no-files --short-option=a --long-option=applications --description="list only applications"
complete --command frida-ps --no-files --short-option=i --long-option=installed --description="include all installed applications"
complete --command frida-ps --no-files --short-option=j --long-option=json --description="output results as JSON"


######## frida-kill ########
add_base_arguments frida-kill
add_device_arguments frida-kill
complete --command frida-kill --force-files --arguments "(__fish_complete_pids) (get_process_names)"


######## frida-discover ########
add_base_arguments frida-discover
add_device_arguments frida-discover
add_target_arguments frida-discover


######## frida-trace ########
add_base_arguments frida-trace
add_device_arguments frida-trace
add_target_arguments frida-trace
complete --command frida-trace --no-files --require-parameter --short-option=I --long-option=include-module --description="include MODULE"
complete --command frida-trace --no-files --require-parameter --short-option=X --long-option=exclude-module --description="exclude MODULE"
complete --command frida-trace --no-files --require-parameter --short-option=i --long-option=include --description="include [MODULE!]FUNCTION"
complete --command frida-trace --no-files --require-parameter --short-option=x --long-option=exclude --description="exclude [MODULE!]FUNCTION"
complete --command frida-trace --no-files --require-parameter --short-option=a --long-option=add --description="add MODULE!OFFSET"
complete --command frida-trace --no-files --require-parameter --short-option=T --long-option=include-imports --description="include program's imports"
complete --command frida-trace --no-files --require-parameter --short-option=t --long-option=include-module-imports --description="include MODULE imports"
complete --command frida-trace --no-files --require-parameter --short-option=m --long-option=include-objc-method --description="include OBJC_METHOD"
complete --command frida-trace --no-files --require-parameter --short-option=M --long-option=exclude-objc-method --description="exclude OBJC_METHOD"
complete --command frida-trace --no-files --require-parameter --short-option=j --long-option=include-java-method --description="include JAVA_METHOD"
complete --command frida-trace --no-files --require-parameter --short-option=J --long-option=exclude-java-method --description="exclude JAVA_METHOD"
complete --command frida-trace --no-files --require-parameter --short-option=s --long-option=include-debug-symbol --description="include DEBUG_SYMBOL"
complete --command frida-trace --no-files --short-option=q --long-option=quiet --description="do not format output messages"
complete --command frida-trace --no-files --short-option=d --long-option=decorate --description="add module name to generated onEnter log statement"
complete --command frida-trace --force-files --require-parameter --short-option=S --long-option=init-session --description="path to JavaScript file used to initialize the session"
complete --command frida-trace --no-files --require-parameter --short-option=P --long-option=parameters --description="parameters as JSON, exposed as a global named 'parameters'"
complete --command frida-trace --force-files --require-parameter --short-option=o --long-option=output --description="dump messages to file"


######## frida-join ########
add_base_arguments frida-join
add_device_arguments frida-join
add_target_arguments frida-join
complete --command frida-join --no-files --require-parameter --long-option=portal-location --description="join portal at LOCATION"
complete --command frida-join --force-files --require-parameter --long-option=portal-certificate --description="speak TLS with portal expecting CERTIFICATE"
complete --command frida-join --no-files --require-parameter --long-option=portal-token --description="authenticate with portal using TOKEN"
complete --command frida-join --no-files --require-parameter --long-option=portal-acl-allow --description="limit portal access to control channels with TAG"
# TODO specify positional arguments better


######## frida-apk ########
add_base_arguments frida-create
complete --command frida-create --no-files --short-option=n --long-option=project-name --description="project name"
complete --command frida-create --force-files --short-option=o --long-option=output-directory --description="output directory"
complete --command frida-create --no-files --arguments "agent cmodule"


######## frida-apk ########
add_base_arguments frida-apk
complete --command frida-apk --force-files --short-option=o --long-option=output --description="output path"
