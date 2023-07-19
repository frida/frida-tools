all: frida_tools/fs_agent.js frida_tools/tracer_agent.js frida_tools/itracer_agent.js

frida_tools/fs_agent.js: agents/fs/agent.ts
	cd agents/fs && npm install && npm run build

frida_tools/tracer_agent.js: agents/tracer/agent.ts
	cd agents/tracer && npm install && npm run build

frida_tools/itracer_agent.js: agents/itracer/agent.ts
	cd agents/itracer && npm install && npm run build

.PHONY: all
