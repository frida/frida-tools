def main() -> None:
    import functools

    import frida

    from frida_tools.application import ConsoleApplication

    class LSDApplication(ConsoleApplication):
        def _usage(self) -> str:
            return "%(prog)s [options]"

        def _needs_device(self) -> bool:
            return False

        def _start(self) -> None:
            try:
                devices = frida.enumerate_devices()
            except Exception as e:
                self._update_status(f"Failed to enumerate devices: {e}")
                self._exit(1)
                return
            device_name = {}
            device_os = {}
            for device in devices:
                device_name[device.id] = device.name
                try:
                    params = device.query_system_parameters()
                except:
                    continue
                device_name[device.id] = params.get("name", device.name)
                os = params["os"]
                version = os.get("version")
                if version is not None:
                    device_os[device.id] = os["name"] + " " + version
                else:
                    device_os[device.id] = os["name"]
            id_column_width = max(map(lambda device: len(device.id) if device.id is not None else 0, devices))
            type_column_width = max(map(lambda device: len(device.type) if device.type is not None else 0, devices))
            name_column_width = max(map(lambda name: len(name) if name is not None else 0, device_name.values()))
            os_column_width = max(map(lambda os: len(os) if os is not None else 0, device_os.values()))
            header_format = (
                "%-"
                + str(id_column_width)
                + "s  "
                + "%-"
                + str(type_column_width)
                + "s  "
                + "%-"
                + str(name_column_width)
                + "s  "
                + "%-"
                + str(os_column_width)
                + "s"
            )
            self._print(header_format % ("Id", "Type", "Name", "OS"))
            self._print(
                f"{id_column_width * '-'}  {type_column_width * '-'}  {name_column_width * '-'}  {os_column_width * '-'}"
            )
            line_format = (
                "%-"
                + str(id_column_width)
                + "s  "
                + "%-"
                + str(type_column_width)
                + "s  "
                + "%-"
                + str(name_column_width)
                + "s  "
                + "%-"
                + str(os_column_width)
                + "s"
            )
            for device in sorted(devices, key=functools.cmp_to_key(compare_devices)):
                self._print(
                    line_format % (device.id, device.type, device_name.get(device.id), device_os.get(device.id, ""))
                )
            self._exit(0)

    def compare_devices(a: frida.core.Device, b: frida.core.Device) -> int:
        a_score = score(a)
        b_score = score(b)
        if a_score == b_score:
            if a.name is None or b.name is None:
                return 0
            if a.name > b.name:
                return 1
            elif a.name < b.name:
                return -1
            else:
                return 0
        else:
            if a_score > b_score:
                return -1
            elif a_score < b_score:
                return 1
            else:
                return 0

    def score(device: frida.core.Device) -> int:
        type = device.type
        if type == "local":
            return 3
        elif type == "usb":
            return 2
        else:
            return 1

    app = LSDApplication()
    app.run()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
