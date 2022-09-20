def main():
    import functools

    import frida

    from frida_tools.application import ConsoleApplication

    class LSDApplication(ConsoleApplication):
        def _usage(self):
            return "%(prog)s [options]"

        def _needs_device(self):
            return False

        def _start(self):
            try:
                devices = frida.enumerate_devices()
            except Exception as e:
                self._update_status(f"Failed to enumerate devices: {e}")
                self._exit(1)
                return
            id_column_width = max(map(lambda device: len(device.id), devices))
            type_column_width = max(map(lambda device: len(device.type), devices))
            name_column_width = max(map(lambda device: len(device.name), devices))
            header_format = (
                "%-"
                + str(id_column_width)
                + "s  "
                + "%-"
                + str(type_column_width)
                + "s  "
                + "%-"
                + str(name_column_width)
                + "s"
            )
            self._print(header_format % ("Id", "Type", "Name"))
            self._print(f"{id_column_width * '-'}  {type_column_width * '-'}  {name_column_width * '-'}")
            line_format = (
                "%-"
                + str(id_column_width)
                + "s  "
                + "%-"
                + str(type_column_width)
                + "s  "
                + "%-"
                + str(name_column_width)
                + "s"
            )
            for device in sorted(devices, key=functools.cmp_to_key(compare_devices)):
                self._print(line_format % (device.id, device.type, device.name))
            self._exit(0)

    def compare_devices(a, b):
        a_score = score(a)
        b_score = score(b)
        if a_score == b_score:
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

    def score(device):
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
