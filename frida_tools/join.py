# -*- coding: utf-8 -*-
from __future__ import unicode_literals


def main():
    import threading

    import frida

    from frida_tools.application import ConsoleApplication, input_with_cancellable

    class JoinApplication(ConsoleApplication):
        def __init__(self):
            ConsoleApplication.__init__(self, self._await_ctrl_c)

        def _usage(self):
            return "usage: %prog [options] target portal-location [portal-certificate] [portal-token]"

        def _add_options(self, parser):
            parser.add_option("--portal-location", help="join portal at LOCATION",
                    metavar="LOCATION", type='string', action='store', dest="portal_location", default=None)
            parser.add_option("--portal-certificate", help="speak TLS with portal, expecting CERTIFICATE",
                    metavar="CERTIFICATE", type='string', action='store', dest="portal_certificate", default=None)
            parser.add_option("--portal-token", help="authenticate with portal using TOKEN",
                    metavar="TOKEN", type='string', action='store', dest="portal_token", default=None)
            parser.add_option("--portal-acl-allow", help="limit portal access to control channels with TAG",
                    metavar="TAG", type='string', action='append', dest="portal_acl", default=None)

        def _initialize(self, parser, options, args):
            location = args[0] if len(args) >= 1 else options.portal_location
            certificate = args[1] if len(args) >= 2 else options.portal_certificate
            token = args[2] if len(args) >= 3 else options.portal_token
            acl = options.portal_acl

            if location is None:
                parser.error('portal location must be specified')

            options = {}
            if certificate is not None:
                options['certificate'] = certificate
            if token is not None:
                options['token'] = token
            if acl is not None:
                options['acl'] = acl

            self._location = location
            self._options = options

        def _needs_target(self):
            return True

        def _start(self):
            self._update_status("Joining portal...")
            try:
                self._session.join_portal(self._location, **self._options)
            except Exception as e:
                self._update_status("Unable to join: " + str(e))
                self._exit(1)
                return
            self._update_status("Joined!")
            self._exit(0)

        def _stop(self):
            pass

        def _await_ctrl_c(self, reactor):
            while True:
                try:
                    input_with_cancellable(reactor.ui_cancellable)
                except frida.OperationCancelledError:
                    break
                except KeyboardInterrupt:
                    break

    app = JoinApplication()
    app.run()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
