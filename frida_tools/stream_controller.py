import threading


class StreamController:
    def __init__(self, post, on_incoming_stream_request=None, on_incoming_stream_closed=None, on_stats_updated=None):
        self.streams_opened = 0
        self.bytes_received = 0
        self.bytes_sent = 0

        self._handlers = {
            ".create": self._on_create,
            ".finish": self._on_finish,
            ".write": self._on_write
        }

        self._post = post
        self._on_incoming_stream_request = on_incoming_stream_request
        self._on_incoming_stream_closed = on_incoming_stream_closed
        self._on_stats_updated = on_stats_updated

        self._sources = {}
        self._next_endpoint_id = 1

        self._requests = {}
        self._next_request_id = 1

    def dispose(self):
        error = DisposedException("disposed")
        for request in self._requests.values():
            request[2] = error
        for event in [request[0] for request in self._requests.values()]:
            event.set()

    def open(self, label, details={}):
        eid = self._next_endpoint_id
        self._next_endpoint_id += 1

        endpoint = {
            "id": eid,
            "label": label,
            "details": details
        }

        sink = Sink(self, endpoint)

        self.streams_opened += 1
        self._notify_stats_updated()

        return sink

    def receive(self, stanza, data):
        sid = stanza["id"]
        name = stanza["name"]
        payload = stanza.get("payload", None)

        stype = name[0]
        if stype == ".":
            self._on_request(sid, name, payload, data)
        elif stype == "+":
            self._on_notification(sid, name, payload)
        else:
            raise ValueError("unknown stanza: " + name)

    def _on_create(self, payload, data):
        endpoint = payload["endpoint"]
        eid = endpoint["id"]
        label = endpoint["label"]
        details = endpoint["details"]

        if self._on_incoming_stream_request is None:
            raise ValueError("incoming streams not allowed")
        source = self._on_incoming_stream_request(label, details)

        self._sources[eid] = (source, label, details)

        self.streams_opened += 1
        self._notify_stats_updated()

    def _on_finish(self, payload, data):
        eid = payload["endpoint"]["id"]

        entry = self._sources.pop(eid, None)
        if entry is None:
            raise ValueError("invalid endpoint ID")
        source, label, details = entry

        source.close()

        if self._on_incoming_stream_closed is not None:
            self._on_incoming_stream_closed(label, details)

    def _on_write(self, payload, data):
        entry = self._sources.get(payload["endpoint"]["id"], None)
        if entry is None:
            raise ValueError("invalid endpoint ID")
        source, *_ = entry

        source.write(data)

        self.bytes_received += len(data)
        self._notify_stats_updated()

    def _request(self, name, payload, data=None):
        rid = self._next_request_id
        self._next_request_id += 1

        completed = threading.Event()
        request = [completed, None, None]
        self._requests[rid] = request

        self._post({
            "id": rid,
            "name": name,
            "payload": payload
        }, data=data)

        completed.wait()

        error = request[2]
        if error is not None:
            raise error

        return request[1]

    def _on_request(self, sid, name, payload, data):
        handler = self._handlers.get(name, None)
        if handler is None:
            raise ValueError("invalid request: " + name)

        try:
            result = handler(payload, data)
        except Exception as e:
            self._reject(sid, e)
            return

        self._resolve(sid, result)

    def _resolve(self, sid, value):
        self._post({
            "id": sid,
            "name": "+result",
            "payload": value
        })

    def _reject(self, sid, error):
        self._post({
            "id": sid,
            "name": "+error",
            "payload": {
                "message": str(error)
            }
        })

    def _on_notification(self, sid, name, payload):
        request = self._requests.pop(sid, None)
        if request is None:
            raise ValueError("invalid request ID")

        if name == "+result":
            request[1] = payload
        elif name == "+error":
            request[2] = StreamException(payload["message"])
        else:
            raise ValueError("unknown notification: " + name)
        completed, *_ = request
        completed.set()

    def _notify_stats_updated(self):
        if self._on_stats_updated is not None:
            self._on_stats_updated()


class Sink:
    def __init__(self, controller, endpoint):
        self._controller = controller
        self._endpoint = endpoint

        controller._request(".create", { "endpoint": endpoint })

    def close(self):
        self._controller._request(".finish", { "endpoint": self._endpoint })

    def write(self, chunk):
        ctrl = self._controller

        ctrl._request(".write", { "endpoint": self._endpoint }, chunk)

        ctrl.bytes_sent += len(chunk)
        ctrl._notify_stats_updated()


class DisposedException(Exception):
    pass


class StreamException(Exception):
    pass
