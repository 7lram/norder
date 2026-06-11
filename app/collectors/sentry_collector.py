class SentryCollector:
    def fetch_events(self):
        raise NotImplementedError("Connect this class to the Sentry API in production.")
