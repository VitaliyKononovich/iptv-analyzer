"""
class MyBroadcaster()
    def __init__():
        self.onChange = Event()

theBroadcaster = MyBroadcaster()

# add a listener to the event
theBroadcaster.onChange += myFunction

# remove listener from the event
theBroadcaster.onChange -= myFunction

# fire event
theBroadcaster.onChange.fire()
"""
class Event(object):
    def __init__(self):
        self.__handlers = set()

    def handle(self, handler):
        self.__handlers.add(handler)
        return self

    def unhandle(self, handler):
        try:
            self.__handlers.remove(handler)
        except:
            raise ValueError("Handler is not handling this event, so cannot unhandle it.")
        return self

    def fire(self, *args, **kargs):
        for handler in self.__handlers:
            handler(*args, **kargs)

    def getHandlerCount(self):
        return len(self.__handlers)

    def __str__(self):
        return 'Events: {}'.format(str(self.__handlers))

    def __repr__(self):
        return 'Event {}'.format(repr(self.__handlers))

    __iadd__ = handle
    __isub__ = unhandle
    __call__ = fire
    __len__ = getHandlerCount
