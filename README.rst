*********
eStreamer
*********

SourceFire eStreamer python client library

Quickstart
----------
Install estreamer using ``pip``: ``$ pip install estreamer``.
Get the `examples/ <https://github.com/spohara79/estreamer/examples>`_ client to get started capturing pcaps

Usage
-----
See the `examples/ <https://github.com/spohara79/estreamer/examples>`_ directory for an example client

You need the following:

- Configure SourceFire for the client authentication using this `guide <http://www.cisco.com/c/en/us/td/docs/security/firesight/540/api/estreamer/EventStreamerIntegrationGuide/ConfiguringEstreamer.html#38601>`_
    - You will need the cert and private key for the client
- Get the SourceFire server certificate (for TLS verification)

eStreamer has two types of streams: Event Stream Requests and Extended Requests.  You can use either or both types of streams.

.. note:: To use the extended requests you must set bit 30 (extended_request=1) in the flags

Event Stream Request Flags
^^^^^^^^^^^^^^^^^^^^^^^^^^

You must set bits in here to use either or both stream requests (Requests vs Extended Requests)

The following are valid stream request flags:

- packets
- metadata
- ids
- discovery
- correlation
- impact
- ids_1
- discovery_v2
- connection
- correlation_v2
- discovery_v3
- disable_events
- connection_v3
- correlation_v3
- metadata_v2
- metadata_v3
- reserved
- discovery_v4
- connection_v4
- correlation_v4
- metadata_v4
- user
- correlation_v5
- timestamp
- discovery_v5
- discovery_v6
- connection_v5
- extra_data
- discovery_v7
- correlation_v6
- extended_request

Extended Requests
^^^^^^^^^^^^^^^^^
.. note :: TO use extended requests you must set the extended_request bit in the event stream request flags

The following are valid extended requests:

- INTRUSION_EVENTS  
- METADATA  
- CORRELATION
- DISCOVERY
- CONNECTION
- USER
- MALWARE
- FILE
- IMPACT
- TERMINATE (this is to end a session, so shouldn't be used as a request)

The stream flags need to be a list of 'extended request event flags', and the stream request must be a dictionary
of flags that have a key of the stream name and a value of 1 or 0 (1=on, 0=off)

Example Config file:

::

    [settings]
    event_types=INTRUSION_EVENTS, MALWARE, USER, FILE, IMPACT
    [flags]
    packets=1
    metadata=0
    ids=0
    discovery=0
    correlation=0
    impact=0
    ids_1=0
    discovery_v2=0
    connection=0
    correlation_v2=0
    discovery_v3=0
    disable_events=0
    connection_v3=0
    correlation_v3=0
    metadata_v2=0
    metadata_v3=0
    reserved=0
    discovery_v4=0
    connection_v4=0
    correlation_v4=0
    metadata_v4=0
    user=0
    correlation_v5=0
    timestamp=1
    discovery_v5=0
    discovery_v6=0
    connection_v5=0
    extra_data=0
    discovery_v7=0
    correlation_v6=0
    extended_request=1

Example code to read a config file

::  

    cfg = ConfigParser.ConfigParser()
    cfg.read('estreamer.config')
    STREAM_FLAGS = [x.lstrip(' ') for x in cfg.get('settings', 'event_types').split(',')]
    REQUEST_FLAGS = { k: v for k, v in cfg.items('flags') }

Plugins
-------
The plugin system uses an autoload and auto-unload mechanism in order to add or remove plugins without needing to restart.  Simply drop a plugin into the plugins/ directory and it will pick it up and register (and use it).  Conversely, remove the plugin from the directory and it will unregister the plugin (and not use it)

To create plugins, you will need to inherit the **Plugin** class.  In addition, you will need to create a class variable (dictionary) named **__info__** that contains:

- **description**: description of the plugin
- **author**: name of the author (and optionally contact, etc.)
- **version**: version of the plugin
- **callback**: the string name of the callback method (the function to be called in your plugin to do its thing)

The callback function will receive each *record* (alert that is processed)

Example: 
::
    from estreamer import plugin
    
    class YourPlugin(plugin.Plugin):
        __info__ = {
            'description': 'my plugin',
            'author'     : 'my name',
            'version'    : '0.1',
            'callback'   : 'my_function',
        }

        def my_function(self, record):
            print(record)
