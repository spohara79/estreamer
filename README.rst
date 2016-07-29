=========
eStreamer
=========

SourceFire eStreamer python client library

Usage
^^^^^
See the `examples/ <https://github.com/spohara79/estreamer/examples>`_ directory for an example client

You need the following:

- Configure SourceFire for the client authentication using this: `http://www.cisco.com/c/en/us/td/docs/security/firesight/540/api/estreamer/EventStreamerIntegrationGuide/ConfiguringEstreamer.html#38601 <http://www.cisco.com/c/en/us/td/docs/security/firesight/540/api/estreamer/EventStreamerIntegrationGuide/ConfiguringEstreamer.html#38601>`_

- Get the SourceFire server certificate (for TLS verification)


Plugins
^^^^^^^
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
