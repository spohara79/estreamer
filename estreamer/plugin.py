# local
from printtable import PrintTable

# standard
from six import with_metaclass
import traceback
import imp
import glob
import os


'''
Plugin class to derive new plugins from, as well as auto-load
and auto-unload plugins (when adding or removing plugins from the plugin dir)

This was derived from:
http://stackoverflow.com/a/17401329
'''

class PluginImportError(Exception): pass

'''
handle dynamic adding of plugins to the plugin directory
so that each time we loop over the plugins, we reload the
dir. (and handle removal via getitem
'''
class PluginDict(dict):


    ''' handle removal of a plugin from the dir '''
    def __getitem__(self, key):
        try:
            super(PluginDict, self).__getitem__(key)
        except KeyError as ke:
            ''' keyerror represents a deleted plugin; unregister '''
            self.plugin_cls.unregister_plugin(key)

    def __init__(self, cls, *args, **kwargs):
        self.plugin_cls = cls
        super(PluginDict, self).__init__(*args,**kwargs)

    def __iter__(self):
        self.plugin_cls.load_plugins()
        return super(PluginDict, self).__iter__()
    
    def __getattr__(self, name):
        def attr_handler(*args, **kwargs):
            super_func = getattr(super(PluginDict, self), name)
            super_func(*args, **kwargs)
        self.plugin_cls.load_plugins()
        return attr_handler


class _PluginMeta(type):

    def __init__(cls, clsname, clsbases, clsdict):
        # 'plugins' doesn't exist.. create the dicts we need
        if not hasattr(cls, 'plugins'):
            cls.plugins = PluginDict(_PluginMeta)
        if not hasattr(cls, 'plugin_info'):
            cls.plugin_info = {}
        else:
            cls.register_plugin(cls)

    def list_plugins(cls):
        pt = PrintTable(['name', 'version', 'author', 'description'])
        for plugin_name in cls.plugins.keys():
            pt.add_row([
                plugin_name,
                cls.plugin_info[plugin_name]['version'],
                cls.plugin_info[plugin_name]['author'],
                cls.plugin_info[plugin_name]['description'],
            ])
        if pt.row_data:
            print(pt)
        else:
            print("No plugins found!")

    def unregister_plugin(cls, plugin):
        instance = plugin()
        k = instance.__class__.__name__
        cls.plugins.pop(k, None)
        cls.plugin_info.pop(k, None)

    def register_plugin(cls, plugin):
        instance = plugin()
        if hasattr(plugin, '__info__'):
            k = instance.__class__.__name__
            cls.plugins[k] = instance
            cls.plugin_info[k] = {
                'description': instance.__info__['description'],
                'version': instance.__info__['version'],
                'author': instance.__info__['author'],
                'callback': instance.__info__['callback'],
            }
            callback_func = getattr(plugin, instance.__info__['callback'])
            setattr(plugin, 'callback', callback_func)
        else:
            raise PluginImportError('{} Class has no __info__ allocated'.format(k))

    @staticmethod
    def load_plugins(plugin_dir='./plugins/'):
        for plugin_file in [fn for fn in glob.glob(plugin_dir + '*.py') if not os.path.basename(fn).startswith("__init__")]:
            modname = os.path.basename(plugin_file.rsplit('.', 1)[0])
            if globals().get(modname, None) is None:
                try:
                    (mod_fh, mod_path, mod_desc) = imp.find_module(modname, [plugin_dir])
                    imp.load_module(modname, mod_fh, mod_path, mod_desc)
                except:
                    raise PluginImportError(traceback.format_exc())
                finally:
                    if mod_fh:
                        mod_fh.close()

# main class for new plugins to inherit from
class Plugin(with_metaclass(_PluginMeta, object)):
    pass
