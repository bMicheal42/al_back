import logging
from collections import OrderedDict
from typing import TYPE_CHECKING

from flask import Config, Flask
from pkg_resources import (DistributionNotFound, iter_entry_points,
                           load_entry_point)

from alerta.plugins import app

LOG = logging.getLogger('alerta.plugins')

if TYPE_CHECKING:
    from typing import Iterable, Tuple  # noqa

    from alerta.models.alert import Alert  # noqa
    from alerta.plugins import PluginBase  # noqa


class Plugins:

    def __init__(self) -> None:
        self.plugins = OrderedDict()  # type: OrderedDict[str, PluginBase]
        self.rules = None  # entry point

        self.config = Config('/')

        app.init_app()  # fake app for plugin config (deprecated)

    def register(self, app: Flask) -> None:
        self.config = app.config

        # Find all available plugins
        entry_points = {}
        available_plugins = []
        for ep in iter_entry_points('alerta.plugins'):
            LOG.debug(f"Server plugin '{ep.name}' found.")
            entry_points[ep.name] = ep
            available_plugins.append(ep.name)

        # Load enabled plugins
        # for name in self.config['PLUGINS']:
        #     if name != 'acked_by': # TODO ...
        #         continue
        #     try:
        #         plugin = entry_points[name].load()
        #         if plugin:
        #             self.plugins[name] = plugin()
        #             success_msg = f"✓ Successfully loaded plugin '{name}'"
        #             print(success_msg)
        #             LOG.warning(success_msg)
        #     except Exception as e:
        #         error_msg = f"✗ Failed to load plugin '{name}': {str(e)}"
        #         print(error_msg)
        #         LOG.error(error_msg)

        try:
            routing_dist = self.config['ROUTING_DIST']
            self.rules = load_entry_point(routing_dist, 'alerta.routing', 'rules')  # type: ignore
        except (DistributionNotFound, ImportError):
            no_rules_msg = 'No plugin routing rules found. All plugins will be evaluated.'
            print(no_rules_msg)
            LOG.warning(no_rules_msg)

    def routing(self, alert: 'Alert') -> 'Tuple[Iterable[PluginBase], Config]':
        try:
            if self.plugins and self.rules:
                try:
                    r = self.rules(alert, self.plugins, config=self.config)
                except TypeError:
                    r = self.rules(alert, self.plugins)

                if isinstance(r, list):
                    return r, self.config
                else:
                    plugins, config = r
                    return plugins, Config('/', {**self.config, **config})

        except Exception as e:
            LOG.warning(f'Plugin routing rules failed: {e}')

        # default when no routing rules defined
        return self.plugins.values(), self.config