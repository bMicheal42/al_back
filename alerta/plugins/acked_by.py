import logging

from flask import g

from alerta.plugins import PluginBase
from alerta.utils.jira import JiraClient
import json

LOG = logging.getLogger('alerta.plugins')


class AckedBy(PluginBase):
    """
    Add "acked-by" attribute to alerts with login id of the operator when
    an alert is acked and automatically watch the alert. Unset the attribute
    when alert is un-acked. Un-watching requires manual intervention.

    To display the "acked-by" attribute in the alert summary add "acked-by"
    to the list of alert attributes in the COLUMNS server setting.
    """

    def pre_receive(self, alert, **kwargs):
        return alert

    def post_receive(self, alert, **kwargs):
        return

    def status_change(self, alert, status, text, **kwargs):
        if status == 'open':
            alert.attributes['acked-by'] = None
        return alert

    def take_action(self, alert, action, text, **kwargs):
        return

    def post_action(self, alert, action, text, **kwargs):
            return

    def delete(self, alert, **kwargs) -> bool:
        raise NotImplementedError
