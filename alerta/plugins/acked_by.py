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
        # if action == 'ack' and g.login:
        #     # watch = 'watch:' + g.login
        #     # alert.tags.append(watch)
        #     alert.attributes['acked-by'] = g.login
        # return alert


    def post_action(self, alert, action, text, **kwargs):
        if action == 'inc' and g.login:
            params = {
                'attributes': json.dumps(alert.attributes),
                'severity': alert.severity,
                'tags': json.dumps(alert.tags),
                'text': alert.text,
                'eventtags': alert.tags,
                'host': alert.event,
                'username': g.login,
                'InfoSystem': None,
                'ProjectGroup': 'Other',
                'Owner_1': None,
                'Owner_2': None,
            }
            for tag in alert.tags:
                if "Owner_1:" in tag or "Owner_2:" in tag or "ProjectGroup:" in tag or "InfoSystem:" in tag:
                    key, value = tag.split(":", 1)
                    params[key] = value

            if not alert.attributes.get('jira_key', None):
                jira_client = JiraClient()
                ticket = jira_client.create_ticket(
                    args=params,
                    infosystem=params['InfoSystem'],
                    projectgroup=params['ProjectGroup']
                )
                if ticket:
                    alert.attributes['jira_url'] = ticket['url']
                    alert.attributes['jira_key'] = ticket['key']
                    alert.attributes['jira_status'] = ticket['status']
                else:
                    logging.error(f"Jira ticket from alert_id: {alert.id} was not created")
            return alert

    def delete(self, alert, **kwargs) -> bool:
        raise NotImplementedError
