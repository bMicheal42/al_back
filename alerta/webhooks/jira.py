import json
from typing import Any, Dict
import logging
from flask import current_app, g, jsonify, request
from alerta.models.alert import Alert
from alerta.utils.format import CustomJSONEncoder

from . import WebhookBase

JSON = Dict[str, Any]



class JiraWebhook(WebhookBase):
    def _parse_jira_payload(self, payload):
        issue_key = payload.get("key", "")
        fields = payload.get("fields", {})

        status_name = fields.get("status", {}) or {}
        assignee = fields.get("assignee", {}) or {}
        project = fields.get("project", {}) or {}

        return {
            "key": issue_key,
            "status": status_name.get("name", None),
            "assignee": assignee.get("name", None),
            "project": project.get("key", None),
        }

    def incoming(self, path, query_string, payload):
        logging.debug(f"Jira hook: {path} {query_string} {json.dumps(payload, cls=CustomJSONEncoder)}")

        parsed_jira = self._parse_jira_payload(payload)
        jira_status = parsed_jira['status']
        jira_assignee = parsed_jira['assignee']
        jira_key = parsed_jira['key']

        incidents = Alert.find_by_jira_keys([jira_key])

        if incidents:
            first = incidents.pop(0)

            # FIXME set to info after stabilization
            logging.warning(f"Jira hook fired {first.id} from '{jira_key}', assignee: {jira_assignee}, status: {jira_status}")

            if jira_status == 'Working':
                first.set_status('escalated', text=f"[JIRA]: {jira_key} to {jira_status} by {jira_assignee}")
                first.attributes['jira_status'] = jira_status
                first.update_attributes(first.attributes)

        return jsonify({
            'status': 'ok'
        }), 200
