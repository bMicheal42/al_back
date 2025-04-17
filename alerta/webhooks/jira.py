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

def incoming(self, path: str, query_string: str, payload: JSON):
    logging.debug(f"Jira hook: {path} {query_string} {json.dumps(payload, cls=CustomJSONEncoder)}")

    parsed_jira = self._parse_jira_payload(payload)
    jira_status = parsed_jira['status']
    jira_assignee = parsed_jira['assignee']
    jira_key = parsed_jira['key']

    if not jira_key:
        logging.error("Missing Jira issue key in payload.")
        return jsonify({'status': 'error', 'message': 'Missing Jira issue key'}), 400

    incidents = Alert.find_by_jira_keys([jira_key])

    if not incidents:
        logging.error(f"No incidents found for Jira key: {jira_key}")
        return jsonify({'status': 'error', 'message': 'No incident found for provided Jira key'}), 404

    first = incidents.pop(0)
    logging.warning(f"Jira hook fired {first.id} from '{jira_key}', assignee: {jira_assignee}, status: {jira_status}") # FIXME set to info after stabilization

    update_text = f"[JIRA]: {jira_key} changed to {jira_status} by {jira_assignee}"
    updated_inc = first.set_status('escalated', text=update_text)
    if updated_inc is None:
        logging.error(f"Failed to update incident id={first.id} status in DB.")
        return jsonify({'status': 'error', 'message': f'Failed to update incident {first.id} status {jira_status} in DB'}), 500
    logging.info(f"Incident id={first.id} status updated successfully to Escalated.")

    updated_inc.attributes['jira_status'] = 'Working'
    updated_inc = updated_inc.update_attributes(updated_inc.attributes)
    if updated_inc is None:
        logging.error(f"Failed to update incident id={first.id} attributes in DB.")
        return jsonify({'status': 'error', 'message': f'Failed to update incident {first.id} attributes in DB'}), 500
    logging.info(f"Incident id={first.id} attributes updated successfully.")

    return jsonify({
        'status': 'ok',
        'message': 'Operation successful'
    }), 200
