import json
from typing import Any, Dict
import logging
from flask import current_app, g, jsonify, request
from alerta.models.alert import Alert
from alerta.utils.format import CustomJSONEncoder

from . import WebhookBase


JSON = Dict[str, Any]


class JiraWebhook(WebhookBase):
    def _parse_jira_payload(self, payload: JSON) -> JSON:
        try:
            issue_key = payload.get("key", "").strip()
            fields = payload.get("fields", {})

            status_data = fields.get("status", {}) or {}
            assignee_data = fields.get("assignee", {}) or {}
            project_data = fields.get("project", {}) or {}

            parsed_payload = {
                "key": issue_key,
                "status": status_data.get("name"),
                "assignee": assignee_data.get("name"),
                "project": project_data.get("key"),
            }
            logging.debug(f"Parsed Jira payload: {parsed_payload}")
            return parsed_payload

        except Exception as e:
            logging.error(f"Error parsing Jira payload: {e}", exc_info=True)
            return {}

    def incoming(self, path: str, query_string: str, payload: JSON):
        try:
            payload_str = json.dumps(payload, cls=CustomJSONEncoder)
            logging.debug(f"Received Jira hook: path={path}, query_string={query_string}, payload={payload_str}")

            # Парсинг payload от Jira.
            parsed_jira = self._parse_jira_payload(payload)
            jira_key = parsed_jira.get('key')
            jira_status = parsed_jira.get('status')
            jira_assignee = parsed_jira.get('assignee')

            if not jira_key:
                logging.error("Received payload without a valid Jira issue key.")
                return jsonify({'status': 'error', 'message': 'Missing issue key in payload'}), 400


            incidents = Alert.find_by_jira_keys([jira_key])
            if not incidents:
                logging.warning(f"No incident found for Jira key {jira_key}.")
                return jsonify({'status': 'ok', 'message': 'No matching incident found'}), 200

            incident = incidents.pop(0)
            logging.info(
                f"Processing incident id={incident.id} for Jira key {jira_key} - assignee: {jira_assignee}, status: {jira_status}"
            )

            if jira_status == 'Working':
                logging.info(f"[JIRA]: {jira_key} changed to {jira_status} by WebHook from Jira (alert_id: {incident.id}")
                incident.set_status('escalated', text="Updated by Webhook from Jira")

                incident.attributes['jira_status'] = jira_status
                incident.update_attributes(incident.attributes)
            else:
                logging.info(f"No status update required for incident id={incident.id} with Jira status '{jira_status}'.")

            return jsonify({'status': 'ok'}), 200

        except Exception as e:
            logging.exception(f"Exception occurred while processing Jira webhook: {e}")
            return jsonify({'status': 'error', 'message': 'Internal server error'}), 500