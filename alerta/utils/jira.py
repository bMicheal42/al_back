import logging
import threading
import json
from jira import JIRA
from jira.exceptions import JIRAError
from alerta.plugins import app
from typing import Dict, Optional

LOG = logging.getLogger('alerta.jira')

class JiraClient:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            with cls._lock:
                if not cls._instance:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if not hasattr(self, "_initialized"):
            self._initialized = True
            self.jira = self._connect()

    def _connect(self):
        """Initialize JIRA client connection"""
        JIRA_URL = app.config['JIRA_URL']
        JIRA_USER = app.config['JIRA_USER']
        JIRA_PWD = app.config['JIRA_PWD']
        if not JIRA_USER or not JIRA_PWD:
            LOG.warning("JIRA credentials are missing! JIRA integration will be disabled.")
            self.jira = None  # Prevent connection attempts
            return None

        LOG.info(f"_connect to JIRA_URL {JIRA_URL} via JIRA_USER: {JIRA_USER}")
        return JIRA(
            options={'server': JIRA_URL, 'timeout': '4', 'max_retries': '4', 'verify': True},
            basic_auth=(JIRA_USER, JIRA_PWD)
        )

    def create_ticket(self, args: Dict[str, str], infosystem: str = None, projectgroup: str = None):
        """Creates a JIRA ticket based on the given parameters."""

        JIRA_PROJECTGROUPS = app.config['JIRA_PROJECTGROUPS']
        JIRA_OWNERS_GROUPS = app.config['JIRA_OWNERS_GROUPS']
        JIRA_SEVERITY_LEVEL = app.config['JIRA_SEVERITY_LEVEL']
        JIRA_CRITICAL = app.config['JIRA_CRITICAL']
        JIRA_PROJECT = app.config['JIRA_PROJECT']

        if not projectgroup or not projectgroup in JIRA_PROJECTGROUPS:
            projectgroup = 'Other'

        if not self.jira:
            logging.warning("Not connected to JIRA, skipping ticket creation")
            return None

        try:
            severity = args.get('severity', 'medium')
            severity_field_value = JIRA_SEVERITY_LEVEL[severity]

            tags = args.get('eventtags')
            if tags and "Host:nonCritical" in tags:
                host_critical = '0'
            else:
                host_critical = '1'
            host_critical_field_value = JIRA_CRITICAL[host_critical]

            host =  args.get('host', 'NO HOST')
            owner_1 = args.get('Owner_1', 'zbx-admins')
            owner_2 = args.get('Owner_2', None)

            escalation_group1 = JIRA_OWNERS_GROUPS.get(owner_1, 'JIRA_Monitoring-development-team')
            escalation_group2 = JIRA_OWNERS_GROUPS.get(owner_2, None)

            username = args.get('username', 'g.taftin') # в идеале проверять что логин есть в Jira (дорого по времени)

            ticket = self.jira.create_issue(
                project=JIRA_PROJECT,
                summary=f"{args.get('host', 'No Host')}: {args.get('text', 'No Text')}",
                description="incident created by Alerta",
                issuetype={'name': 'Incident'},
                assignee={'name': username},
                customfield_19702={'name': 'JIRA_Duty-engineers-team'},   # Workgroup
                customfield_19819={'value': projectgroup},                # Project Group // AF CP Lab RETN
                customfield_13251={'id': severity_field_value},
                customfield_19949={'id': host_critical_field_value},
                customfield_19502=[{'key': 'SC-39772'}],                  # Service ZBX Incident
                customfield_19823=host,                                   # Host
                customfield_19920=owner_1,                                # Slack Group
                customfield_19921=owner_2,                                # Reserve Slack Group
                customfield_19918=escalation_group1,                      # Escalation Group № 161 чекает
                customfield_19919=escalation_group2,                      # Reserve Escalation Group
            )
            ticket_fields = {
                "url": ticket.permalink(),
                "key": ticket.key,
                "status": '24/7 Processing',
                "id": ticket.id
            }
            logging.warning(f"[JIRA] Created ticket: {ticket_fields.get('url', '')}")
            return ticket_fields

        except JIRAError as e:
            error_text = ''
            if e.response is not None:
                try:
                    error_text = e.response.text
                except Exception as parse_err:
                    error_text = f'Не удалось получить тело ответа: {parse_err}'

            LOG.error(f"Error creating JIRA ticket: {e.status_code} - {e.text if hasattr(e, 'text') else ''}")
            LOG.error(f"Response content: {error_text}")
            return None


    def transition_ticket(self, jira_key: str, transition_id: str):
        LOG.info(f"[JIRA] Attempting to transition JIRA ticket '{jira_key}' with transition ID '{transition_id}'")

        if not self.jira:
            LOG.error("[JIRA] client not initialized, aborting ticket transition.")
            return False, None
        try:
            self.jira.transition_issue(jira_key, transition_id)
            updated_issue = self.jira.issue(jira_key)
            new_status = updated_issue.fields.status.name

            LOG.info(f"[JIRA] Ticket '{jira_key}' transitioned successfully to status '{new_status}'")
            return True, new_status

        except JIRAError as e:
            LOG.error(f"[JIRA] Failed to transition JIRA ticket '{jira_key}' to transition_id '{transition_id}': {e}")
            return False, None