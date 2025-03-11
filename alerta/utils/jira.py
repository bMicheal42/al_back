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

        print(f"_connect to JIRA_URL {JIRA_URL} via JIRA_USER: {JIRA_USER}")
        return JIRA(
            options={'server': JIRA_URL, 'timeout': '4', 'max_retries': '4', 'verify': True},
            basic_auth=(JIRA_USER, JIRA_PWD)
        )

    def create_ticket(self, args: Dict[str, str], project: str = None, infosystem: str = None, projectgroup: str = None):
        """Creates a JIRA ticket based on the given parameters."""
        # FIXME not used for now..
        # JIRA_SEVERITY = app.config['JIRA_SEVERITY']
        logging.warning(f"[JIRA] Creating ticket: {json.dumps(args, indent=4, ensure_ascii=False)}")
        JIRA_PROJECTGROUPS = app.config['JIRA_PROJECTGROUPS']
        JIRA_OWNERS_GROUPS = app.config['JIRA_OWNERS_GROUPS']

        if not projectgroup or not projectgroup in JIRA_PROJECTGROUPS:
            projectgroup = 'Other'
        if not infosystem:
            infosystem = 'other'
        if not project:
            project = app.config['JIRA_PROJECT']

        try:
            if not self.jira:
                LOG.warning(f"Not connected to JIRA, skipping ticket creation")
                return None

            owner_1 = args.get('Owner_1', '')
            owner_2 = args.get('Owner_2', '')
            escalation_group1 = JIRA_OWNERS_GROUPS.get(owner_1, 'JIRA_Duty-engineers-team')
            escalation_group2 = JIRA_OWNERS_GROUPS.get(owner_2, '')
            username = 'a.skhomenko' if args['username'] == 'alertademo' else args['username']

            ticket = self.jira.create_issue(
                project=project,
                summary=f"{args['host']}: {args['text']}",
                description=json.dumps({'attributes': args['attributes'], 'tags': args['tags']}, indent=4, ensure_ascii=False),
                issuetype={'name': 'Incident'},
                #assignee={'name': args.username},
                #reporter={'name': args.username},
                customfield_19702={'name': 'JIRA_Duty-engineers-team'},   # Workgroup
                customfield_19819={'value': projectgroup},                # Project Group // AF CP Lab RETN
                # customfield_11915=[infosystem],                         # Info System // jira not accepting..
                customfield_19502=[{'key': 'SC-39772'}],                  # Service ZBX Incident
                customfield_19832={'name': username},                     # MonSpec
                customfield_19823=args['host'],                           # Host
                customfield_19920=args['Owner_1'],                        # Slack Group
                customfield_19921=args['Owner_2'],                        # Reserve Slack Group
                customfield_19918=escalation_group1,                      # Escalation Group
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
            print(f"Error creating JIRA ticket: {e}")
            return None

    def transition_ticket(self, jira_key: str, transition_name: str, resolution: Optional[str] = None):
        """Transitions a Jira ticket to the specified transition state."""
        try:
            if not self.jira:
                LOG.warning(f"Not connected to JIRA, skipping ticket transition")
                return None

            # Get available transitions for the ticket
            transitions = {} if resolution else self.jira.transitions(jira_key)
            available_transitions = {transition['name']: transition['id'] for transition in transitions}

            # Check if the requested transition is available (or bypass it if resolution is passed)
            if transition_name in available_transitions or resolution:
                transition_id = '261' if resolution else available_transitions[transition_name]
                if resolution:
                    logging.warning(f"[JIRA] Making transition for {jira_key} with id: {transition_id}, resolution: {resolution}")
                    self.jira.transition_issue(jira_key, transition_id, fields={"resolution": {"name": resolution}})
                else:
                    logging.warning(f"[JIRA] Making transition for {jira_key} with id: {transition_id}")
                    self.jira.transition_issue(jira_key, transition_id)

                updated_issue = self.jira.issue(jira_key)
                new_status = updated_issue.fields.status.name
                logging.warning(f"[JIRA] Transitioned {jira_key} with '{transition_id}' to status: {new_status}")

                return True, new_status
            else:
                LOG.warning(f"[JIRA] Transition '{transition_name}' not available for ticket {jira_key}")
                return False, None

        except JIRAError as e:
            LOG.warning(f"Error during JIRA transition for ticket {jira_key}: {e}")
            return None, None
