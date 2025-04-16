import logging
from flask import current_app

from alerta.exceptions import ApiError, InvalidAction
from alerta.models.alarms import AlarmModel
from alerta.models.enums import Action, Severity, Status, TrendIndication
from alerta.utils.jira import JiraClient
from alerta.utils.format import CustomJSONEncoder
import json

SEVERITY_MAP = {
    Severity.Security: 0,
    Severity.Critical: 1,
    Severity.High: 2,
    Severity.Medium: 3,
    Severity.Major: 4,
    Severity.Minor: 5,
    Severity.Warning: 6,
    Severity.Indeterminate: 7,
    Severity.Informational: 8,
    Severity.Normal: 9,
    Severity.Ok: 10,
    Severity.Cleared: 11,
    Severity.Debug: 12,
    Severity.Trace: 13,
    Severity.Unknown: 14
}
DEFAULT_NORMAL_SEVERITY = Severity.Normal  # 'normal', 'ok', 'cleared'
DEFAULT_INFORM_SEVERITY = Severity.Informational
DEFAULT_PREVIOUS_SEVERITY = Severity.Indeterminate

COLOR_MAP = {
    'severity': {
        Severity.Security: 'blue',
        Severity.Critical: 'red',
        Severity.Major: 'orange',
        Severity.Minor: 'yellow',
        Severity.Warning: 'dodgerblue',
        Severity.Indeterminate: 'lightblue',
        Severity.Cleared: '#00CC00',  # lime green
        Severity.Normal: '#00CC00',
        Severity.Ok: '#00CC00',
        Severity.Informational: '#00CC00',
        Severity.Debug: '#9D006D',  # purple
        Severity.Trace: '#7554BF',  # violet
        Severity.Unknown: 'silver'
    },
    'status': {
        Status.Ack: 'skyblue',
        Status.Shelved: 'skyblue'
    },
    'text': 'black'
}

STATUS_MAP = {
    Status.Open: 'A',
    Status.Ack: 'B',
    Status.Inc: 'C',
    Status.Obs: 'D',
    Status.Pending: 'E',
    Status.Escalated: 'F',
    Status.False_positive: 'G',
    # Status.Flap: 'H',
    Status.Closed: 'I',
    # Status.Unknown: 'J'
}


ACTION_ALL = [
    Action.OPEN,
    Action.ASSIGN,
    Action.ACK,
    Action.UNACK,
    Action.SHELVE,
    Action.UNSHELVE,
    Action.CLOSE,
    Action.EXPIRED,
    Action.TIMEOUT,
    Action.INC,
    Action.AIDONE,
    Action.ESC,
    Action.ESCALATED,
    Action.FALSE_POSITIVE,
    Action.FLAP,
    Action.UNDO
]


class StateMachine(AlarmModel):

    @property
    def valid_severities(self):
        return sorted(StateMachine.Severity, key=StateMachine.Severity.get)

    def register(self, app):
        from alerta.management.views import __version__
        self.name = f'Alerta {__version__}'

        StateMachine.Severity = app.config['SEVERITY_MAP'] or SEVERITY_MAP
        StateMachine.Colors = app.config['COLOR_MAP'] or COLOR_MAP
        StateMachine.Status = STATUS_MAP

        StateMachine.DEFAULT_STATUS = Status.Open
        StateMachine.DEFAULT_NORMAL_SEVERITY = app.config['DEFAULT_NORMAL_SEVERITY'] or DEFAULT_NORMAL_SEVERITY
        StateMachine.DEFAULT_INFORM_SEVERITY = app.config['DEFAULT_INFORM_SEVERITY'] or DEFAULT_INFORM_SEVERITY
        StateMachine.DEFAULT_PREVIOUS_SEVERITY = app.config['DEFAULT_PREVIOUS_SEVERITY'] or DEFAULT_PREVIOUS_SEVERITY

        if StateMachine.DEFAULT_NORMAL_SEVERITY not in StateMachine.Severity:
            raise RuntimeError('DEFAULT_NORMAL_SEVERITY ({}) is not one of {}'.format(
                StateMachine.DEFAULT_NORMAL_SEVERITY, ', '.join(self.valid_severities)))
        if StateMachine.DEFAULT_PREVIOUS_SEVERITY not in StateMachine.Severity:
            raise RuntimeError('DEFAULT_PREVIOUS_SEVERITY ({}) is not one of {}'.format(
                StateMachine.DEFAULT_PREVIOUS_SEVERITY, ', '.join(self.valid_severities)))

        StateMachine.NORMAL_SEVERITY_LEVEL = StateMachine.Severity[StateMachine.DEFAULT_NORMAL_SEVERITY]

    def trend(self, previous, current):
        if previous not in StateMachine.Severity or current not in StateMachine.Severity:
            return TrendIndication.No_Change

        if StateMachine.Severity[previous] > StateMachine.Severity[current]:
            return TrendIndication.More_Severe
        elif StateMachine.Severity[previous] < StateMachine.Severity[current]:
            return TrendIndication.Less_Severe
        else:
            return TrendIndication.No_Change

    def jira_transition(self, alert, transition_id: str):
        jira_key = alert.attributes.get('jira_key')
        if not jira_key:
            logging.warning(f"[JIRA] У алерта нет jira_key, переход '{transition_id}' не выполнен.")
            return False

        jira_client = JiraClient()
        success, new_status = jira_client.transition_ticket(jira_key, transition_id)

        if success:
            logging.info(f"[JIRA] Успешный переход алерта '{alert.id}' (JIRA: {jira_key}) в статус '{new_status}'.")
            alert.attributes['jira_status'] = new_status #TODO может выпилим?
            return True
        else:
            logging.warning(f"[JIRA] Не удалось выполнить переход '{transition_id}' для алерта '{alert.id}' (JIRA: {jira_key}).")
            return False


    def transition(self, alert, current_status=None, previous_status=None, action=None, **kwargs):
        current_status = current_status or StateMachine.DEFAULT_STATUS
        previous_status = previous_status or StateMachine.DEFAULT_STATUS
        current_severity = alert.severity
        previous_severity = alert.previous_severity or StateMachine.DEFAULT_PREVIOUS_SEVERITY
        valid_severities = sorted(StateMachine.Severity, key=StateMachine.Severity.get)
        is_incident = alert.attributes.get('jira_key')
        if current_severity not in StateMachine.Severity:
            raise ApiError(f"Severity ({current_severity}) is not one of {', '.join(valid_severities)}", 400)

        def next_state(rule, severity, status):
            current_app.logger.info(
                'State Transition: Rule #{} STATE={:8s} ACTION={:8s} SET={:8s} '
                'SEVERITY={:13s}-> {:8s} HISTORY={:8s}-> {:8s} => SEVERITY={:8s}, STATUS={:8s}'.format(
                    rule,
                    current_status,
                    action or '',
                    alert.status,
                    previous_severity,
                    current_severity,
                    previous_status,
                    current_status,
                    severity,
                    status
                ))
            return severity, status

        # if an unrecognised action is passed then assume state transition has been handled
        # by a take_action() plugin and return the current severity and status unchanged
        if action and action not in ACTION_ALL:
            return next_state('ACT-1', current_severity, alert.status)

        # if alert has non-default status then assume state transition has been handled
        # by a pre_receive() plugin and return the current severity and status, accounting
        # for auto-closing normal alerts, otherwise unchanged
        if not action and alert.status != StateMachine.DEFAULT_STATUS:
            if StateMachine.Severity[current_severity] == StateMachine.NORMAL_SEVERITY_LEVEL:
                return next_state('SET-1', StateMachine.DEFAULT_NORMAL_SEVERITY, Status.Closed)
            return next_state('SET-*', current_severity, alert.status)

        # state transition determined by operator action, if any, or severity changes
        state = current_status

        if action == Action.UNDO:
            return next_state('UNDO-1', current_severity, previous_status)

        if action == Action.UNACK:
            if state == Status.Ack:
                return next_state('UNACK-1', current_severity, previous_status)
            else:
                raise InvalidAction(f'invalid action for current {state} status')

        if action == Action.UNSHELVE:
            if state == Status.Shelved:
                # as per ISA 18.2 recommendation 11.7.3 manually unshelved alarms transition to previous status
                return next_state('UNSHL-1', current_severity, previous_status)
            else:
                raise InvalidAction(f'invalid action for current {state} status')

        if action == Action.EXPIRED:
            return next_state('EXP-0', current_severity, Status.Expired)

        if action == Action.TIMEOUT:
            if previous_status == Status.Ack:
                return next_state('ACK-0', current_severity, Status.Ack)
            else:
                return next_state('OPEN-0', current_severity, Status.Open)

        if action == Action.FALSE_POSITIVE and state != Status.False_positive and state != Status.Closed:
            if is_incident:
                self.jira_transition(alert, '261')
            return next_state('FALSE-POSITIVE-0', current_severity, Status.False_positive)

        if action == Action.FLAP and not state == Status.Flap:
            return next_state('FLAP-0', current_severity, Status.Flap)

        if action == Action.ESCALATED and state != Status.Escalated and state != Status.Closed:
            return next_state('ESCALATED-0', current_severity, Status.Escalated)

        if action == Action.CLOSE and not state == Status.Closed:
            if is_incident and state == Status.Obs:
                self.jira_transition(alert, '271') # 'Fixed by 24/7'
            elif is_incident and state != Status.Escalated and state != Status.Pending and state != Status.False_positive:
                self.jira_transition(alert, '201') # 'Self-healed'
            return next_state('CLOSE-0', current_severity, Status.Closed)

        if state == Status.Open:
            if action == Action.OPEN:
                raise InvalidAction(f'alert is already in {state} status')
            if action == Action.ACK:
                return next_state('OPEN-1', current_severity, Status.Ack)
            if action == Action.SHELVE:
                return next_state('OPEN-2', current_severity, Status.Shelved)

        if state == Status.Assign:
            pass

        if state == Status.Ack:
            if action == Action.OPEN:
                return next_state('ACK-1', current_severity, Status.Open)
            if action == Action.ACK:
                raise InvalidAction(f'alert is already in {state} status')
            if action == Action.SHELVE:
                return next_state('ACK-2', current_severity, Status.Shelved)
            if action == Action.INC:
                # jira create issue
                return next_state('ACK-4', current_severity, Status.Inc)
            # re-open ack'ed alerts if the severity actually increases
            # not just because the previous severity is the default
            if previous_severity != StateMachine.DEFAULT_PREVIOUS_SEVERITY:
                if self.trend(previous_severity, current_severity) == TrendIndication.More_Severe:
                    return next_state('ACK-3', current_severity, Status.Open)


        if state == Status.Inc and is_incident:
            if action == Action.AIDONE:
                self.jira_transition(alert, '81')
                return next_state('OBS-0', current_severity, Status.Obs)
            elif action == Action.ESC:
                self.jira_transition(alert, '161')
                return next_state('PEN-0', current_severity, Status.Pending)
        elif state == Status.Inc:
            if action == Action.AIDONE:
                raise InvalidAction(f'Jira issue is not created yet. Please try again few seconds later. 🙃')
            elif action == Action.ESC:
                raise InvalidAction(f'Jira issue is not created yet. Please try again few seconds later. 🙃')

        if state == Status.Obs and is_incident:
            if action == Action.ESC:
                self.jira_transition(alert, '161')
                return next_state('PEN-1', current_severity, Status.Pending)
            elif action == Action.AIDONE: # TODO for several AI done during observation
                return next_state('OBS-2', current_severity, current_status)

        if state == Status.Shelved:
            if action == Action.OPEN:
                return next_state('SHL-1', current_severity, Status.Open)
            if action == Action.ACK:
                raise InvalidAction(f'invalid action for current {state} status')
            if action == Action.SHELVE:
                raise InvalidAction(f'alert is already in {state} status')

        if state == Status.Blackout:
            if previous_status != Status.Blackout:
                return next_state('BLK-2', current_severity, previous_status)
            else:
                return next_state('BLK-*', current_severity, alert.status)

        if state == Status.Closed:
            if action == Action.OPEN:
                return next_state('CLS-1', previous_severity, Status.Open)
            if action == Action.ACK:
                raise InvalidAction(f'invalid action for current {state} status')
            if action == Action.SHELVE:
                raise InvalidAction(f'invalid action for current {state} status')
            if action == Action.FALSE_POSITIVE:
                raise InvalidAction(f'invalid action for current {state} status')
            if action == Action.CLOSE:
                raise InvalidAction(f'alert is already in {state} status')

            if StateMachine.Severity[current_severity] != StateMachine.NORMAL_SEVERITY_LEVEL:
                if previous_status == Status.Shelved:
                    return next_state('CLS-2', previous_severity, Status.Shelved)
                else:
                    return next_state('CLS-3', previous_severity, Status.Open)

        if state == Status.Expired:
            if action and action != Action.OPEN:
                raise InvalidAction(f'invalid action for current {state} status')
            if StateMachine.Severity[current_severity] != StateMachine.NORMAL_SEVERITY_LEVEL:
                return next_state('EXP-1', current_severity, Status.Open)

        if state != Status.Open and action:
            logging.error(f'No action found for state: {state}, action: {action}, alert_id: {alert.id} ')
        return next_state('ALL-*', current_severity, current_status)

    @staticmethod
    def is_suppressed(alert):
        return alert.status == Status.Blackout
