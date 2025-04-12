import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Union, Tuple
from uuid import uuid4

from flask import current_app

from alerta.app import db
from alerta.database.base import Query
from alerta.models.enums import Status
from alerta.utils.format import DateTime
from alerta.utils.response import absolute_url

JSON = Dict[str, Any]
NoneType = type(None)


class Issue:

    def __init__(self, summary: str, severity: str, **kwargs) -> None:
        if not summary:
            raise ValueError('Missing mandatory value for "summary"')
        if not severity:
            raise ValueError('Missing mandatory value for "severity"')
        if any(['.' in key for key in kwargs.get('attributes', dict()).keys()]) \
                or any(['$' in key for key in kwargs.get('attributes', dict()).keys()]):
            raise ValueError('Attribute keys must not contain "." or "$"')
        for attr in ['create_time', 'last_alert_time', 'resolve_time']:
            if not isinstance(kwargs.get(attr), (datetime, NoneType)):  # type: ignore
                raise ValueError(f"Attribute '{attr}' must be datetime type")

        self.id = kwargs.get('id', str(uuid4()))
        self.summary = summary
        self.severity = severity
        self.host_critical = kwargs.get('host_critical', '1')
        self.duty_admin = kwargs.get('duty_admin')
        self.description = kwargs.get('description', '')
        self.status = kwargs.get('status', Status.Open)
        self.status_duration = kwargs.get('status_duration')
        self.create_time = kwargs.get('create_time', datetime.utcnow())
        self.last_alert_time = kwargs.get('last_alert_time')
        self.resolve_time = kwargs.get('resolve_time')
        self.pattern_id = kwargs.get('pattern_id')
        self.inc_key = kwargs.get('inc_key')
        self.slack_link = kwargs.get('slack_link')
        self.disaster_link = kwargs.get('disaster_link')
        self.escalation_group = kwargs.get('escalation_group')
        self.alerts = kwargs.get('alerts', [])
        self.hosts = kwargs.get('hosts', [])
        self.project_groups = kwargs.get('project_groups', [])
        self.info_systems = kwargs.get('info_systems', [])
        self.attributes = kwargs.get('attributes', {})
        self.master_incident = kwargs.get('master_incident')
        self.history = kwargs.get('history', [])

    @classmethod
    def parse(cls, json: JSON) -> 'Issue':
        if not isinstance(json, dict):
            raise ValueError('Request must be a JSON object')

        id = json.get('id')
        summary = json.get('summary')
        severity = json.get('severity')
        host_critical = json.get('host_critical', '1')
        duty_admin = json.get('duty_admin')
        description = json.get('description', '')
        status = json.get('status', Status.Open)
        status_duration = json.get('status_duration')
        create_time = json.get('create_time')
        last_alert_time = json.get('last_alert_time')
        resolve_time = json.get('resolve_time')
        pattern_id = json.get('pattern_id')
        inc_key = json.get('inc_key')
        slack_link = json.get('slack_link')
        disaster_link = json.get('disaster_link')
        escalation_group = json.get('escalation_group')
        alerts = json.get('alerts', [])
        hosts = json.get('hosts', [])
        project_groups = json.get('project_groups', [])
        info_systems = json.get('info_systems', [])
        attributes = json.get('attributes', {})
        master_incident = json.get('master_incident')
        history = json.get('history', [])

        return cls(
            id=id,
            summary=summary,
            severity=severity,
            host_critical=host_critical,
            duty_admin=duty_admin,
            description=description,
            status=status,
            status_duration=status_duration,
            create_time=create_time,
            last_alert_time=last_alert_time,
            resolve_time=resolve_time,
            pattern_id=pattern_id,
            inc_key=inc_key,
            slack_link=slack_link,
            disaster_link=disaster_link,
            escalation_group=escalation_group,
            alerts=alerts,
            hosts=hosts,
            project_groups=project_groups,
            info_systems=info_systems,
            attributes=attributes,
            master_incident=master_incident,
            history=history
        )

    @property
    def serialize(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'href': absolute_url('/issue/' + self.id),
            'summary': self.summary,
            'severity': self.severity,
            'host_critical': self.host_critical,
            'duty_admin': self.duty_admin,
            'description': self.description,
            'status': self.status,
            'status_duration': self.status_duration,
            'create_time': DateTime.iso8601(self.create_time),
            'last_alert_time': DateTime.iso8601(self.last_alert_time) if self.last_alert_time else None,
            'resolve_time': DateTime.iso8601(self.resolve_time) if self.resolve_time else None,
            'pattern_id': self.pattern_id,
            'inc_key': self.inc_key,
            'slack_link': self.slack_link,
            'disaster_link': self.disaster_link,
            'escalation_group': self.escalation_group,
            'alerts': self.alerts,
            'hosts': self.hosts,
            'project_groups': self.project_groups,
            'info_systems': self.info_systems,
            'attributes': self.attributes,
            'master_incident': self.master_incident,
            'history': self.history
        }

    def get_id(self, short: bool = False) -> str:
        if short:
            return self.id[:8]
        return self.id

    def get_body(self, history: bool = True) -> Dict[str, Any]:
        body = self.serialize
        if not history:
            body.pop('history', None)
        return body

    def __repr__(self) -> str:
        return f'Issue(id={self.id}, summary={self.summary}, severity={self.severity}, status={self.status})'

    @classmethod
    def from_document(cls, doc: Dict[str, Any]) -> 'Issue':
        return cls(
            id=doc.get('_id'),
            summary=doc.get('summary'),
            severity=doc.get('severity'),
            host_critical=doc.get('host_critical', '1'),
            duty_admin=doc.get('duty_admin'),
            description=doc.get('description', ''),
            status=doc.get('status', Status.Open),
            status_duration=doc.get('status_duration'),
            create_time=doc.get('create_time'),
            last_alert_time=doc.get('last_alert_time'),
            resolve_time=doc.get('resolve_time'),
            pattern_id=doc.get('pattern_id'),
            inc_key=doc.get('inc_key'),
            slack_link=doc.get('slack_link'),
            disaster_link=doc.get('disaster_link'),
            escalation_group=doc.get('escalation_group'),
            alerts=doc.get('alerts', []),
            hosts=doc.get('hosts', []),
            project_groups=doc.get('project_groups', []),
            info_systems=doc.get('info_systems', []),
            attributes=doc.get('attributes', {}),
            master_incident=doc.get('master_incident'),
            history=doc.get('history', [])
        )

    @classmethod
    def from_record(cls, rec) -> 'Issue':
        return cls(
            id=rec.id,
            summary=rec.summary,
            severity=rec.severity,
            host_critical=rec.host_critical,
            duty_admin=rec.duty_admin,
            description=rec.description,
            status=rec.status,
            status_duration=rec.status_duration,
            create_time=rec.create_time,
            last_alert_time=rec.last_alert_time,
            resolve_time=rec.resolve_time,
            pattern_id=rec.pattern_id,
            inc_key=rec.inc_key,
            slack_link=rec.slack_link,
            disaster_link=rec.disaster_link,
            escalation_group=rec.escalation_group,
            alerts=rec.alerts,
            hosts=rec.hosts,
            project_groups=rec.project_groups,
            info_systems=rec.info_systems,
            attributes=rec.attributes,
            master_incident=rec.master_incident,
            history=rec.history
        )

    @classmethod
    def from_db(cls, r: Union[Dict, Tuple]) -> 'Issue':
        if isinstance(r, dict):
            return cls.from_document(r)
        return cls.from_record(r)

    def create(self) -> 'Issue':
        return db.create_issue(self)

    def update(self) -> 'Issue':
        return db.update_issue(self)

    def delete(self) -> bool:
        return db.delete_issue(self.id)

    @staticmethod
    def find_by_id(id: str) -> Optional['Issue']:
        return db.get_issue(id)

    @staticmethod
    def find_by_inc_key(inc_key: str) -> Optional['Issue']:
        return db.get_issue_by_inc_key(inc_key)

    @staticmethod
    def find_all(query: Query = None, page: int = 1, page_size: int = 1000) -> List['Issue']:
        return db.get_issues(query, page, page_size)

    @staticmethod
    def get_count(query: Query = None) -> Dict[str, Any]:
        return db.get_issue_count(query)

    @staticmethod
    def get_counts_by_status(query: Query = None) -> Dict[str, Any]:
        return db.get_issue_counts_by_status(query)

    @staticmethod
    def get_counts_by_severity(query: Query = None) -> Dict[str, Any]:
        return db.get_issue_counts_by_severity(query)

    @staticmethod
    def get_top10_count(query: Query = None) -> List[Dict[str, Any]]:
        return db.get_top10_issue_count(query)

    @staticmethod
    def get_topn_count(query: Query = None, topn: int = 10) -> List[Dict[str, Any]]:
        return db.get_topn_issue_count(query, topn)

    @staticmethod
    def get_environments(query: Query = None) -> List[str]:
        return db.get_issue_environments(query)

    @staticmethod
    def get_services(query: Query = None) -> List[str]:
        return db.get_issue_services(query)

    @staticmethod
    def get_groups(query: Query = None) -> List[str]:
        return db.get_issue_groups(query)

    @staticmethod
    def get_tags(query: Query = None) -> List[str]:
        return db.get_issue_tags(query)

    def add_history(self, action: str, user: str, details: str = '') -> None:
        history_entry = {
            'timestamp': datetime.utcnow(),
            'action': action,
            'user': user,
            'details': details
        }
        self.history.append(history_entry)
        self.update()

    def get_history(self, page: int = 1, page_size: int = 100) -> List[Dict[str, Any]]:
        return self.history[(page - 1) * page_size:page * page_size]

    def set_status(self, status: str, text: str = '') -> 'Issue':
        self.status = status
        if text:
            self.description = text
        self.update()
        return self

    def add_alert(self, alert_id: str) -> 'Issue':
        if alert_id not in self.alerts:
            self.alerts.append(alert_id)
            self.update()
        return self

    def remove_alert(self, alert_id: str) -> 'Issue':
        if alert_id in self.alerts:
            self.alerts.remove(alert_id)
            self.update()
        return self

    def update_last_alert_time(self) -> 'Issue':
        self.last_alert_time = datetime.utcnow()
        self.update()
        return self

    def resolve(self) -> 'Issue':
        self.status = Status.Closed
        self.resolve_time = datetime.utcnow()
        self.update()
        return self 