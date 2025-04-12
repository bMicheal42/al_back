import logging
from datetime import datetime

from alerta.utils.response import absolute_url


class IssueHistory:

    def __init__(self, id, issue_id, **kwargs):
        self.id = id
        self.issue_id = issue_id
        self.summary = kwargs.get('summary', None)
        self.severity = kwargs.get('severity', None)
        self.status = kwargs.get('status', None)
        self.text = kwargs.get('text', None)
        self.change_type = kwargs.get('change_type', kwargs.get('type', None)) or ''
        self.update_time = kwargs.get('update_time', None) or datetime.utcnow()
        self.user = kwargs.get('user', None)
        self.assigned_to = kwargs.get('assigned_to', None)
        self.labels = kwargs.get('labels', None) or list()
        self.attributes = kwargs.get('attributes', None) or dict()

    @property
    def serialize(self):
        return {
            'id': self.id,
            'href': absolute_url('/issue/' + self.issue_id + '/history/' + self.id),
            'issue_id': self.issue_id,
            'summary': self.summary,
            'severity': self.severity,
            'status': self.status,
            'text': self.text,
            'type': self.change_type,
            'updateTime': self.update_time,
            'user': self.user,
            'assigned_to': self.assigned_to,
            'labels': self.labels,
            'attributes': self.attributes
        }

    def __repr__(self):
        return 'IssueHistory(id={!r}, issue_id={!r}, summary={!r}, severity={!r}, status={!r}, type={!r})'.format(
            self.id, self.issue_id, self.summary, self.severity, self.status, self.change_type)

    @classmethod
    def from_document(cls, doc):
        return IssueHistory(
            id=doc.get('id', None),
            issue_id=doc.get('issue_id'),
            summary=doc.get('summary', None),
            severity=doc.get('severity', None),
            status=doc.get('status', None),
            text=doc.get('text', None),
            change_type=doc.get('type', None),
            update_time=doc.get('updateTime', None),
            user=doc.get('user', None),
            assigned_to=doc.get('assigned_to', None),
            labels=doc.get('labels', None) or list(),
            attributes=doc.get('attributes', None) or dict()
        )

    @classmethod
    def from_record(cls, rec):
        return IssueHistory(
            id=rec.id,
            issue_id=rec.issue_id,
            summary=rec.summary,
            severity=rec.severity,
            status=rec.status,
            text=rec.text,
            change_type=rec.type,
            update_time=rec.update_time,
            user=getattr(rec, 'user', None),
            assigned_to=getattr(rec, 'assigned_to', None),
            labels=getattr(rec, 'labels', None) or list(),
            attributes=getattr(rec, 'attributes', None) or dict()
        )

    @classmethod
    def from_db(cls, r):
        if isinstance(r, dict):
            return cls.from_document(r)
        elif isinstance(r, tuple):
            return cls.from_record(r)


class RichIssueHistory:

    def __init__(self, issue_id, **kwargs):
        self.id = kwargs.get('id', None)
        self.issue_id = issue_id
        self.summary = kwargs.get('summary', None)
        self.severity = kwargs.get('severity', None)
        self.status = kwargs.get('status', None)
        self.text = kwargs.get('text', None)
        self.change_type = kwargs.get('change_type', kwargs.get('type', None))
        self.update_time = kwargs.get('update_time', None)
        self.user = kwargs.get('user', None)
        self.assigned_to = kwargs.get('assigned_to', None)
        self.labels = kwargs.get('labels', None) or list()
        self.attributes = kwargs.get('attributes', None) or dict()
        self.customer = kwargs.get('customer', None) 