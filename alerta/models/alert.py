import logging
import os
import platform
import sys
import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional  # noqa
from typing import Any, Dict, List, Tuple, Union
from uuid import uuid4

from flask import current_app, g

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from alerta.app import alarm_model, db
from alerta.database.base import Query
from alerta.models.enums import ChangeType
from alerta.models.history import History, RichHistory
from alerta.models.note import Note
from alerta.utils.format import DateTime
from alerta.utils.hooks import status_change_hook
from alerta.utils.response import absolute_url

from alerta.models.issue import Issue
JSON = Dict[str, Any]
NoneType = type(None)


class Alert:

    def __init__(self, resource: str, event: str, **kwargs) -> None:

        if not resource:
            raise ValueError('Missing mandatory value for "resource"')
        if not event:
            raise ValueError('Missing mandatory value for "event"')
        if any(['.' in key for key in kwargs.get('attributes', dict()).keys()]) \
                or any(['$' in key for key in kwargs.get('attributes', dict()).keys()]):
            raise ValueError('Attribute keys must not contain "." or "$"')
        if isinstance(kwargs.get('value', None), int):
            kwargs['value'] = str(kwargs['value'])
        for attr in ['create_time', 'receive_time', 'last_receive_time']:
            if not isinstance(kwargs.get(attr), (datetime, NoneType)):  # type: ignore
                raise ValueError(f"Attribute '{attr}' must be datetime type")

        timeout = kwargs.get('timeout') if kwargs.get('timeout') is not None else current_app.config['ALERT_TIMEOUT']
        try:
            timeout = int(timeout)  # type: ignore
        except ValueError:
            raise ValueError(f"Could not convert 'timeout' value of '{timeout}' to an integer")
        if timeout < 0:
            raise ValueError(f"Invalid negative 'timeout' value ({timeout})")

        self.id = kwargs.get('id') or str(uuid4())
        self.resource = resource
        self.event = event
        self.environment = kwargs.get('environment', None) or ''
        self.severity = kwargs.get('severity', None) or alarm_model.DEFAULT_NORMAL_SEVERITY
        self.correlate = kwargs.get('correlate', None) or list()
        if self.correlate and event not in self.correlate:
            self.correlate.append(event)
        self.status = kwargs.get('status', None) or alarm_model.DEFAULT_STATUS
        self.service = kwargs.get('service', None) or list()
        self.group = kwargs.get('group', None) or 'Misc'
        self.value = kwargs.get('value', None)
        self.text = kwargs.get('text', None) or ''
        self.tags = kwargs.get('tags', None) or list()
        self.attributes = kwargs.get('attributes', None) or {'duplicate alerts': []}
        self.origin = kwargs.get('origin', None) or f'{os.path.basename(sys.argv[0])}/{platform.uname()[1]}'
        self.event_type = kwargs.get('event_type', kwargs.get('type', None)) or 'exceptionAlert'
        self.create_time = kwargs.get('create_time', None) or datetime.utcnow()
        self.timeout = timeout
        self.raw_data = kwargs.get('raw_data', None)
        self.customer = kwargs.get('customer', None)

        self.duplicate_count = kwargs.get('duplicate_count', None)
        self.repeat = kwargs.get('repeat', None)
        self.previous_severity = kwargs.get('previous_severity', None)
        self.trend_indication = kwargs.get('trend_indication', None)
        self.receive_time = kwargs.get('receive_time', None) or datetime.utcnow()
        self.last_receive_id = kwargs.get('last_receive_id', None)
        self.last_receive_time = kwargs.get('last_receive_time', None)
        self.update_time = kwargs.get('update_time', None)
        self.history = kwargs.get('history', None) or list()
        self.issue_id = kwargs.get('issue_id', None)

    @classmethod
    def parse(cls, json: JSON) -> 'Alert':
        if not isinstance(json.get('correlate', []), list):
            raise ValueError('correlate must be a list')
        if not isinstance(json.get('service', []), list):
            raise ValueError('service must be a list')
        if not isinstance(json.get('tags', []), list):
            raise ValueError('tags must be a list')
        if not isinstance(json.get('attributes', {}), dict):
            raise ValueError('attributes must be a JSON object')
        if not isinstance(json.get('timeout') if json.get('timeout', None) is not None else 0, int):
            raise ValueError('timeout must be an integer')
        if json.get('customer', None) == '':
            raise ValueError('customer must not be an empty string')

        # tags transform: .strip() for strings or as is for other types
        raw_tags = json.get('tags', list())
        transformed_tags = [tag.strip() if isinstance(tag, str) else tag for tag in raw_tags]

        return Alert(
            id=json.get('id', None),
            resource=json.get('resource', None),
            event=json.get('event', None),
            environment=json.get('environment', None),
            severity=json.get('severity', None),
            correlate=json.get('correlate', list()),
            status=json.get('status', None),
            service=json.get('service', list()),
            group=json.get('group', None),
            value=json.get('value', None),
            text=json.get('text', None),
            tags=transformed_tags,
            attributes=json.get('attributes', dict()),
            origin=json.get('origin', None),
            event_type=json.get('type', None),
            create_time=DateTime.parse(json['createTime']) if 'createTime' in json else None,
            timeout=json.get('timeout', None),
            raw_data=json.get('rawData', None),
            customer=json.get('customer', None)
        )

    @property
    def serialize(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'href': absolute_url('/alert/' + self.id),
            'resource': self.resource,
            'event': self.event,
            'environment': self.environment,
            'severity': self.severity,
            'correlate': self.correlate,
            'status': self.status,
            'service': self.service,
            'group': self.group,
            'value': self.value,
            'text': self.text,
            'tags': self.tags,
            'attributes': self.attributes,
            'origin': self.origin,
            'type': self.event_type,
            'createTime': self.create_time,
            'timeout': self.timeout,
            'rawData': self.raw_data,
            'customer': self.customer,
            'duplicateCount': self.duplicate_count,
            'repeat': self.repeat,
            'previousSeverity': self.previous_severity,
            'trendIndication': self.trend_indication,
            'receiveTime': self.receive_time,
            'lastReceiveId': self.last_receive_id,
            'lastReceiveTime': self.last_receive_time,
            'updateTime': self.update_time,
            'history': [h.serialize for h in sorted(self.history, key=lambda x: x.update_time)],
            'issue_id': self.issue_id
        }

    def get_id(self, short: bool = False) -> str:
        return self.id[:8] if short else self.id

    def get_body(self, history: bool = True) -> Dict[str, Any]:
        body = self.serialize
        body.update({
            key: DateTime.iso8601(body[key]) for key in ['createTime', 'lastReceiveTime', 'receiveTime', 'updateTime'] if body[key]
        })
        if not history:
            body['history'] = []
        return body

    def __repr__(self) -> str:
        return 'Alert(id={!r}, environment={!r}, resource={!r}, event={!r}, severity={!r}, status={!r}, customer={!r})'.format(
            self.id, self.environment, self.resource, self.event, self.severity, self.status, self.customer
        )

    @classmethod
    def from_document(cls, doc: Dict[str, Any]) -> 'Alert':
        return Alert(
            id=doc.get('id', None) or doc.get('_id'),
            resource=doc.get('resource', None),
            event=doc.get('event', None),
            environment=doc.get('environment', None),
            severity=doc.get('severity', None),
            correlate=doc.get('correlate', list()),
            status=doc.get('status', None),
            service=doc.get('service', list()),
            group=doc.get('group', None),
            value=doc.get('value', None),
            text=doc.get('text', None),
            tags=doc.get('tags', list()),
            attributes=doc.get('attributes', dict()),
            origin=doc.get('origin', None),
            event_type=doc.get('type', None),
            create_time=doc.get('createTime', None),
            timeout=doc.get('timeout', None),
            raw_data=doc.get('rawData', None),
            customer=doc.get('customer', None),
            duplicate_count=doc.get('duplicateCount', None),
            repeat=doc.get('repeat', None),
            previous_severity=doc.get('previousSeverity', None),
            trend_indication=doc.get('trendIndication', None),
            receive_time=doc.get('receiveTime', None),
            last_receive_id=doc.get('lastReceiveId', None),
            last_receive_time=doc.get('lastReceiveTime', None),
            update_time=doc.get('updateTime', None),
            history=[History.from_db(h) for h in doc.get('history', list())],
            issue_id=doc.get('issue_id', None)
        )

    @classmethod
    def from_record(cls, rec) -> 'Alert':
        return Alert(
            id=rec.id,
            resource=rec.resource,
            event=rec.event,
            environment=rec.environment,
            severity=rec.severity,
            correlate=rec.correlate,
            status=rec.status,
            service=rec.service,
            group=rec.group,
            value=rec.value,
            text=rec.text,
            tags=rec.tags,
            attributes=dict(rec.attributes),
            origin=rec.origin,
            event_type=rec.type,
            create_time=rec.create_time,
            timeout=rec.timeout,
            raw_data=rec.raw_data,
            customer=rec.customer,
            duplicate_count=rec.duplicate_count,
            repeat=rec.repeat,
            previous_severity=rec.previous_severity,
            trend_indication=rec.trend_indication,
            receive_time=rec.receive_time,
            last_receive_id=rec.last_receive_id,
            last_receive_time=rec.last_receive_time,
            update_time=getattr(rec, 'update_time'),
            history=[History.from_db(h) for h in rec.history],
            issue_id=getattr(rec, 'issue_id', None)
        )

    @classmethod
    def from_db(cls, r: Union[Dict, Tuple]) -> 'Alert':
        if isinstance(r, dict):
            return cls.from_document(r)
        elif isinstance(r, tuple):
            return cls.from_record(r)

    def are_potential_duplicates(self) -> Optional[List['Alert']]:
        """Return potential duplicate alerts or None"""
        potential_duplicates = db.are_potential_duplicates(self)
        if not potential_duplicates:
            return None
        return [Alert.from_db(record) for record in potential_duplicates]

    @staticmethod
    def _parse_COSINUS_SEARCH(query):
        if "COSINUS_SEARCH(" not in query:
            return [], query
        pattern = r"COSINUS_SEARCH\((.*?)\)"
        matches = re.findall(pattern, query)
        keys = matches[0].split(',') if matches else []

        keys = [key.strip("'") for key in keys]
        new_query = re.sub(pattern, "1=1", query)

        return keys, new_query

    @staticmethod
    def _calculate_COSINUS_SEARCH(alert: 'Alert', matches: List['Alert'], keys: List[str]) -> List[Dict[str, float]]:
        cosinus_dict = {}
        vectorizer = TfidfVectorizer()

        for match in matches:
            cosinus_dict[match.id] = {}
            overall_score = 1.0

            for key in keys:
                alert_field = getattr(alert, key, None)
                match_field = getattr(match, key, None)
                if not alert_field or not match_field:
                    continue  # no key - skip

                fidf_matrix = vectorizer.fit_transform([alert_field, match_field])
                similarity = cosine_similarity(fidf_matrix[0:1], fidf_matrix[1:2])[0][0]
                logging.debug(f"cos similarity: {similarity} for {alert.id} and {match.id} on key {key}")
                cosinus_dict[match.id][key] = similarity
                overall_score *= similarity

            cosinus_dict[match.id]['score'] = overall_score
            cosinus_dict[match.id]['match'] = match

        result = [{
            'id': match_id,
            'score': data['score'],
            'match': data['match']
        } for match_id, data in cosinus_dict.items() if data['score'] > 0.5]

        return sorted(result, key=lambda x: float(x['score']), reverse=True)

    def pattern_match_duplicated(self, alert=None, pattern_query=None) -> Optional[List['Alert']]:
        """Return potential duplicate alerts found by pattern or None"""
        if not pattern_query:
            return None
        if alert is None:
            alert = self
        cosinus_keys, query = Alert._parse_COSINUS_SEARCH(pattern_query)
        potential_duplicates = db.pattern_match_duplicated(alert, query)
        if not potential_duplicates:
            return None
        if cosinus_keys:
            cosinus_matches = Alert._calculate_COSINUS_SEARCH(alert, potential_duplicates, cosinus_keys)
            return [Alert.from_db(record['match']) for record in cosinus_matches]

        return [Alert.from_db(record) for record in potential_duplicates]

    def pattern_match_childrens(self, parent_alert=None, child_alert_ids=None, pattern_query=None):
        if not pattern_query or not child_alert_ids:
            return None
        if parent_alert is None:
            parent_alert = self

        cosinus_keys, query = Alert._parse_COSINUS_SEARCH(pattern_query)

        is_matched = db.all_children_match_pattern(parent_alert, child_alert_ids, query)

        if not is_matched:
            return None

        if cosinus_keys:
            potential_matches = Alert.find_by_ids(child_alert_ids)
            cosinus_matches = Alert._calculate_COSINUS_SEARCH(parent_alert, potential_matches, cosinus_keys)
            return [Alert.from_db(record['match']) for record in cosinus_matches]

        return [Alert.from_db(alert_id) for alert_id in child_alert_ids]

    def get_children(self) -> List['Alert']:
        duplicates_ids = self.attributes.get('duplicate alerts', [])
        return Alert.find_by_ids(duplicates_ids)

    def is_correlated(self) -> Optional['Alert']:
        """Return correlated alert or None"""
        return Alert.from_db(db.is_correlated(self))

    def is_flapping(self, window: int = 1800, count: int = 2) -> bool:
        return db.is_flapping(self, window, count)

    def get_status_and_value(self):
        return [(h.status, h.value) for h in self.get_alert_history(self, page=1, page_size=10) if h.status]

    def _get_hist_info(self, action=None):
        h_loop = self.get_alert_history(alert=self)
        if not h_loop:
            return None, None, None, None

        current_status = h_loop[0].status
        current_value = h_loop[0].value

        if len(h_loop) == 1:
            return current_status, current_value, None, None
        if action == ChangeType.unack:
            find = ChangeType.ack
        elif action == ChangeType.unshelve:
            find = ChangeType.shelve
        else:
            find = None

        if find:
            for h, h_next in zip(h_loop, h_loop[1:]):
                if h.change_type == find:
                    return current_status, current_value, h_next.status, h_next.timeout


        return current_status, current_value, h_loop[1].status, h_loop[1].timeout

    def deduplicate(self, duplicate_alert) -> 'Alert':
        now = datetime.utcnow()
        id = self.id
        return Alert.from_db(db.dedup_alert(id, duplicate_alert.id, now))
    
    # correlate an alert
    def update(self, correlate_with) -> 'Alert':
        now = datetime.utcnow()

        self.previous_severity = db.get_severity(self)
        self.trend_indication = alarm_model.trend(self.previous_severity, self.severity)

        status, _, previous_status, _ = self._get_hist_info()
        _, new_status = alarm_model.transition(
            alert=self,
            current_status=status,
            previous_status=previous_status
        )
        logging.warning(f"Update transition for '{self.id}', prev_status: {previous_status}, status: {status}, new_status: {new_status}")

        self.duplicate_count = 0
        self.repeat = False
        self.receive_time = now
        self.last_receive_id = self.id
        self.last_receive_time = now

        if new_status != status:
            r = status_change_hook.send(correlate_with, status=new_status, text=self.text)
            _, (_, new_status, text) = r[0]
            self.update_time = now
        else:
            text = self.text

        history = [History(
            id=self.id,
            event=self.event,
            severity=self.severity,
            status=new_status,
            value=self.value,
            text=text,
            change_type=ChangeType.severity,
            update_time=self.create_time,
            user=g.login,
            timeout=self.timeout
        )]

        self.status = new_status
        return Alert.from_db(db.correlate_alert(self, history))

    # create an alert
    def create(self) -> 'Alert':
        now = datetime.utcnow()

        trend_indication = alarm_model.trend(alarm_model.DEFAULT_PREVIOUS_SEVERITY, self.severity)

        _, self.status = alarm_model.transition(
            alert=self
        )

        logging.warning(f"Create transition for '{self.id}', status: {self.status}")

        self.duplicate_count = 0
        self.repeat = False
        self.previous_severity = alarm_model.DEFAULT_PREVIOUS_SEVERITY
        self.trend_indication = trend_indication
        self.receive_time = now
        self.last_receive_id = self.id
        self.last_receive_time = now
        self.update_time = now
        self.attributes['incident'] = True
        self.attributes['wasIncident'] = True
        self.attributes['duplicate alerts'] = []

        self.history = [History(
            id=self.id,
            event=self.event,
            severity=self.severity,
            status=self.status,
            value=self.value,
            text=self.text,
            change_type=ChangeType.new,
            update_time=self.create_time,
            user=g.login,
            timeout=self.timeout
        )]

        return Alert.from_db(db.create_alert(self))

    # create a new alert from zabbix or update+return already associated with same event alert
    def from_zabbix_create(self) -> ['Alert', bool]:
        zabbix_id = self.attributes.get('zabbix_id')
        if zabbix_id:
            found = Alert.find_by_zabbix_meta(zabbix_id, self.origin)
            resolved_in_zabbix = self.attributes.get('zabbix_status', None) == 'OK'
            if found:
                returning = found.pop()
                if self.tags:
                    new_tags = self.tags
                    returning.tags = new_tags
                    returning.update_tags(new_tags)

                will_update_attributes = False
                fields_to_check = ['zabbix_severity', 'zabbix_status']

                for field in fields_to_check:
                    new_value = self.attributes.get(field)
                    if new_value and new_value != returning.attributes.get(field):
                        returning.attributes[field] = new_value
                        will_update_attributes = True

                if will_update_attributes:
                    returning.update_attributes(returning.attributes)

                if resolved_in_zabbix:
                    from alerta.utils.api import process_action
                    alert, action, text, timeout, was_updated = process_action(returning, 'close', 'Resolve from zabbix', timeout=None)
                    if was_updated:
                        is_incident = alert.attributes.get('incident', False)
                        if not is_incident:
                            alert = alert.from_action(action, text, timeout)
                        alert = alert.recalculate_incident_close('closed' if is_incident else None)
                        alert.recalculate_status_durations()
                        alert.update_attributes(alert.attributes)
                    returning = alert
                return returning, False
            else:
                ZABBIX_SEVERITY_MAPPING = current_app.config.get('ZABBIX_SEVERITY_MAPPING', {})
                zabbix_severity = self.attributes.get('zabbix_severity', None)
                if zabbix_severity and zabbix_severity in ZABBIX_SEVERITY_MAPPING:
                    self.severity = ZABBIX_SEVERITY_MAPPING[zabbix_severity]

                if resolved_in_zabbix:
                    self.status = 'closed'

        return self.create(), True

    # retrieve an alert
    @classmethod
    def find_by_id(cls, id: str, customers: List[str] = None) -> 'Alert':
        return cls.from_db(db.get_alert(id, customers))

    @classmethod
    def find_by_ids(cls, ids: List[str], customers: List[str] = None) -> List['Alert']:
        """
        Находит множество алертов по списку их ID.
        Намного эффективнее, чем вызывать find_by_id для каждого ID отдельно.
        
        :param ids: Список ID алертов
        :param customers: Опциональный список клиентов для фильтрации
        :return: Список объектов Alert
        """
        if not ids:
            return []
            
        return [cls.from_db(alert) for alert in db.find_by_ids(ids, customers=customers)]

    def get_parent(self) -> 'Alert':
        if self.attributes.incident:
            return self
        return Alert.from_db(db.get_parent(self.id))

    def get_parent_with_children(self):
        if self.attributes.get("incident"):
            return [self] + self.get_children()

        return [Alert.from_db(alert) for alert in db.get_parent_with_children(self.id)]

    def is_blackout(self) -> bool:
        """Does the alert create time fall within an existing blackout period?"""
        if not current_app.config['NOTIFICATION_BLACKOUT']:
            if self.severity in current_app.config['BLACKOUT_ACCEPT']:
                return False
        return db.is_blackout_period(self)

    @property
    def is_suppressed(self) -> bool:
        """Is the alert status 'blackout'?"""
        return alarm_model.is_suppressed(self)

    # set alert status
    def set_status(self, status: str, text: str = '', timeout: int = None) -> 'Alert':
        now = datetime.utcnow()

        timeout = timeout or current_app.config['ALERT_TIMEOUT']
        history = History(
            id=self.id,
            event=self.event,
            severity=self.severity,
            status=status,
            value=self.value,
            text=text,
            change_type=ChangeType.status,
            update_time=now,
            user=g.login,
            timeout=self.timeout
        )
        return Alert.from_db(db.set_status(self.id, status, timeout, update_time=now, history=history))

    def get_previous_status(self) -> Optional[str]:
        history = sorted(self.history, key=lambda x: x.update_time, reverse=True)
        previous_status_entry = next((h for h in history if h.status != self.status), None)
        if previous_status_entry:
            return previous_status_entry.status
        return None

    # tag an alert
    def tag(self, tags: List[str]) -> bool:
        return db.tag_alert(self.id, tags)

    # untag an alert
    def untag(self, tags: List[str]) -> bool:
        return db.untag_alert(self.id, tags)

    # update alert tags
    def update_tags(self, tags: List[str]) -> bool:
        return db.update_tags(self.id, list(set(tags)))

    # update alert attributes
    def update_attributes(self, attributes: Dict[str, Any]) -> Dict[str, Any]:
        return db.update_attributes(self.id, self.attributes, attributes)

    @staticmethod
    def mass_update_attributes(attributes_dict: Dict[str, Dict]) -> bool:
        """
        Mass update attributes for alerts.

        :param attributes_dict: Список Dict attributes. (key - alert id, value - Dict attributes)
        :return: True if success
        """
        if not attributes_dict:
            return True  # nothing to update

        updates = [{'id': key, 'attributes': value} for key, value in attributes_dict.items()]
        return db.mass_update_attributes(updates)

    @staticmethod
    def mass_update_last_receive_time(last_receive_times_dict: Dict[str, Any]) -> bool:
        """
        Mass update last_receive_time for incidents.

        :param last_receive_times_dict: Список Dict last_receive_time. (key - alert id, value - iso datetime)
        :return: True if success
        """
        if not last_receive_times_dict:
            return True  # nothing to update

        updates = [{'id': key, 'last_receive_time': str(value)} for key, value in last_receive_times_dict.items()]

        return db.mass_update_last_receive_time(updates)

    def recalculate_status_durations(self):
        if not self.history:
            logging.warning("No history available for alert: %s", self.id)
            return self

        history = sorted(self.history, key=lambda x: x.update_time)
        status_durations = defaultdict(float)
        previous_time = history[0].update_time
        previous_status = history[0].status

        for index in range(1, len(history)):
            entry = history[index]
            update_time = entry.update_time
            status = entry.status

            duration = (update_time - previous_time).total_seconds()
            if previous_status:
                status_durations[previous_status] += duration

            previous_time = update_time
            previous_status = status

        self.attributes['status_durations'] = status_durations

        return self

    def recalculate_incident_close(self, optimistic_status=None):
        if not self.attributes.get('incident') and self.status != 'closed':
            return self

        targets = self.get_parent_with_children()
        if not targets:
            logging.warning("No parent or children found for alert: %s", self.id)
            return self

        parent = targets[0]
        children = targets[1:]

        # Если все children и parent имеют статус 'closed' - ничего не меняем
        if all(child.status == 'closed' for child in children) and parent.status == 'closed':
            logging.debug(f"[close recalculation] 1 parent [{parent.id}] status={parent.status}")
            return self

        # Если все children закрыты, а у parent есть атрибут 'resolved' - закрываем parent
        all_childs_resolved = all(child.status == 'closed' for child in children)
        if self.id != parent.id and all_childs_resolved and parent.attributes.get('zabbix_resolved'):
            logging.debug(f"[close recalculation] 2 parent [{parent.id}] status={parent.status}")
            return parent.from_action('close', 'All children closed', timeout=None)

        # Если self это parent и статус 'closed' - добавляем 'zabbix_resolved' и меняем статус на previous_status
        if self.id == parent.id:
            if self.status == 'closed':
                previous_status = parent.get_previous_status()
                logging.debug(f"[close recalculation] 3 parent [{parent.id}] status={parent.status}, previous_status={previous_status}")
                if previous_status:
                    updated = self.set_status(previous_status, text='Resolved incident alert')
                    updated.attributes['zabbix_resolved'] = True
                    return updated
            elif optimistic_status == 'closed':
                logging.debug(f"[close recalculation] 4 parent [{parent.id}] status={parent.status}")
                self.attributes['zabbix_resolved'] = True
                if all_childs_resolved or not children:
                    return self.from_action('close', 'Ma alert was closed BUT ', timeout=None)
                else:
                    self.set_status(self.status, text='alert was')
                    return self

        return self

    # delete an alert
    def delete(self) -> bool:
        return db.delete_alert(self.id)

    # bulk tag
    @staticmethod
    def tag_find_all(query, tags):
        return db.tag_alerts(query, tags)

    # bulk untag
    @staticmethod
    def untag_find_all(query, tags):
        return db.untag_alerts(query, tags)

    # bulk update attributes
    @staticmethod
    def update_attributes_find_all(query, attributes):
        return db.update_attributes_by_query(query, attributes)

    # bulk delete
    @staticmethod
    def delete_find_all(query=None):
        return db.delete_alerts(query)

    # search alerts
    @staticmethod
    def find_all(query: Query = None, raw_data: bool = False, history: bool = False, page: int = 1, page_size: int = 1000) -> List['Alert']:
        return [Alert.from_db(alert) for alert in db.get_alerts(query, raw_data, history, page, page_size)]

    @staticmethod
    def find_all_really(query: Query = None) -> List['Alert']:
        return [Alert.from_db(alert) for alert in db.get_allAlerts(query)]

    @staticmethod
    def find_by_jira_keys(ids: List[str]) -> List['Alert']:
        if not ids:
            return []

        return [Alert.from_db(alert) for alert in db.find_by_jira_keys(ids)]

    @staticmethod
    def find_by_zabbix_meta(zabbix_id: str, origin: str = None) -> List['Alert']:
        if not origin:
            return []

        return [Alert.from_db(alert) for alert in db.find_by_zabbix_meta(zabbix_id, origin)]

    @staticmethod
    def get_alert_history(alert, page=1, page_size=100):
        return [RichHistory.from_db(hist) for hist in db.get_alert_history(alert, page, page_size)]

    # list alert history
    @staticmethod
    def get_history(query: Query = None, page=1, page_size=1000) -> List[RichHistory]:
        return [RichHistory.from_db(hist) for hist in db.get_history(query, page, page_size)]

    # get total count
    @staticmethod
    def get_count(query: Query = None) -> Dict[str, Any]:
        return db.get_count(query)

    # get severity counts
    @staticmethod
    def get_counts_by_severity(query: Query = None) -> Dict[str, Any]:
        return db.get_counts_by_severity(query)

    # get status counts
    @staticmethod
    def get_counts_by_status(query: Query = None) -> Dict[str, Any]:
        return db.get_counts_by_status(query)

    # top 10 alerts
    @staticmethod
    def get_top10_count(query: Query = None) -> List[Dict[str, Any]]:
        return Alert.get_topn_count(query, topn=10)

    @staticmethod
    def get_topn_count(query: Query = None, topn: int = 10) -> List[Dict[str, Any]]:
        return db.get_topn_count(query, topn=topn)

    # top 10 flapping
    @staticmethod
    def get_top10_flapping(query: Query = None) -> List[Dict[str, Any]]:
        return Alert.get_topn_flapping(topn=10)

    @staticmethod
    def get_topn_flapping(query: Query = None, topn: int = 10) -> List[Dict[str, Any]]:
        return db.get_topn_flapping(query, topn=topn)

    # top 10 standing
    @staticmethod
    def get_top10_standing(query: Query = None) -> List[Dict[str, Any]]:
        return Alert.get_topn_standing(topn=10)

    @staticmethod
    def get_topn_standing(query: Query = None, topn: int = 10) -> List[Dict[str, Any]]:
        return db.get_topn_standing(query, topn=topn)

    # get environments
    @staticmethod
    def get_environments(query: Query = None) -> List[str]:
        return db.get_environments(query)

    # get services
    @staticmethod
    def get_services(query: Query = None) -> List[str]:
        return db.get_services(query)

    # get groups
    @staticmethod
    def get_groups(query: Query = None) -> List[str]:
        return db.get_alert_groups(query)

    # get tags
    @staticmethod
    def get_tags(query: Query = None) -> List[str]:
        return db.get_alert_tags(query)

    # add note
    def add_note(self, text: str) -> Note:
        note = Note.from_alert(self, text)
        history = History(
            id=note.id,
            event=self.event,
            severity=self.severity,
            status=self.status,
            value=self.value,
            text=text,
            change_type=ChangeType.note,
            update_time=datetime.utcnow(),
            user=g.login
        )
        db.add_history(self.id, history)
        return note

    # get notes for alert
    def get_alert_notes(self, page: int = 1, page_size: int = 100) -> List['Note']:
        notes = db.get_alert_notes(self.id, page, page_size)
        return [Note.from_db(note) for note in notes]

    def delete_note(self, note_id):
        history = History(
            id=note_id,
            event=self.event,
            severity=self.severity,
            status=self.status,
            value=self.value,
            text='note dismissed',
            change_type=ChangeType.dismiss,
            update_time=datetime.utcnow(),
            user=g.login
        )
        db.add_history(self.id, history)
        return Note.delete_by_id(note_id)

    @staticmethod
    def housekeeping(expired_threshold: int, info_threshold: int) -> Tuple[List['Alert'], List['Alert'], List['Alert']]:
        return (
            [Alert.from_db(alert) for alert in db.get_expired(expired_threshold, info_threshold)],
            [Alert.from_db(alert) for alert in db.get_unshelve()],
            [Alert.from_db(alert) for alert in db.get_unack()]
        )

    def from_status(self, status: str, text: str = '', timeout: int = None) -> 'Alert':
        now = datetime.utcnow()

        self.timeout = timeout or current_app.config['ALERT_TIMEOUT']
        history = [History(
            id=self.id,
            event=self.event,
            severity=self.severity,
            status=status,
            value=self.value,
            text=text,
            change_type=ChangeType.status,
            update_time=now,
            user=g.login,
            timeout=self.timeout
        )]
        return Alert.from_db(db.set_alert(
            id=self.id,
            severity=self.severity,
            status=status,
            tags=self.tags,
            attributes=self.attributes,
            timeout=timeout,
            previous_severity=self.previous_severity,
            update_time=now,
            history=history)
        )

    def from_action(self, action: str, text: str = '', timeout: int = None) -> 'Alert':
        now = datetime.utcnow()

        status, _, previous_status, previous_timeout = self._get_hist_info(action)
        if action in [ChangeType.unack, ChangeType.unshelve, ChangeType.timeout]:
            timeout = timeout or previous_timeout

        if action in [ChangeType.ack, ChangeType.unack]:
            timeout = timeout or current_app.config['ACK_TIMEOUT']
        elif action in [ChangeType.shelve, ChangeType.unshelve]:
            timeout = timeout or current_app.config['SHELVE_TIMEOUT']
        else:
            timeout = timeout or self.timeout or current_app.config['ALERT_TIMEOUT']

        new_severity, new_status = alarm_model.transition(
            alert=self,
            current_status=status,
            previous_status=previous_status,
            action=action
        )
        logging.warning(f"Action [{action}] transition for '{self.id}', prev_status: {previous_status}, status: {status}, new_status: {new_status}, new_severity: {new_severity}")
        r = status_change_hook.send(self, status=new_status, text=text)
        _, (_, new_status, text) = r[0]

        try:
            change_type = ChangeType(action)
        except ValueError:
            change_type = ChangeType.action

        history = [History(
            id=self.id,
            event=self.event,
            severity=new_severity,
            status=new_status,
            value=self.value,
            text=text,
            change_type=change_type,
            update_time=now,
            user=g.login,
            timeout=timeout
        )]

        return Alert.from_db(db.set_alert(
            id=self.id,
            severity=new_severity,
            status=new_status,
            tags=self.tags,
            attributes=self.attributes,
            timeout=self.timeout,
            previous_severity=self.severity if new_severity != self.severity else self.previous_severity,
            update_time=now,
            history=history)
        )

    def from_expired(self, text: str = '', timeout: int = None):
        return self.from_action(action='expired', text=text, timeout=timeout)

    def from_timeout(self, text: str = '', timeout: int = None):
        return self.from_action(action='timeout', text=text, timeout=timeout)

    # add history entry
    @staticmethod
    def add_history(alert_id, history):
        return db.add_history(alert_id, history)
        
    # mass update status
    @staticmethod
    def mass_update_status(alert_ids, status, timeout, update_time):
        """
        Массовое обновление статусов для списка алертов.
        
        :param alert_ids: Список ID алертов для обновления
        :param status: Новый статус
        :param timeout: Значение таймаута
        :param update_time: Время обновления
        :return: Список ID обновленных алертов
        """
        if not alert_ids:
            return []
            
        return db.mass_update_status(alert_ids, status, timeout, update_time)

    # link alert to issue
    def link_alert(self, issue) -> 'Alert':
        issue_id = issue.id
        logging.warning(f"Привязка алерта {self.id} к issue {issue_id}")
        
        if self.issue_id == issue_id:
            logging.warning(f"Алерт {self.id} уже привязан к issue {issue_id}")
            return self
            
        history = History(
            id=self.id,
            event=self.event,
            severity=self.severity,
            status=self.status,
            value=self.value,
            text=f'Alert linked to issue {issue_id}',
            change_type='link-issue',
            update_time=datetime.utcnow(),
            user=g.login if hasattr(g, 'login') else None
        )
        
        self.history.append(history)
        self.issue_id = issue_id
        
        try:
            logging.warning(f"Обновление issue_id для алерта {self.id} на {issue_id}")
            result = Alert.from_db(db.update_issueid_for_alert(self.id, issue_id))
            logging.warning(f"Результат привязки алерта {self.id} к issue {issue_id}: issue_id={result.issue_id if result else None}")
            
            # Обновляем атрибуты Issue после успешного линкования
            try:
                issue.recalculate_and_update_issue()
                logging.info(f"Атрибуты issue {issue_id} обновлены после привязки алерта {self.id}")
            except Exception as e:
                logging.error(f"Ошибка при обновлении атрибутов issue {issue_id}: {str(e)}")
            
            return result
        except Exception as e:
            logging.error(f"Ошибка привязки алерта {self.id} к issue {issue_id}: {str(e)}")
            import traceback
            logging.error(traceback.format_exc())
            # Возвращаем исходный алерт без изменений
            self.issue_id = None  # Сбрасываем установленный issue_id
            return self

    # массовое связывание алертов с issue
    @staticmethod
    def link_alerts(alert_ids, issue_id):
        """
        Массовое связывание алертов с задачей
        """
        if not alert_ids:
            return 0

        # Обеспечиваем уникальность ID алертов
        alert_ids = list(set(alert_ids))
        logging.info(f"Mass linking {len(alert_ids)} alerts to issue {issue_id}")
        
        try:
            return db.update_issueid_for_alerts(
                alert_ids=alert_ids,
                new_issue_id=issue_id
            )
        except Exception as e:
            logging.error(f"Error mass linking alerts to issue {issue_id}: {e}")
            raise


    # массовое отвязывание алертов от issue
    @staticmethod
    def unlink_alerts(alert_ids):
        """
        Массовое отвязывание алертов от задачи
        """
        if not alert_ids:
            return 0

        # Обеспечиваем уникальность ID алертов
        alert_ids = list(set(alert_ids))
        logging.info(f"Mass unlinking {len(alert_ids)} alerts from issue")
        
        try:
            return db.update_issueid_for_alerts(
                alert_ids=alert_ids
            )
        except Exception as e:
            logging.error(f"Error mass unlinking alerts from issue: {e}")
            raise
