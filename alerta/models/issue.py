import logging
import os
import platform
import sys
from datetime import datetime
from typing import Optional, List, Dict, Any, Union, Tuple
from uuid import uuid4

from flask import current_app, g

from alerta.app import db
from alerta.database.base import Query
from alerta.models.history import History
from alerta.utils.format import DateTime, deep_serialize_datetime, CustomJSONEncoder
from alerta.utils.response import absolute_url

# Импортируем Alert для функций, которые его используют
from alerta.models.alert import Alert

JSON = Dict[str, Any]
NoneType = type(None)


class Issue:
    def __init__(self, summary: str, **kwargs) -> None:
        if not summary:
            raise ValueError('Missing mandatory value for "summary"')
        
        self.id = kwargs.get('id') or str(uuid4())
        self.summary = summary
        self.severity = kwargs.get('severity', None) or ''
        self.host_critical = kwargs.get('host_critical', None) or '0'
        self.duty_admin = kwargs.get('duty_admin', None) or ''
        self.description = kwargs.get('description', None) or ''
        self.status = kwargs.get('status', None) or ''
        self.status_duration = kwargs.get('status_duration', None)
        self.create_time = kwargs.get('create_time', None) or datetime.utcnow()
        self.last_alert_time = kwargs.get('last_alert_time', None)
        self.resolve_time = kwargs.get('resolve_time', None)
        self.pattern_id = kwargs.get('pattern_id', None)
        self.inc_key = kwargs.get('inc_key', None) or ''
        self.slack_link = kwargs.get('slack_link', None) or ''
        self.disaster_link = kwargs.get('disaster_link', None) or ''
        self.escalation_group = kwargs.get('escalation_group', None) or ''
        self.alerts = kwargs.get('alerts', None) or list()
        self.hosts = kwargs.get('hosts', None) or list()
        self.project_groups = kwargs.get('project_groups', None) or list()
        self.info_systems = kwargs.get('info_systems', None) or list()
        self.attributes = kwargs.get('attributes', None) or dict()
        self.master_incident = kwargs.get('master_incident', None)
        self.issue_history = kwargs.get('issue_history', None) or list()

    @classmethod
    def parse(cls, json: JSON) -> 'Issue':
        return Issue(
            id=json.get('id', None),
            summary=json.get('summary', None),
            severity=json.get('severity', None),
            host_critical=json.get('host_critical', None),
            duty_admin=json.get('duty_admin', None),
            description=json.get('description', None),
            status=json.get('status', None),
            status_duration=json.get('status_duration', None),
            create_time=DateTime.parse(json['createTime']) if 'createTime' in json else None,
            last_alert_time=DateTime.parse(json['lastAlertTime']) if 'lastAlertTime' in json else None,
            resolve_time=DateTime.parse(json['resolveTime']) if 'resolveTime' in json else None,
            pattern_id=json.get('pattern_id', None),
            inc_key=json.get('inc_key', None),
            slack_link=json.get('slack_link', None),
            disaster_link=json.get('disaster_link', None),
            escalation_group=json.get('escalation_group', None),
            alerts=json.get('alerts', list()),
            hosts=json.get('hosts', list()),
            project_groups=json.get('project_groups', list()),
            info_systems=json.get('info_systems', list()),
            attributes=json.get('attributes', dict()),
            master_incident=json.get('master_incident', None),
            issue_history=json.get('issue_history', list())
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
            'create_time': self.create_time,
            'last_alert_time': self.last_alert_time,
            'resolve_time': self.resolve_time,
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
            'issue_history': self.issue_history
        }

    def get_id(self, short: bool = False) -> str:
        return self.id[:8] if short else self.id

    def get_body(self, history: bool = True) -> Dict[str, Any]:
        body = self.serialize
        body.update({
            key: DateTime.iso8601(body[key]) for key in ['create_time', 'last_alert_time', 'resolve_time'] if body[key]
        })
        return body

    def __repr__(self) -> str:
        return 'Issue(id={!r}, summary={!r}, severity={!r}, status={!r})'.format(
            self.id, self.summary, self.severity, self.status
        )

    @classmethod
    def from_document(cls, doc: Dict[str, Any]) -> 'Issue':
        return Issue(
            id=doc.get('id', None) or doc.get('_id'),
            summary=doc.get('summary', None),
            severity=doc.get('severity', None),
            host_critical=doc.get('host_critical', None),
            duty_admin=doc.get('duty_admin', None),
            description=doc.get('description', None),
            status=doc.get('status', None),
            status_duration=doc.get('status_duration', None),
            create_time=doc.get('create_time', None),
            last_alert_time=doc.get('last_alert_time', None),
            resolve_time=doc.get('resolve_time', None),
            pattern_id=doc.get('pattern_id', None),
            inc_key=doc.get('inc_key', None),
            slack_link=doc.get('slack_link', None),
            disaster_link=doc.get('disaster_link', None),
            escalation_group=doc.get('escalation_group', None),
            alerts=doc.get('alerts', list()),
            hosts=doc.get('hosts', list()),
            project_groups=doc.get('project_groups', list()),
            info_systems=doc.get('info_systems', list()),
            attributes=doc.get('attributes', dict()),
            master_incident=doc.get('master_incident', None),
            issue_history=doc.get('issue_history', list())
        )
        
    @classmethod
    def from_db(cls, r: Union[Dict, Tuple]) -> 'Issue':
        if isinstance(r, dict):
            return cls.from_document(r)
        elif isinstance(r, tuple):
            return cls.from_document(dict(zip(r._fields, r)))
        return r

    # Дополнительные методы будут добавлены на следующих шагах 

    # create an issue
    def create(self) -> 'Issue':
        logging.warning(f"Создаем Issue {self.id}")
        now = datetime.utcnow()
        
        if not self.create_time:
            self.create_time = now
            
        if not self.status:
            self.status = 'open'
            
        history = History(
            id=str(uuid4()),
            event='event',
            severity=self.severity,
            status=self.status,
            text='Issue created',
            change_type='new',
            update_time=now,
            user=g.login if hasattr(g, 'login') else None
        )
        
        self.issue_history.append(history)
        
        return Issue.from_db(db.create_issue(self))

    # get an issue
    @classmethod
    def find_by_id(cls, issue_id: str) -> 'Issue':
        return Issue.from_db(db.get_issue(issue_id))
        
    # get issues
    @classmethod
    def find_all(cls, query=None, page=1, page_size=100) -> List['Issue']:
        return [Issue.from_db(issue) for issue in db.get_issues(query, page, page_size)]
        
    # update an issue
    def update(self, **kwargs) -> 'Issue':
        now = datetime.utcnow()
        update = {}
        
        change_type = kwargs.pop('change_type', 'update')
        text = kwargs.pop('text', '')
        
        for attr, value in kwargs.items():
            if hasattr(self, attr):
                old_value = getattr(self, attr)
                if old_value != value:
                    setattr(self, attr, value)
                    update[attr] = value
        
        if not update:
            return self
            
        history = History(
            id=str(uuid4()),
            event=self.summary,  # используем summary как event
            severity=self.severity,
            status=self.status,
            text=text,
            change_type=change_type,
            update_time=now,
            user=g.login if hasattr(g, 'login') else None
        )
        
        self.issue_history.append(history)
        
        return Issue.from_db(db.update_issue(self.id, update, now, history))
        
    # add alert to issue
    def add_alert(self, alert_id: str, alert_data: dict = None) -> 'Issue':
        """
        Добавляет алерт в Issue и обновляет списки уникальных значений полей
        
        :param alert_id: ID алерта
        :param alert_data: Данные алерта (host, project_groups, info_systems)
        :return: Обновленный Issue
        """
        if alert_id in self.alerts:
            return self
        
        update_data = {'alerts': self.alerts + [alert_id]}
        change_text = f'Alert {alert_id} added to issue'
        
        if alert_data:
            # Добавление host если он уникален
            if 'event' in alert_data and alert_data['event']:
                host = alert_data['event']
                if host not in self.hosts:
                    update_data['hosts'] = self.hosts + [host]
                    
            # Добавление project_groups если они уникальны
            if 'project_groups' in alert_data and alert_data['project_groups']:
                for pg in alert_data['project_groups']:
                    if pg not in self.project_groups:
                        if 'project_groups' not in update_data:
                            update_data['project_groups'] = self.project_groups.copy()
                        update_data['project_groups'].append(pg)
                        
            # Добавление info_systems если они уникальны
            if 'info_systems' in alert_data and alert_data['info_systems']:
                for info_sys in alert_data['info_systems']:
                    if info_sys not in self.info_systems:
                        if 'info_systems' not in update_data:
                            update_data['info_systems'] = self.info_systems.copy()
                        update_data['info_systems'].append(info_sys)
        
        return self.update(
            **update_data,
            change_type='alert-added', 
            text=change_text
        )
        
    # remove alert from issue
    def remove_alert(self, alert_id: str, alert_data: dict = None) -> 'Issue':
        """
        Удаляет алерт из Issue и обновляет списки уникальных значений полей
        
        :param alert_id: ID алерта
        :param alert_data: Данные алерта (event, project_groups, info_systems)
        :return: Обновленный Issue
        """
        if alert_id not in self.alerts:
            return self
        
        update_data = {'alerts': [a for a in self.alerts if a != alert_id]}
        change_text = f'Alert {alert_id} removed from issue'
        
        if alert_data:
            # Удаление host если он не используется в других алертах
            if 'event' in alert_data and alert_data['event'] in self.hosts:
                # Проверяем, есть ли другие алерты с таким же event
                other_alerts_with_same_event = False
                for remaining_alert_id in update_data['alerts']:
                    remaining_alert = Alert.find_by_id(remaining_alert_id)
                    if remaining_alert and remaining_alert.event == alert_data['event']:
                        other_alerts_with_same_event = True
                        break
                
                if not other_alerts_with_same_event:
                    update_data['hosts'] = [h for h in self.hosts if h != alert_data['event']]
            
            # Аналогично для project_groups и info_systems
            # ...
        
        return self.update(
            **update_data,
            change_type='alert-removed', 
            text=change_text
        )
        
    # resolve an issue
    def resolve(self, text: str = '') -> 'Issue':
        now = datetime.utcnow()
        
        return self.update(
            status='resolved',
            resolve_time=now,
            change_type='resolve',
            text=text or 'Issue resolved'
        )
        
    # reopen an issue
    def reopen(self, text: str = '') -> 'Issue':
        return self.update(
            status='open',
            resolve_time=None,
            change_type='reopen',
            text=text or 'Issue reopened'
        )
        
    # delete an issue
    @classmethod
    def delete_by_id(cls, issue_id: str) -> bool:
        return db.delete_issue(issue_id)

def find_matching_issue(alert):
    """
    Находит Issue для линкования алерта по приоритетной логике
    
    :param alert: Алерт для линкования
    :return: ID подходящего Issue или None
    """
    # Извлекаем данные из алерта
    event = alert.event
    resource = alert.resource
    project_groups = [tag.split(':')[1] for tag in alert.tags if tag.startswith('ProjectGroup:')]
    info_systems = [tag.split(':')[1] for tag in alert.tags if tag.startswith('InfoSystem:')]
    
    # Получаем все активные Issue
    issues = Issue.find_all(Query().filter("status!='closed' AND status!='resolved'"))
    
    # Если нет активных Issue, возвращаем None
    if not issues:
        return None
    
    # Словарь с приоритетами: 1 - самый высокий
    priority_fields = {
        'hosts': 1, 
        'project_groups': 2, 
        'info_systems': 3
    }
    
    matching_issues = []
    
    for issue in issues:
        scores = {}
        
        # Проверка соответствия по host (event алерта должен совпадать с hosts в issue)
        if len(issue.hosts) == 1 and event == issue.hosts[0]:
            scores['hosts'] = True
            
        # Проверка соответствия по project_groups
        if len(issue.project_groups) == 1 and issue.project_groups[0] in project_groups:
            scores['project_groups'] = True
            
        # Проверка соответствия по info_systems
        if len(issue.info_systems) == 1 and issue.info_systems[0] in info_systems:
            scores['info_systems'] = True
            
        # Если есть совпадения, добавляем в список с приоритетом
        if scores:
            highest_priority_match = min(
                [priority_fields[field] for field in scores.keys()],
                default=None
            )
            if highest_priority_match:
                matching_issues.append((issue, highest_priority_match))
    
    # Сортируем совпадения по приоритету (с самым высоким вначале)
    if matching_issues:
        matching_issues.sort(key=lambda x: x[1])
        logging.debug(f"Found matching issue for alert {alert.id}: {matching_issues[0][0].id}")
        return matching_issues[0][0].id
    
    logging.debug(f"No matching issue found for alert {alert.id}")
    return None

def process_new_alert(alert):

    """
    Обработка нового алерта и привязка к Issue при необходимости
    
    :param alert: Новый алерт
    :return: Алерт после обработки
    """
    # Проверка на сопоставление с существующими паттернами
    pattern_matches = alert.pattern_match_duplicated()
    
    if pattern_matches:
        # Обрабатываем совпадение с существующими паттернами как сейчас
        return handle_pattern_match(alert, pattern_matches)
    
    # Если нет совпадений по паттернам, проверяем соответствие по новой логике
    issue_id = find_matching_issue(alert)
    
    if issue_id:
        # Получаем Issue и добавляем к нему алерт
        issue = Issue.find_by_id(issue_id)
        alert_data = {
            'event': alert.event,
            'project_groups': [tag.split(':')[1] for tag in alert.tags if tag.startswith('ProjectGroup:')],
            'info_systems': [tag.split(':')[1] for tag in alert.tags if tag.startswith('InfoSystem:')]
        }
        
        issue = issue.add_alert(alert.id, alert_data)
        alert = alert.link_to_issue(issue_id)
        
        return alert
    
    # Если нет подходящего Issue, создаем новый
    return create_new_issue_for_alert(alert) 

def create_new_issue_for_alert(alert):
    logging.debug(f"Создаем новый Issue для алерта {alert}")
    """
    Создает новый Issue для алерта
    
    :param alert: Алерт, для которого создается Issue
    :return: Алерт, привязанный к новому Issue
    """
    # Извлекаем данные из алерта
    event = alert.event
    resource = alert.resource
    project_groups = [tag.split(':')[1] for tag in alert.tags if tag.startswith('ProjectGroup:')]
    info_systems = [tag.split(':')[1] for tag in alert.tags if tag.startswith('InfoSystem:')]
    
    # Формируем summary - если есть text, используем его, иначе формируем из event и resource
    summary = alert.text if alert.text else f"Issue for {event} on {resource}"
    
    # Создаем новый Issue
    issue = Issue(
        summary=summary,
        severity=alert.severity,
        status='open',
        alerts=[alert.id],
        hosts=[event],
        project_groups=project_groups,
        info_systems=info_systems
    )
    
    logging.debug(f"Issue {issue}")
    # Сохраняем Issue
    issue = issue.create()
    
    # Привязываем алерт к Issue
    alert = alert.link_to_issue(issue.id)
    
    return alert 

def create_test_issues():
    """
    Создает несколько тестовых Issue для проверки функциональности
    
    :return: Список созданных Issue
    """
    test_issues = []
    
    # Создаем Issue с одним значением в hosts
    issue1 = Issue(
        summary="Test Issue 1 for node_down",
        severity="major",
        status="open",
        alerts=[],
        hosts=["node_down"],
        project_groups=["TestGroup"],
        info_systems=["TestSystem"]
    )
    issue1 = issue1.create()
    test_issues.append(issue1)
    
    # Создаем Issue с одним значением в project_groups
    issue2 = Issue(
        summary="Test Issue 2 for ProjectGroup",
        severity="minor",
        status="open",
        alerts=[],
        hosts=["node_up", "node_down"],  # несколько значений
        project_groups=["ImportantGroup"],  # одно значение
        info_systems=["TestSystem1", "TestSystem2"]
    )
    issue2 = issue2.create()
    test_issues.append(issue2)
    
    # Создаем Issue с одним значением в info_systems
    issue3 = Issue(
        summary="Test Issue 3 for InfoSystem",
        severity="critical",
        status="open",
        alerts=[],
        hosts=["node_error", "node_warning"],
        project_groups=["Group1", "Group2"],
        info_systems=["CriticalSystem"]  # одно значение
    )
    issue3 = issue3.create()
    test_issues.append(issue3)
    
    logging.info(f"Created {len(test_issues)} test issues")
    return test_issues 