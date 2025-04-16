import logging
import os
import platform
import sys
from collections import namedtuple
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
            logging.debug(f"No updates to apply to Issue {self.id}")
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
        
        try:
            logging.debug(f"Sending update for Issue {self.id}: {update}")
            updated_issue = Issue.from_db(db.update_issue(self.id, update, now, history))
            logging.debug(f"Issue {self.id} successfully updated")
            return updated_issue
        except Exception as e:
            logging.error(f"Error updating Issue {self.id}: {str(e)}")
            # Возвращаем текущий объект, если обновление не удалось
            return self
        
    # add alert to issue
    def add_alert(self, alert_id: str, alert_data: dict = None) -> 'Issue':
        """
        Добавляет алерт в Issue и обновляет списки уникальных значений полей
        
        :param alert_id: ID алерта
        :param alert_data: Данные алерта (event, project_groups, info_systems)
        :return: Обновленный Issue
        """
        logging.debug(f"Adding alert {alert_id} to issue {self.id}")
        
        if alert_id in self.alerts:
            logging.debug(f"Alert {alert_id} already in issue {self.id}")
            return self
        
        # Создаем копию текущих списков для обновления
        update_data = {'alerts': self.alerts + [alert_id]}
        change_text = f'Alert {alert_id} added to issue'
        
        if alert_data:
            # Добавление event если он уникален
            if 'event' in alert_data and alert_data['event']:
                event = alert_data['event']
                if event not in self.hosts:
                    logging.debug(f"Adding unique event '{event}' to issue {self.id}")
                    update_data['hosts'] = self.hosts + [event]
                else:
                    logging.debug(f"Event '{event}' already in issue {self.id}")
                    
            # Добавление project_groups если они уникальны
            if 'project_groups' in alert_data and alert_data['project_groups']:
                project_groups_to_add = []
                for pg in alert_data['project_groups']:
                    if pg not in self.project_groups:
                        logging.debug(f"Adding unique project_group '{pg}' to issue {self.id}")
                        project_groups_to_add.append(pg)
                    else:
                        logging.debug(f"Project group '{pg}' already in issue {self.id}")
                        
                if project_groups_to_add:
                    update_data['project_groups'] = self.project_groups + project_groups_to_add
                        
            # Добавление info_systems если они уникальны
            if 'info_systems' in alert_data and alert_data['info_systems']:
                info_systems_to_add = []
                for info_sys in alert_data['info_systems']:
                    if info_sys not in self.info_systems:
                        logging.debug(f"Adding unique info_system '{info_sys}' to issue {self.id}")
                        info_systems_to_add.append(info_sys)
                    else:
                        logging.debug(f"Info system '{info_sys}' already in issue {self.id}")
                        
                if info_systems_to_add:
                    update_data['info_systems'] = self.info_systems + info_systems_to_add
        
        # Обновляем Issue
        updated_issue = self.update(
            **update_data,
            change_type='alert-added', 
            text=change_text
        )
        
        logging.info(f"Alert {alert_id} successfully added to issue {self.id}")
        return updated_issue
    # remove alert from issue
    def remove_alert(self, alert_id: str, alert_data: dict = None) -> 'Issue':
        """
        Удаляет алерт из Issue и обновляет списки уникальных значений полей
        
        :param alert_id: ID алерта
        :param alert_data: Данные алерта (event, project_groups, info_systems)
        :return: Обновленный Issue
        """
        logging.debug(f"Removing alert {alert_id} from issue {self.id}")
        
        if alert_id not in self.alerts:
            logging.debug(f"Alert {alert_id} not in issue {self.id}")
            return self
        
        update_data = {'alerts': [a for a in self.alerts if a != alert_id]}
        change_text = f'Alert {alert_id} removed from issue'
        
        # Если это был последний алерт в Issue, Issue будет закрыт
        if not update_data['alerts']:
            logging.debug(f"Last alert removed from issue {self.id}, issue will be closed")
            update_data['status'] = 'closed'
            update_data['resolve_time'] = datetime.utcnow()
            change_text += ' (issue closed as no alerts remain)'
        
        if alert_data:
            # Удаление event из hosts, если он больше не используется в других алертах
            if 'event' in alert_data and alert_data['event'] in self.hosts:
                event = alert_data['event']
                
                # Проверяем, есть ли другие алерты с таким же event
                other_alerts_with_same_event = False
                for remaining_alert_id in update_data['alerts']:
                    try:
                        remaining_alert = Alert.find_by_id(remaining_alert_id)
                        if remaining_alert and remaining_alert.event == event:
                            other_alerts_with_same_event = True
                            logging.debug(f"Event {event} still used by alert {remaining_alert_id}")
                            break
                    except Exception as e:
                        logging.error(f"Error checking alert {remaining_alert_id}: {str(e)}")
                
                if not other_alerts_with_same_event:
                    logging.debug(f"Removing unused event {event} from issue {self.id}")
                    update_data['hosts'] = [h for h in self.hosts if h != event]
            
            # Удаление project_groups, если они больше не используются в других алертах
            if 'project_groups' in alert_data and alert_data['project_groups']:
                project_groups_to_remove = []
                
                for pg in alert_data['project_groups']:
                    if pg in self.project_groups:
                        # Проверяем, используется ли project_group в других алертах
                        pg_used = False
                        for remaining_alert_id in update_data['alerts']:
                            try:
                                remaining_alert = Alert.find_by_id(remaining_alert_id)
                                if remaining_alert:
                                    # Извлекаем project_groups из тегов
                                    alert_pgs = [tag.split(':', 1)[1] for tag in remaining_alert.tags 
                                                if tag.startswith('ProjectGroup:')]
                                    if pg in alert_pgs:
                                        pg_used = True
                                        logging.debug(f"Project group {pg} still used by alert {remaining_alert_id}")
                                        break
                            except Exception as e:
                                logging.error(f"Error checking alert {remaining_alert_id}: {str(e)}")
                        
                        if not pg_used:
                            logging.debug(f"Removing unused project group {pg} from issue {self.id}")
                            project_groups_to_remove.append(pg)
                
                if project_groups_to_remove:
                    update_data['project_groups'] = [pg for pg in self.project_groups 
                                                    if pg not in project_groups_to_remove]
            
            # Удаление info_systems, если они больше не используются в других алертах
            if 'info_systems' in alert_data and alert_data['info_systems']:
                info_systems_to_remove = []
                
                for info_sys in alert_data['info_systems']:
                    if info_sys in self.info_systems:
                        # Проверяем, используется ли info_system в других алертах
                        info_sys_used = False
                        for remaining_alert_id in update_data['alerts']:
                            try:
                                remaining_alert = Alert.find_by_id(remaining_alert_id)
                                if remaining_alert:
                                    # Извлекаем info_systems из тегов
                                    alert_info_systems = [tag.split(':', 1)[1] for tag in remaining_alert.tags 
                                                        if tag.startswith('InfoSystem:')]
                                    if info_sys in alert_info_systems:
                                        info_sys_used = True
                                        logging.debug(f"Info system {info_sys} still used by alert {remaining_alert_id}")
                                        break
                            except Exception as e:
                                logging.error(f"Error checking alert {remaining_alert_id}: {str(e)}")
                        
                        if not info_sys_used:
                            logging.debug(f"Removing unused info system {info_sys} from issue {self.id}")
                            info_systems_to_remove.append(info_sys)
                
                if info_systems_to_remove:
                    update_data['info_systems'] = [info_sys for info_sys in self.info_systems 
                                                  if info_sys not in info_systems_to_remove]
        
        # Обновляем Issue
        updated_issue = self.update(
            **update_data,
            change_type='alert-removed', 
            text=change_text
        )
        
        logging.info(f"Alert {alert_id} successfully removed from issue {self.id}")
        return updated_issue
        
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
    Находит Issue для связывания с алертом на основе логики приоритета и общих полей.
    Приоритет полей для сопоставления: хосты (event) > группы проектов > информационные системы.
    """
    logging.debug(f"Поиск подходящего Issue для алерта {alert.id}")
    
    # Извлекаем event из алерта
    event = alert.event
    
    # Извлекаем теги группы проекта и информационной системы из алерта
    project_groups = []
    info_systems = []
    
    for tag in alert.tags:
        if tag.startswith('ProjectGroup:'):
            project_groups.append(tag.split(':', 1)[1])
        elif tag.startswith('InfoSystem:'):
            info_systems.append(tag.split(':', 1)[1])
    
    logging.debug(f"Ищем Issue, соответствующие: event={event}, project_groups={project_groups}, info_systems={info_systems}")
    
    # Получаем все активные Issue
    # Используем объект Query из alerta.database.base
    from alerta.database.base import Query
    query = Query(where="status!='closed' AND status!='resolved'", sort="create_time DESC", group="")
    issues = Issue.find_all(query)
    
    logging.debug(f"Найдено активных Issue: {len(issues)}")
    
    # Массив для хранения подходящих Issue с приоритетами
    matching_issues = []
    
    # Проверяем каждый Issue на соответствие
    for issue in issues:
        score = 0
        
        # Проверяем hosts (event)
        if hasattr(issue, 'hosts') and event in issue.hosts:
            score += 100  # Высший приоритет - соответствие event
            logging.debug(f"Issue {issue.id}: совпадение по event (+100)")
        
        # Проверяем project_groups
        if hasattr(issue, 'project_groups') and project_groups:
            for pg in project_groups:
                if pg in issue.project_groups:
                    score += 10  # Средний приоритет - соответствие группы проектов
                    logging.debug(f"Issue {issue.id}: совпадение по project_group {pg} (+10)")
        
        # Проверяем info_systems
        if hasattr(issue, 'info_systems') and info_systems:
            for is_ in info_systems:
                if is_ in issue.info_systems:
                    score += 1  # Низкий приоритет - соответствие информационной системы
                    logging.debug(f"Issue {issue.id}: совпадение по info_system {is_} (+1)")
        
        # Если есть совпадения, добавляем в список
        if score > 0:
            matching_issues.append((issue.id, score))
            logging.debug(f"Issue {issue.id} добавлен в список совпадений с приоритетом {score}")
    
    # Сортируем по приоритету (по убыванию)
    matching_issues.sort(key=lambda x: x[1], reverse=True)
    
    if matching_issues:
        best_match_id = matching_issues[0][0]
        logging.debug(f"Найден подходящий Issue: {best_match_id} с приоритетом {matching_issues[0][1]}")
        return best_match_id
    
    logging.debug("Не найдено подходящих Issue")
    return None

def process_new_alert(alert):
    """
    Обработка нового алерта и привязка к Issue при необходимости
    
    :param alert: Новый алерт
    :return: Алерт после обработки
    """
    logging.debug(f"Processing new alert {alert.id} (event={alert.event})")
    
    # Проверка на сопоставление с существующими паттернами
    pattern_matches = None
    try:
        pattern_matches = alert.pattern_match_duplicated()
        if pattern_matches:
            logging.debug(f"Found pattern matches for alert {alert.id}")
    except Exception as e:
        logging.error(f"Error during pattern matching: {str(e)}")
    
    if pattern_matches:
        # Обрабатываем совпадение с существующими паттернами
        try:
            from alerta.utils.api import process_alert
            logging.debug(f"Processing alert {alert.id} with patterns")
            result = process_alert(alert)
            logging.debug(f"Alert {alert.id} processed with patterns")
            return result
        except Exception as e:
            logging.error(f"Error processing alert with patterns: {str(e)}")
            logging.error(f"Falling back to Issue-based processing")
    
    # Если нет совпадений по паттернам, проверяем соответствие по новой логике
    issue_id = None
    try:
        issue_id = find_matching_issue(alert)
    except Exception as e:
        logging.error(f"Error finding matching issue: {str(e)}")
    
    if issue_id:
        try:
            # Получаем Issue и добавляем к нему алерт
            issue = Issue.find_by_id(issue_id)
            logging.warning(f"ISSUESSSS: {[issue]}")
            
            # Извлекаем данные алерта
            project_groups = []
            info_systems = []
            
            for tag in alert.tags:
                if tag.startswith('ProjectGroup:'):
                    project_groups.append(tag.split(':', 1)[1])
                elif tag.startswith('InfoSystem:'):
                    info_systems.append(tag.split(':', 1)[1])
            
            alert_data = {
                'event': alert.event,
                'project_groups': project_groups,
                'info_systems': info_systems
            }
            
            try:
                # Добавляем алерт к Issue
                issue = issue.add_alert(alert.id, alert_data)
                
                # Связываем алерт с Issue
                alert = alert.link_to_issue(issue_id)
                
                logging.info(f"Added alert {alert.id} to existing issue {issue_id}")
                return alert
            except Exception as e:
                logging.error(f"Error adding alert to issue {issue_id}: {str(e)}")
                logging.error(f"Falling back to creating new Issue")
        except Exception as e:
            logging.error(f"Error finding issue {issue_id}: {str(e)}")
            logging.error(f"Falling back to creating new Issue")
    
    # Если нет подходящего Issue, создаем новый
    try:
        result = create_new_issue_for_alert(alert)
        return result
    except Exception as e:
        logging.error(f"Error creating new issue for alert {alert.id}: {str(e)}")
        # Возвращаем исходный алерт, если не удалось создать Issue
        return alert

def create_new_issue_for_alert(alert):
    """
    Создает новый Issue для алерта и связывает алерт с этим Issue
    
    :param alert: Алерт, для которого создается Issue
    :return: Алерт, привязанный к новому Issue
    """
    logging.debug(f"Creating new Issue for alert {alert.id}")
    
    # Извлекаем данные из алерта
    event = alert.event
    resource = alert.resource
    
    # Извлекаем теги проектных групп и информационных систем
    project_groups = []
    info_systems = []
    
    for tag in alert.tags:
        if ':' in tag:
            key, value = tag.split(':', 1)
            if key == 'ProjectGroup':
                project_groups.append(value)
                logging.debug(f"Extracted ProjectGroup tag: {value}")
            elif key == 'InfoSystem':
                info_systems.append(value)
                logging.debug(f"Extracted InfoSystem tag: {value}")
    
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
    
    # Сохраняем Issue
    issue = issue.create()
    logging.info(f"Created new Issue {issue.id} for alert {alert.id}")
    
    # Привязываем алерт к Issue
    alert = alert.link_to_issue(issue.id)
    logging.info(f"Linked alert {alert.id} to Issue {issue.id}")
    
    return alert