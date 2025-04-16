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
        self.host_critical = kwargs.get('host_critical', None) or '1'
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
    def add_alert(self, alert) -> 'Issue':
        """
        Добавляет алерт в Issue и обновляет списки уникальных значений полей
        
        :param alert: Объект Alert, который нужно добавить к Issue
        :return: Обновленный Issue
        """
        return self.mass_add_alerts([alert])

    # массовое добавление алертов к issue
    def mass_add_alerts(self, alerts: List) -> 'Issue':
        """
        Массовое добавление алертов в Issue и обновление списков уникальных значений полей
        
        :param alerts: Список объектов Alert, которые нужно добавить к Issue
        :return: Обновленный Issue
        """
        if not alerts:
            logging.debug(f"Список алертов для добавления пуст")
            return self
            
        alert_ids = []
        for alert in alerts:
            if alert.id not in self.alerts and alert.id not in alert_ids:
                alert_ids.append(alert.id)
                
        if not alert_ids:
            logging.debug(f"Все алерты уже привязаны к Issue {self.id}")
            return self
            
        logging.debug(f"Добавление {len(alert_ids)} алертов к Issue {self.id}")
        
        # Создаем копию текущих списков для обновления
        update_data = {'alerts': self.alerts + alert_ids}
        change_text = f'Added {len(alert_ids)} alerts to issue'
        
        # Инициализируем переменные для отслеживания максимальных значений
        max_severity = self.severity if self.severity else 'medium'
        max_host_critical = str(self.host_critical) if self.host_critical else '1'
        max_last_alert_time = self.last_alert_time
        
        severity_order = {'medium': 3, 'high': 4, 'critical': 5}
        
        # Наборы для уникальных значений
        events = set(self.hosts) if self.hosts else set()
        project_groups_set = set(self.project_groups) if self.project_groups else set()
        info_systems_set = set(self.info_systems) if self.info_systems else set()
        
        # Проходим по всем алертам и обновляем максимальные значения
        for alert in alerts:
            if alert.id not in self.alerts:
                # Проверяем severity
                alert_severity = alert.severity if alert.severity else 'medium'
                # Если severity алерта не в словаре, считаем её как 'medium'
                if severity_order.get(alert_severity, 3) > severity_order.get(max_severity, 3):
                    logging.debug(f"Обновление severity Issue {self.id} на {alert_severity}")
                    max_severity = alert_severity
                    update_data['severity'] = alert_severity
                
                # Проверяем host_critical
                if hasattr(alert, 'attributes') and 'host_critical' in alert.attributes:
                    alert_host_critical = str(alert.attributes.get('host_critical'))
                    if alert_host_critical != max_host_critical:
                        logging.debug(f"Обновление host_critical Issue {self.id} на {alert_host_critical}")
                        max_host_critical = alert_host_critical
                        update_data['host_critical'] = alert_host_critical
                
                # Проверяем last_alert_time
                if alert.create_time:
                    if not max_last_alert_time or alert.create_time > max_last_alert_time:
                        logging.debug(f"Обновление last_alert_time Issue {self.id} на {alert.create_time}")
                        max_last_alert_time = alert.create_time
                        update_data['last_alert_time'] = alert.create_time
                
                # Добавляем event
                event = alert.event
                if event:
                    events.add(event)
                
                # Извлекаем project_groups и info_systems из тегов
                for tag in alert.tags:
                    if tag.startswith('ProjectGroup:'):
                        pg = tag.split(':', 1)[1]
                        project_groups_set.add(pg)
                    elif tag.startswith('InfoSystem:'):
                        info_sys = tag.split(':', 1)[1]
                        info_systems_set.add(info_sys)
        
        # Обновляем значения только если они изменились
        if events != set(self.hosts):
            update_data['hosts'] = list(events)
        
        if project_groups_set != set(self.project_groups):
            update_data['project_groups'] = list(project_groups_set)
            
        if info_systems_set != set(self.info_systems):
            update_data['info_systems'] = list(info_systems_set)
        
        logging.debug(f"Update data for issue {self.id}: {update_data}")
        
        # Обновляем Issue
        updated_issue = self.update(
            **update_data,
            change_type='alerts-added', 
            text=change_text
        )
        
        logging.info(f"Successfully added {len(alert_ids)} alerts to issue {self.id}")
        return updated_issue

    # remove alert from issue
    def remove_alert(self, alert_id: str) -> 'Issue':
        """
        Удаляет алерт из Issue и обновляет списки уникальных значений полей
        
        :param alert_id: ID алерта, который нужно удалить
        :return: Обновленный Issue
        """
        return self.mass_remove_alerts([alert_id])
        
    # массовое удаление алертов из issue
    def mass_remove_alerts(self, alert_ids: List[str]) -> 'Issue':
        """
        Массовое удаление алертов из Issue и обновление списков уникальных значений полей
        
        :param alert_ids: Список ID алертов, которые нужно удалить
        :return: Обновленный Issue
        """
        if not alert_ids:
            logging.debug(f"Список алертов для удаления пуст")
            return self
            
        # Фильтруем только те ID, которые действительно есть в Issue
        alert_ids_to_remove = [a_id for a_id in alert_ids if a_id in self.alerts]
        
        if not alert_ids_to_remove:
            logging.debug(f"Нет алертов для удаления из Issue {self.id}")
            return self
            
        logging.debug(f"Удаление {len(alert_ids_to_remove)} алертов из Issue {self.id}")
        
        # Определяем оставшиеся алерты
        remaining_alert_ids = [a_id for a_id in self.alerts if a_id not in alert_ids_to_remove]
        update_data = {'alerts': remaining_alert_ids}
        change_text = f'Removed {len(alert_ids_to_remove)} alerts from issue'
        
        # Если это были последние алерты в Issue, Issue будет закрыт
        if not remaining_alert_ids:
            logging.debug(f"Last alerts removed from issue {self.id}, issue will be closed")
            update_data['status'] = 'closed'
            update_data['resolve_time'] = datetime.utcnow()
            change_text += ' (issue closed as no alerts remain)'
        else:
            # Если остались алерты, пересчитываем severity, host_critical и last_alert_time
            from alerta.models.alert import Alert
            
            # Подгружаем информацию о всех оставшихся алертах за один запрос
            remaining_alerts = Alert.find_by_ids(remaining_alert_ids)
            
            # Наборы для уникальных значений
            events = set()
            project_groups_set = set()
            info_systems_set = set()
            
            # Инициализируем максимальные значения
            max_severity = 'medium'
            max_host_critical = '1'  # По умолчанию host_critical = 1
            max_last_alert_time = None
            
            severity_order = {'medium': 3, 'high': 4, 'critical': 5}
            
            # Проходим по всем оставшимся алертам и пересчитываем значения
            for alert in remaining_alerts:
                # Проверяем severity
                alert_severity = alert.severity if alert.severity else 'medium'
                # Если severity алерта не в словаре, считаем её как 'medium'
                if severity_order.get(alert_severity, 3) > severity_order.get(max_severity, 3):
                    max_severity = alert_severity
                
                # Проверяем host_critical
                if hasattr(alert, 'attributes') and 'host_critical' in alert.attributes:
                    alert_host_critical = str(alert.attributes.get('host_critical'))
                    if alert_host_critical != max_host_critical:
                        max_host_critical = alert_host_critical
                
                # Проверяем create_time
                if alert.create_time:
                    if not max_last_alert_time or alert.create_time > max_last_alert_time:
                        max_last_alert_time = alert.create_time
                
                # Добавляем event
                if alert.event:
                    events.add(alert.event)
                
                # Извлекаем project_groups и info_systems из тегов
                for tag in alert.tags:
                    if tag.startswith('ProjectGroup:'):
                        pg = tag.split(':', 1)[1]
                        project_groups_set.add(pg)
                    elif tag.startswith('InfoSystem:'):
                        info_sys = tag.split(':', 1)[1]
                        info_systems_set.add(info_sys)
            
            # Обновляем значения в Issue
            if max_severity != self.severity:
                logging.debug(f"Обновление severity Issue {self.id} на {max_severity}")
                update_data['severity'] = max_severity
                
            current_host_critical = str(self.host_critical) if self.host_critical else '1'
            if str(max_host_critical) != current_host_critical:
                logging.debug(f"Обновление host_critical Issue {self.id} на {max_host_critical}")
                update_data['host_critical'] = max_host_critical
                
            if max_last_alert_time and max_last_alert_time != self.last_alert_time:
                logging.debug(f"Обновление last_alert_time Issue {self.id} на {max_last_alert_time}")
                update_data['last_alert_time'] = max_last_alert_time
            
            # Обновляем списки hosts, project_groups и info_systems
            if events != set(self.hosts):
                update_data['hosts'] = list(events)
                
            if project_groups_set != set(self.project_groups):
                update_data['project_groups'] = list(project_groups_set)
                
            if info_systems_set != set(self.info_systems):
                update_data['info_systems'] = list(info_systems_set)
        
        logging.debug(f"Update data for issue {self.id}: {update_data}")
        
        # Обновляем Issue
        updated_issue = self.update(
            **update_data,
            change_type='alerts-removed', 
            text=change_text
        )
        
        logging.info(f"Successfully removed {len(alert_ids_to_remove)} alerts from issue {self.id}")
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
            # Добавляем дополнительные очки за severity
            severity_order = {'medium': 3, 'high': 4, 'critical': 5}
            issue_severity = issue.severity if issue.severity else 'medium'
            severity_score = severity_order.get(issue_severity, 3)
            score = score + severity_score  # Учитываем severity при сортировке
            
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
            
            try:
                # Добавляем алерт к Issue, передавая весь объект алерта
                issue = issue.add_alert(alert)
                
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
    
    # Получаем host_critical из атрибутов алерта, если он есть
    host_critical = '1'  # По умолчанию host_critical = 1
    if hasattr(alert, 'attributes') and 'host_critical' in alert.attributes:
        host_critical = alert.attributes['host_critical']
        logging.debug(f"Using host_critical={host_critical} from alert attributes")
    
    # Проверяем severity и устанавливаем корректное значение
    severity_order = {'medium': 3, 'high': 4, 'critical': 5}
    severity = alert.severity if alert.severity in severity_order else 'medium'
    logging.debug(f"Using severity={severity} for new Issue")
    
    # Создаем новый Issue
    issue = Issue(
        summary=summary,
        severity=severity,
        host_critical=host_critical,
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