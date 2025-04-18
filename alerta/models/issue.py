import logging
import os
import platform
import sys
from collections import namedtuple
from datetime import datetime
from typing import Optional, List, Dict, Any, Union, Tuple, TYPE_CHECKING
from uuid import uuid4

from flask import current_app, g
from flask import jsonify
from alerta.exceptions import ApiError

from alerta.app import db
from alerta.database.base import Query
from alerta.models.history import History
from alerta.utils.format import DateTime
from alerta.utils.response import absolute_url

# Избегаем циклического импорта с использованием TYPE_CHECKING
if TYPE_CHECKING:
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
        # Обеспечиваем уникальность алертов при инициализации
        alerts = kwargs.get('alerts', None) or list()
        self.alerts = list(set(alerts))
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
        # Обеспечиваем уникальность алертов при создании из документа
        alerts = doc.get('alerts', list())
        if alerts:
            alerts = list(set(alerts))
            
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
            alerts=alerts,
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
        
    # find issues by list of ids
    @classmethod
    def find_by_ids(cls, ids: List[str]) -> List['Issue']:
        """
        Находит множество инцидентов по списку их ID.
        Намного эффективнее, чем вызывать find_by_id для каждого ID отдельно.
        
        :param ids: Список ID инцидентов
        :return: Список объектов Issue
        """
        if not ids:
            return []
        
        # Поскольку в DB API нет специального метода для поиска множества инцидентов по ID,
        # создаем запрос с условием WHERE id IN (...)
        where = 'id = ANY(%(ids)s)'
        query = Query(where=where, sort='create_time DESC', group='', vars={'ids': ids})
        
        return [Issue.from_db(issue) for issue in db.get_issues(query)]
        
    # update an issue
    def update(self, **kwargs) -> 'Issue':
        now = datetime.utcnow()
        update = {}
        
        change_type = kwargs.pop('change_type', 'update')
        text = kwargs.pop('text', '')
        
        # Если обновляется поле alerts, обеспечиваем уникальность
        if 'alerts' in kwargs:
            kwargs['alerts'] = list(set(kwargs['alerts']))
        
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
            event='issue',
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

    # delete an issue
    @classmethod
    def delete_by_id(cls, issue_id: str) -> bool:
        return db.delete_issue(issue_id)


    def link_alerts_to_issue(self, new_alert_ids: List[str]) -> 'Issue':
        """
        Оптимизированное массовое добавление алертов к Issue 
        с использованием SQL для проверки уникальности.
        
        :param alert_ids: Список ID алертов, которые нужно добавить
        :return: Обновленный Issue
        """
        # Проверяем, что список ID не пустой
        if not new_alert_ids:
            logging.debug(f"Список alert_ids для добавления пуст")
            return self
        
        logging.debug(f"Добавление {len(new_alert_ids)} новых алертов к Issue {self.id}")
        
        current_alerts_ids = self.alerts if hasattr(self, 'alerts') else []
        all_alerts_ids = current_alerts_ids + new_alert_ids
        new_alerts_count = len(all_alerts_ids) - len(current_alerts_ids)
        
        if new_alerts_count == 0:
            logging.debug(f"Все алерты уже привязаны к Issue {self.id}")
            return self
        
        # Обновляем алерты новым issue_id
        from alerta.models.alert import Alert
        Alert.link_alerts(new_alert_ids, self.id)
        
        # Обновляем Issue добавляя новые alert_ids
        updated_issue = self.update(
            alerts=all_alerts_ids,
            change_type='alerts-added',
            text=f'Added {new_alerts_count} alerts to issue'
        )
        updated_issue = updated_issue.recalculate_and_update_issue()
        logging.info(f"Successfully added {new_alerts_count} alerts to issue {self.id}")
        return updated_issue
    

    # массовое удаление алертов из issue с использованием SQL-агрегации
    def unlink_alerts_from_issue(self, alert_ids: List[str], target_issue_id = None) -> 'Issue':
        """
        Массовое удаление алертов из Issue с использованием SQL-агрегации
        для обновления атрибутов.
        
        :param alert_ids: Список ID алертов, которые нужно удалить
        :return: Обновленный Issue или ApiError если инцидент остается без алертов
        """
        if not alert_ids:
            logging.debug(f"Список алертов для удаления пуст")
            return self
        
        logging.debug(f"Удаление {len(alert_ids)} алертов из Issue {self.id}")
        
        # Определяем оставшиеся алерты
        remaining_alert_ids = [a_id for a_id in self.alerts if a_id not in alert_ids]
        update_data = {'alerts': remaining_alert_ids}
        change_text = f'Removed {len(alert_ids)} alerts from issue'
        
        # Проверяем, остались ли алерты в Issue
        if not remaining_alert_ids:
            logging.debug(f"Last alerts removed from issue {self.id}")
            
            # Проверяем, является ли Issue инцидентом (имеет inc_key)
            if self.inc_key:
                # Нельзя удалять инцидент с inc_key, если в нем не остается алертов
                logging.error(f"Cannot remove all alerts from incident with inc_key={self.inc_key}")
                raise ApiError(f"Cannot remove all alerts from incident with inc_key={self.inc_key}", 400)
            else:
                logging.info(f"Deleting issue {self.id} as it has no alerts and no inc_key")
                # отлинковываем алерты от Issue
                from alerta.models.alert import Alert
                Alert.unlink_alerts(alert_ids)
                # Если это не инцидент с inc_key, удаляем Issue
                Issue.delete_by_id(self.id)
                # добавить атрибут is_deleted со значением - id таргетного self.id
                return
        else:
            # отлинковываем алерты от Issue
            from alerta.models.alert import Alert
            Alert.unlink_alerts(alert_ids)
            
            # Пересчитываем атрибуты Issue
            updated_issue = self.update(
                alerts=remaining_alert_ids,
                change_type='alerts-removed',
                text=change_text
            )
            updated_issue = updated_issue.recalculate_and_update_issue()    
            return updated_issue
        

    # обновление атрибутов Issue с использованием SQL-агрегации
    def recalculate_and_update_issue(self) -> 'Issue':
        """
        Обновляет атрибуты Issue на основе связанных алертов,
        используя SQL-запросы для агрегации данных.

        :return: Обновленный Issue
        """
        if not self.id:
            logging.warning("Невозможно обновить Issue без ID")
            return self

        # Получаем обновленные атрибуты с помощью SQL
        try:
            updated_attrs = Issue.recalculate_issue_attributes(self.id)
            logging.warning(f"updated_attrs: {updated_attrs}")
            # Если обновления отсутствуют, возвращаем текущий Issue
            if not updated_attrs:
                logging.debug(f"Нет обновлений для Issue {self.id}")
                return self

            # Обновляем Issue
            return self.update(
                **updated_attrs,
                change_type='attributes-recalculated',
                text='Issue attributes recalculated with SQL aggregation'
            )
        except Exception as e:
            logging.error(f"Ошибка при обновлении атрибутов Issue {self.id} с помощью SQL: {str(e)}")
            import traceback
            logging.error(traceback.format_exc())
            # Возвращаем текущий объект без изменений в случае ошибки
            return self
    

    @classmethod
    def find_matching_issue(cls, alert):
        """
        Находит Issue для связывания с алертом на основе логики приоритета и общих полей.
        Приоритет полей для сопоставления: хосты (event) > (project_group + info_system)
        Теперь требуется совпадение и project_group, и info_system для группировки.
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
        
        # Если нет project_group или info_system, то нельзя группировать по ним
        if not project_groups or not info_systems:
            logging.debug(f"У алерта отсутствует project_group или info_system, группировка только по event")
        
        # Получаем все активные Issue
        # Используем объект Query из alerta.database.base
        from alerta.database.base import Query
        query = Query(where="status!='closed'", sort="create_time DESC", group="")
        issues = cls.find_all(query)
        
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
            
            # Проверка на совпадение и project_group, и info_system
            # Требуется, чтобы и project_group, и info_system совпадали
            if project_groups and info_systems and hasattr(issue, 'project_groups') and hasattr(issue, 'info_systems'):
                # Проверяем совпадение project_group
                project_group_match = False
                for pg in project_groups:
                    if pg in issue.project_groups:
                        project_group_match = True
                        break
                
                # Проверяем совпадение info_system
                info_system_match = False
                for is_ in info_systems:
                    if is_ in issue.info_systems:
                        info_system_match = True
                        break
                
                # Если совпали и project_group, и info_system
                if project_group_match and info_system_match:
                    score += 20  # Более высокий приоритет для совпадения обоих полей
                    logging.debug(f"Issue {issue.id}: совпадение по project_group и info_system (+20)")
            
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

    @classmethod
    def process_new_alert(cls, alert):
        """
        Обработка нового алерта и привязка к Issue при необходимости
        
        :param alert: Новый алерт
        :return: Алерт после обработки
        """
        logging.debug(f"Processing new alert {alert.id} (event={alert.event})")

        issue_id = None
        try:
            issue_id = cls.find_matching_issue(alert)
        except Exception as e:
            logging.error(f"Error finding matching issue: {str(e)}")
        
        if issue_id:
            try:
                # Получаем Issue и добавляем к нему алерт
                issue = cls.find_by_id(issue_id)
                logging.warning(f"Issue for linking Found: {issue.id}")
                
                try:
                    # Передаем ID алерта в метод link_alerts_to_issue
                    issue = issue.link_alerts_to_issue([alert.id])
                    # Связываем алерт с Issue
                    from alerta.models.alert import Alert
                    if isinstance(alert, Alert):
                        alert = alert.link_alert(issue)
                    
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
            result = cls.create_new_issue_for_alert(alert)
            return result
        except Exception as e:
            logging.error(f"Error creating new issue for alert {alert.id}: {str(e)}")
            # Возвращаем исходный алерт, если не удалось создать Issue
            return alert

    @classmethod
    def create_new_issue_for_alert(cls, alert):
        """
        Создает новый Issue для алерта и связывает алерт с этим Issue
        
        :param alert: Алерт, для которого создается Issue
        :return: Алерт, привязанный к новому Issue
        """
        logging.debug(f"Creating new Issue for alert {alert.id}")
        
        # Извлекаем данные из алерта
        event = alert.event
        resource = alert.resource
        
        # Извлекаем первый тег проектной группы и информационной системы
        project_group = None
        info_system = None
        
        for tag in alert.tags:
            if ':' in tag:
                key, value = tag.split(':', 1)
                if key == 'ProjectGroup' and project_group is None:
                    project_group = value
                    logging.debug(f"Extracted ProjectGroup tag: {value}")
                elif key == 'InfoSystem' and info_system is None:
                    info_system = value
                    logging.debug(f"Extracted InfoSystem tag: {value}")
        
        # Если не нашли project_group или info_system, логируем предупреждение
        if project_group is None:
            logging.warning(f"No ProjectGroup tag found for alert {alert.id}")
        if info_system is None:
            logging.warning(f"No InfoSystem tag found for alert {alert.id}")
        
        # Преобразуем в списки с одним элементом или пустые списки
        project_groups = [project_group] if project_group else []
        info_systems = [info_system] if info_system else []
        
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
        from alerta.models.alert import Alert
        if isinstance(alert, Alert):
            alert = alert.link_alert(issue)
        logging.info(f"Linked alert {alert.id} to Issue {issue.id}")
        
        return alert

    @classmethod
    def recalculate_issue_attributes(cls, issue_id: str) -> Dict[str, Any]:
        """
        Пересчитывает атрибуты Issue на основе связанных алертов, используя SQL-запросы
        для агрегации данных.
        
        :param issue_id: ID Issue, для которого требуется пересчитать атрибуты
        :return: Словарь с обновленными атрибутами Issue
        """
        from alerta.app import db
        
        logging.debug(f"Пересчет атрибутов для Issue {issue_id} с использованием SQL-агрегации")
        
        try:
            # Получаем все агрегированные атрибуты за один вызов
            agg_attrs = db.get_issue_aggregated_attributes(issue_id)
            
            # Формируем словарь с обновленными атрибутами
            updated_attrs = {
                'severity': agg_attrs['severity'],
                'host_critical': '1' if agg_attrs['host_critical'] else '0',
                'hosts': agg_attrs['hosts'],
                'project_groups': agg_attrs['project_groups'],
                'info_systems': agg_attrs['info_systems']
            }
            
            # Добавляем last_alert_time, если оно есть
            if agg_attrs['last_alert_time']:
                updated_attrs['last_alert_time'] = agg_attrs['last_alert_time']
            
            # Добавляем earliest_create_time в качестве create_time для Issue, если оно есть
            if agg_attrs['earliest_create_time']:
                updated_attrs['create_time'] = agg_attrs['earliest_create_time']
                logging.debug(f"Установлено наименьшее create_time для Issue {issue_id}: {agg_attrs['earliest_create_time']}")
            
            logging.debug(f"Результат SQL-агрегации для Issue {issue_id}: {updated_attrs}")
            return updated_attrs
        except Exception as e:
            logging.error(f"Ошибка при выполнении SQL-агрегации для Issue {issue_id}: {str(e)}")
            import traceback
            logging.error(traceback.format_exc())
            
            # Возвращаем значения по умолчанию
            default_attrs = {
                'severity': 'medium',
                'host_critical': '1',  # Устанавливаем по умолчанию в 1
                'hosts': [],
                'project_groups': [],
                'info_systems': []
            }
            logging.warning(f"Используем значения по умолчанию для Issue {issue_id} из-за ошибки в SQL-агрегации")
            return default_attrs