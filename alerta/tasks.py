import logging
from typing import Dict, List, Optional
from datetime import datetime
import threading

from flask import g

from alerta.app import create_celery_app, db
from alerta.exceptions import InvalidAction, RejectException
from alerta.models.alert import Alert
from alerta.models.enums import ChangeType
from alerta.models.history import History
from alerta.utils.api import process_action, process_status
from alerta.utils.jira import JiraClient
from alerta.app import alarm_model

celery = create_celery_app()

# Определяем поддерживаемые действия
SUPPORTED_ACTIONS = ['ack', 'false-positive', 'inc', 'esc', 'aidone', 'close']
BULK_ACTIONS = ['ack', 'false-positive']

# @celery.task
# def action_alerts(alerts: List[str], action: str, text: str, timeout: Optional[int], login: str) -> None:
#     updated = []
#     errors = []
#     for alert_id in alerts:
#         alert = Alert.find_by_id(alert_id)
#
#         try:
#             g.login = login
#             previous_status = alert.status
#             # pre action
#             # alert, action, text, timeout, was_updated = process_action(alert, action, text, timeout)
#             # update status
#             # alert = alert.from_action(action, text, timeout) # хуйня по сути тот же апдейт всего но через валидацию и плагины опять
#             # if was_updated:
#             alert = alert.recalculate_incident_close()
#             alert.recalculate_status_durations()
#             alert.update_attributes(alert.attributes)
#             # post action
#             # alert, action, text, timeout, was_updated = process_action(alert, action, text, timeout, post_action=True)
#         except RejectException as e:
#             errors.append(str(e))
#             continue
#         except InvalidAction as e:
#             errors.append(str(e))
#             continue
#         except Exception as e:
#             errors.append(str(e))
#             continue
#
#         # if previous_status != alert.status:
#         #     try:
#         #         alert, status, text = process_status(alert, alert.status, text)
#         #         alert = alert.from_status(status, text, timeout)
#         #     except RejectException as e:
#         #         errors.append(str(e))
#         #         continue
#         #     except Exception as e:
#         #         errors.append(str(e))
#         #         continue
#
#         updated.append(alert.id)


def single_action(alert_id: str, action: str, text: str, timeout: Optional[int], login: str) -> Optional[str]:
    """
    Обрабатывает одиночный алерт для действий ack, false-positive, inc, esc, aidone.

    Args:
        alert_id: ID алерта
        action: Действие для выполнения
        text: Текст комментария
        timeout: Таймаут действия
        login: Логин пользователя

    Returns:
        ID обработанного алерта или None в случае ошибки
    """
    try:
        alert = Alert.find_by_id(alert_id)
        if not alert:
            logging.warning(f"Alert with ID {alert_id} not found")
            return None

        current_login = getattr(g, 'login', login)
        previous_status = alert.status

        logging.warning(f"Processing single action '{action}' for alert ID {alert_id} (status: {previous_status})")

        # Получаем текущий и предыдущий статусы для transition
        current_status, _, previous_status, _ = alert._get_hist_info(action)
        logging.warning(f"current_status: {current_status}, previous_status: {previous_status}")

        # Применяем transition для определения нового статуса
        _, new_status = alarm_model.transition(
            alert=alert,
            current_status=current_status,
            previous_status=previous_status,
            action=action
        )
        logging.warning(f"new_status: {new_status}")
        # Обновляем статус и добавляем специфичные атрибуты
        # Всегда считаем, что обновление требуется
        alert.status = new_status
        # Добавляем специальные атрибуты в зависимости от действия
        if action == 'ack':
            alert.attributes['acked-by'] = current_login

        elif action == 'inc':
            alert.attributes['incident'] = True
            # Обновляем статус алерта сразу
            update_time = datetime.utcnow()
            db.set_status(alert.id, new_status, timeout, update_time=update_time)
            history = History(
                id=alert.id,
                event=alert.event,
                severity=alert.severity,
                status=new_status,
                value=alert.value,
                text=text or f'Action: {action}',
                change_type=ChangeType.action,
                update_time=update_time,
                user=current_login,
                timeout=timeout
            )
            Alert.add_history(alert.id, history)
            # Запускаем создание Jira тикета в отдельном потоке и ждем результат
            result = {'ticket': None}
            def create_ticket_wrapper(alert, login, result):
                ticket_data = create_jira_ticket(alert, login)
                result['ticket'] = ticket_data

            thread = threading.Thread(target=create_ticket_wrapper, args=(alert, current_login, result))
            thread.start()
            thread.join()  # Ждем завершения потока
            ticket = result['ticket']
            if ticket:
                alert.attributes['jira_url'] = ticket['url']
                alert.attributes['jira_key'] = ticket['key']
                alert.attributes['jira_status'] = ticket['status']
                alert.update_attributes(alert.attributes)
                logging.info(f"Created Jira ticket {ticket['key']} for alert {alert.id}")
            else:
                logging.error(f"Failed to create Jira ticket for alert {alert.id}")

            # Возможные атрибуты для эскалации
            # alert.attributes['escalated'] = True
            # alert.attributes['escalated-by'] = current_login
            # alert.attributes['escalated-time'] = datetime.utcnow().isoformat()
        # elif action == 'aidone':
            # Атрибуты для завершения обработки инцидента
            # alert.attributes['aidone'] = True
            # alert.attributes['aidone-by'] = current_login
            # alert.attributes['aidone-time'] = datetime.utcnow().isoformat()


        # Сохраняем изменения в БД
        if action != 'inc':
            update_time = datetime.utcnow()
            db.set_status(alert.id, new_status, timeout, update_time=update_time)
            alert.update_attributes(alert.attributes)
            history = History(
                id=alert.id,
                event=alert.event,
                severity=alert.severity,
                status=new_status,
                value=alert.value,
                text=text or f'Action: {action}',
                change_type=ChangeType.action,
                update_time=update_time,
                user=current_login,
                timeout=timeout
            )
            Alert.add_history(alert.id, history)

        logging.debug(f"Successfully processed alert {alert_id} with single action '{action}', new status: {new_status}")
        return alert.id

    except (RejectException, InvalidAction) as e:
        logging.error(f"Action '{action}' failed for alert {alert_id}: {str(e)}")
    except Exception as e:
        logging.error(f"Unexpected error for alert {alert_id}, action '{action}': {str(e)}", exc_info=True)

    return None


def mass_action(alerts: List[str], action: str, text: str, timeout: Optional[int], login: str) -> None:
    if not alerts:
        return

    now = datetime.utcnow()

    try:
        if not hasattr(g, 'login') or not g.login:
            g.login = login
    except:
        pass

    # Для массовых действий (ack, false-positive) используем оптимизированную логику
    if action == 'ack':
        new_status = 'ack'
    elif action == 'false-positive':
        new_status = 'false-positive'
    else:
        logging.warning(f"Action '{action}' is not optimized for mass processing, consider implementing")
        return

    alert_objects = Alert.find_by_ids(alerts)
    attribute_updates = {}
    alert_ids = []

    for alert in alert_objects:
        alert_ids.append(alert.id)
        if action == 'ack':
            alert.attributes['acked-by'] = login
        attribute_updates[alert.id] = alert.attributes.copy()

    Alert.mass_update_status(alerts, new_status, timeout, now)

    for alert_id in alert_ids:
        history = History(
            id=alert_id,
            event="",
            severity="",
            status=new_status,
            value="",
            text=text or f'Bulk {action} action',
            change_type=ChangeType(action) if action in dir(ChangeType) else ChangeType.action,
            update_time=now,
            user=login,
            timeout=timeout
        )
        Alert.add_history(alert_id, history)

    Alert.mass_update_attributes(attribute_updates)
    logging.info(f"Mass {action} action applied to {len(alerts)} alerts")


@celery.task
def create_jira_ticket(alert, login):
    if alert.attributes.get('jira_key'):
        logging.info(f"Jira ticket already exists for alert {alert.id}: {alert.attributes.get('jira_key')}")
        return None

    try:
        params = {
            'attributes': alert.attributes,
            'severity': alert.severity,
            'tags': alert.tags,
            'text': alert.text,
            'eventtags': alert.tags,
            'host': alert.event,
            'username': login,
            'InfoSystem': None,
            'ProjectGroup': 'Other',
            'Owner_1': None,
            'Owner_2': None,
        }

        for tag in alert.tags:
            if "Owner_1:" in tag or "Owner_2:" in tag or "ProjectGroup:" in tag or "InfoSystem:" in tag:
                key, value = tag.split(":", 1)
                params[key] = value

        logging.warning(f"Creating Jira ticket for alert {alert.id} with params: {params}")
        jira_client = JiraClient()
        ticket = jira_client.create_ticket(
            args=params,
            infosystem=params['InfoSystem'],
            projectgroup=params['ProjectGroup']
        )

        return ticket

    except Exception as e:
        logging.error(f"Error creating Jira ticket for alert {alert.id}: {str(e)}", exc_info=True)
        return None

def mass_add_history_bulk(self, alert_ids, change_type, status, text, update_time, user):

    if not alert_ids:
        return True

    try:
        # PostgreSQL вариант
        placeholders = ','.join(['%s'] * len(alert_ids))
        query = f"""
            UPDATE alerts
            SET history = jsonb_build_array(
                jsonb_build_object(
                    'id', id,
                    'status', %s,
                    'type', %s,
                    'updateTime', %s,
                    'text', %s, 
                    'user', %s
                )
            ) || (CASE WHEN history IS NULL THEN '[]'::jsonb ELSE history[0:{current_app.config['HISTORY_LIMIT']-1}] END)
            WHERE id IN ({placeholders})
        """
        params = [status, change_type, update_time, text, user] + alert_ids
        self._updateall(query, params)
        return True
    except Exception as e:
        logging.error(f"Error in mass_add_history_bulk: {str(e)}")
        return False
