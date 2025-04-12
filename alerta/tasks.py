import logging
from typing import Dict, List, Optional
from datetime import datetime

from flask import g

from alerta.app import create_celery_app, db
from alerta.exceptions import InvalidAction, RejectException
from alerta.models.alert import Alert
from alerta.models.enums import ChangeType
from alerta.models.history import History
from alerta.utils.api import process_action, process_status

celery = create_celery_app()


@celery.task
def action_alerts(alerts: List[str], action: str, text: str, timeout: Optional[int], login: str) -> None:
    updated = []
    errors = []
    
    # Устанавливаем g.login для синхронного выполнения (при вызове через Celery это не нужно)
    try:
        if not hasattr(g, 'login') or not g.login:
            g.login = login
    except:
        pass  # Игнорируем ошибки - в контексте Celery g может быть недоступным
    
    # Используем массовый подход для действий 'ack' и 'false-positive'
    if action in ['ack', 'false-positive']:
        mass_action(alerts, action, text, timeout, login)
        return

    # Стандартный подход для других действий
    for alert_id in alerts:
        alert = Alert.find_by_id(alert_id)
        if not alert:
            errors.append(f"Alert with ID {alert_id} not found")
            continue

        try:
            current_login = getattr(g, 'login', login)
            previous_status = alert.status
            # pre action
            alert, action, text, timeout, was_updated = process_action(alert, action, text, timeout)
            # update status
            alert = alert.from_action(action, text, timeout)
            if was_updated:
                alert = alert.recalculate_incident_close()
                alert.recalculate_status_durations()
                
                # Добавляем атрибут 'acked-by' при действии ack
                if action == 'ack':
                    alert.attributes['acked-by'] = current_login
                    
                alert.update_attributes(alert.attributes)
            # post action
            alert, action, text, timeout, was_updated = process_action(alert, action, text, timeout, post_action=True)
        except RejectException as e:
            errors.append(str(e))
            continue
        except InvalidAction as e:
            errors.append(str(e))
            continue
        except Exception as e:
            errors.append(str(e))
            continue

        updated.append(alert.id)
    
    # Логирование результатов (полезно для синхронного режима)
    if errors:
        logging.error(f"Errors during action '{action}': {errors}")
    if updated:
        logging.info(f"Successfully processed {len(updated)} alerts with action '{action}'")
    return updated


def mass_action(alerts: List[str], action: str, text: str, timeout: Optional[int], login: str) -> None:
    """
    Массовая обработка действий с алертами для 'ack' и 'false-positive'
    
    Данная функция выполняет оптимизированную обработку для указанных действий,
    применяя изменения сразу ко всем алертам вместо поочередного изменения каждого.
    """
    if not alerts:
        return
    
    now = datetime.utcnow()
    
    # Устанавливаем g.login для корректной работы в синхронном режиме
    try:
        if not hasattr(g, 'login') or not g.login:
            g.login = login
    except:
        pass
    
    # Определяем новый статус в зависимости от действия
    new_status = 'ack' if action == 'ack' else 'false-positive'
    
    # Получаем все алерты одним запросом для оптимизации
    alert_objects = Alert.find_by_ids(alerts)
    
    # Подготовка массовых обновлений
    attribute_updates = {}
    
    # Создаем один массив с идентификаторами алертов для истории
    alert_ids = []
    
    for alert in alert_objects:
        alert_ids.append(alert.id)
        
        # Добавляем атрибут 'acked-by' непосредственно в объект алерта
        if action == 'ack':
            alert.attributes['acked-by'] = login
        
        # Добавляем обновленные атрибуты после всех модификаций
        attribute_updates[alert.id] = alert.attributes.copy()
    
    # Массовое обновление статусов алертов в БД
    Alert.mass_update_status(alerts, new_status, timeout, now)
    
    # Добавляем историю для каждого алерта
    for alert_id in alert_ids:
        history = History(
            id=alert_id,
            event="",  # Базовые значения для записи истории
            severity="",
            status=new_status,
            value="",
            text=text or f'Bulk {action} action',
            change_type=ChangeType(action) if action in dir(ChangeType) else ChangeType.action,
            update_time=now,
            user=login,
            timeout=timeout
        )
        # Используем метод Alert.add_history вместо прямого обращения к db
        Alert.add_history(alert_id, history)
    
    # Применяем массовое обновление атрибутов
    Alert.mass_update_attributes(attribute_updates)
    
    logging.info(f"Mass {action} action applied to {len(alerts)} alerts")

def mass_add_history_bulk(self, alert_ids, change_type, status, text, update_time, user):
    """
    Массовое добавление одинаковой истории для списка алертов.
    
    :param alert_ids: Список ID алертов
    :param change_type: Тип изменения
    :param status: Новый статус
    :param text: Текст
    :param update_time: Время обновления
    :param user: Пользователь
    :return: True в случае успеха
    """
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
