import logging
from apscheduler.schedulers.background import BackgroundScheduler
from importlib import import_module
from pyzabbix import ZabbixAPI
import os
from collections import namedtuple
from datetime import datetime, timedelta
from flask import g
from celery import Celery

logger = logging.getLogger(__name__)

ZABBIX_USER = os.getenv('ZABBIX_USER')
ZABBIX_PASSWORD = os.getenv('ZABBIX_PASSWORD')
ZABBIX_API_URL = 'http://10.20.1.107'


def zabbix_login():
    try:
        zabbix = ZabbixAPI(ZABBIX_API_URL)
        zabbix.login(ZABBIX_USER, ZABBIX_PASSWORD)
        return zabbix
    except Exception as exc:
        logger.error("Ошибка подключения к Zabbix API: %s", exc)
        return None


def poll_zabbix_events(event_ids):
    zabbix = zabbix_login()
    try:
        event_ids = event_ids
        events = zabbix.event.get(
            eventids=event_ids,
            output=['eventid', 'r_eventid'],
            selectHosts=['hostid', 'name']
        )
        # logger.warning(f"EVENTS: {events}")
        event_map = {
            str(event['eventid']): {
                'eventid': event.get('eventid'),
                'hosts': event.get('hosts', []),
                'r_eventid': event.get('r_eventid')
            } for event in events
        }
        updated_event_ids = []
        for event_id in event_ids:
            # logger.warning(f"{event_id}")
            if event_id in event_map:
                # logger.warning(f"was found in Zabbix")
                event = event_map[event_id]
                if not event.get('hosts'):
                    updated_event_ids.append(event_id)
                    # logger.warning(f"Event id: {event_id} was Deleted")
                else:
                    try:
                        r_eventid = str(event.get('r_eventid', 0))
                    except Exception as ex:
                        logger.error("Ошибка преобразования r_eventid для события %s: %s", event_id, ex)
                        r_eventid = '0'
                    if r_eventid != '0':
                        updated_event_ids.append(event_id)
                        # logger.warning(f"Event id: {event_id} is in OK state")
                    # else:
                        # logger.warning(f"Event id: {event_id} is in ERROR state")

            else:
                updated_event_ids.append(event_id)
                # logger.warning(f"Event id: {event_id} was not found in Zabbix events")
        # logger.warning(f"UPDATED: {updated_event_ids}")
        return updated_event_ids

    except Exception as e:
        logger.error("Ошибка при получении или обработке событий из Zabbix: %s", e)
        return []


def get_error_alerts_older_than():
    alert_module = import_module("alerta.models.alert")
    Alert = getattr(alert_module, "Alert")

    cutoff = datetime.utcnow() - timedelta(minutes=5)
    Query = namedtuple("Query", ["where", "vars", "sort", "group"])
    query = Query(
        where="1=1\nAND DATE(create_time) <= %(to_date)s\nAND \"status\" <> %(status)s",
        vars={'to_date': cutoff, 'status': 'closed'},
        sort="create_time DESC",
        group=[]
    )
    try:
        alerts = Alert.find_all(query=query)
        # logger.warning(f"OLD ALERTS: {alerts}")
        return alerts
    except Exception as e:
        logger.warning("Ошибка при выборке алертов: %s", e)
        return []


def set_alerts_status(alerts):
    from alerta.utils.api import process_status

    updated = []
    errors = []
    for alert in alerts:
        try:
            alert, status, text = process_status(alert, "closed", "auto close by scheduled task")
        except Exception as e:
            errors.append(str(e))
            continue

        if alert.set_status("closed", "auto close by scheduled task"):
            updated.append(alert.id)

    if errors:
        logger.error(f"failed to bulk set alert status', errors={errors}")
        return
    else:
        logger.warning(f"status = OK, {len(updated)} issues closed: {updated}")


def check_alerts_and_close(app):
    try:
        alert_module = import_module("alerta.models.alert")
        Alert = getattr(alert_module, "Alert")
        from alerta.tasks import action_alerts
    except Exception as e:
        logger.error(f"Ошибка в check_alerts_and_close: {e}")

    with app.app_context():
        alerts = get_error_alerts_older_than()
        if not alerts:
            logger.warning("Нет алертов для обработки.")
            return

        event_map = {}
        for alert in alerts:
            attrs = getattr(alert, "attributes", None)
            event_id = attrs.get("zabbix_id")
            event_map.setdefault(event_id, []).append(alert)
            # logger.warning(f"TEST {alert.id} : {event_id}")

        if not event_map:
            logger.info("Нет event_id для обработки.")
            return

        filtered_event_ids = poll_zabbix_events(list(event_map.keys()))
        Query = namedtuple("Query", ["where", "vars", "sort", "group"])

        query_filtered_alerts = Query(
            where="attributes->>'zabbix_id' IN %(filtered_event_ids)s AND \"status\" <> %(status)s",
            vars={'filtered_event_ids': tuple(filtered_event_ids), 'status': 'closed'},
            sort="create_time DESC",
            group=[]
        )
        filtered_alerts = Alert.find_all(query_filtered_alerts)
        # logger.warning(f"FILTERED ALERTS: {filtered_alerts}")
        if not filtered_alerts:
            logger.warning("No alerts to close")

        g.login = "g.taftin"
        try:
            set_alerts_status(filtered_alerts)
        except Exception as exc:
            logger.exception(f"Ошибка при вызове set_alerts_status для filtered_alerts")



from apscheduler.schedulers.background import BackgroundScheduler

scheduler = None

def init_zabbix_poll(app):
    global scheduler
    if scheduler and scheduler.running:
        logger.info("Zabbix scheduler already running. Skipping new instance.")
        return
    scheduler = BackgroundScheduler()
    scheduler.add_job(
        lambda: check_alerts_and_close(app),
        'interval',
        minutes=1,
        max_instances=1,
        coalesce=True,
        id="zabbix_poll_job",
        replace_existing=True
    )
    scheduler.start()
    logger.warning("Фоновый опрос Zabbix запущен.")
