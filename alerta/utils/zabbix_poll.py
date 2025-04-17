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


def set_alerts_status(alerts):
    try:
        from alerta.utils.api import process_action
    except ImportError as e:
        logger.exception(f"Failed to import process_action: {e}")
        return 0, len(alerts)

    updated = []
    errors = []

    if not alerts:
        logger.warning("No alerts to close")
        return 0, 0

    for alert in alerts:
        if getattr(alert, 'status', None) == 'closed':
            logger.info(f"Alert {getattr(alert, 'id', 'unknown')} is already closed - skipping")
            continue

        try:
            alert, action, text, timeout, was_updated = process_action(
                alert=alert,
                action='close',
                text='closed by Alerta Scheduller',
                timeout=None
            )

            if was_updated:  # Only update if action was successful
                try:
                    # Handle incidents differently
                    is_incident = alert.attributes.get('incident', False)

                    # Apply action to alert if not an incident
                    if not is_incident:
                        alert = alert.from_action(action, text, timeout)

                    alert = alert.recalculate_incident_close('closed' if is_incident else None) # Update incident status

                    alert.recalculate_status_durations()
                    alert.update_attributes(alert.attributes)

                    updated.append(alert.id)  # Track successful update
                    logger.debug(f"Successfully closed alert {alert.id}")

                except Exception as e:
                    error_msg = f"Failed to update alert {getattr(alert, 'id', 'unknown')}: {str(e)}"
                    errors.append(error_msg)
                    logger.exception(error_msg)

        except Exception as e:
            error_msg = f"Failed to process close action for alert {getattr(alert, 'id', 'unknown')}: {str(e)}"
            errors.append(error_msg)
            logger.exception(error_msg)

    if errors:
        logger.error(f"Failed to close {len(errors)} alerts: {errors}")
    if updated:
        logger.warning(f"Successfully closed {len(updated)} alerts")
    return len(updated), len(errors)


def poll_zabbix_events(event_ids):
    if not event_ids:
        logger.warning("No event IDs provided to poll_zabbix_events")
        return []

    zabbix = zabbix_login()
    if not zabbix:
        logger.error("Failed to connect to Zabbix API")
        return []

    try:
        logger.warning(f"Polling Zabbix for {len(event_ids)} events")

        # Convert all event_ids to strings for consistent comparison
        event_ids_str = [str(eid) for eid in event_ids if eid]

        # Get events from Zabbix API
        events = zabbix.event.get(
            eventids=event_ids,
            output=['eventid', 'r_eventid'],
            selectHosts=['hostid', 'name'],
            selectRelatedObject=['triggerid', 'status']
        )

        # Validate events response
        if not events:
            logger.warning("No events returned from Zabbix API")
            return event_ids_str  # Return all event IDs to be closed if nothing found in Zabbix

        if not isinstance(events, list):
            logger.error(f"Unexpected response type from Zabbix API: {type(events)}")
            events = [events] if events else []

        # Create event map with string keys
        event_map = {}
        for event in events:
            # Skip events without eventid
            if not event or 'eventid' not in event:
                continue

            # Create event data dictionary with safe accessors
            event_data = {
                'eventid': event.get('eventid'),
                'hosts': event.get('hosts', []),
                'r_eventid': event.get('r_eventid', '0'),
                'trigger_status': -1  # Default to -1 if not found
            }

            # Safely extract trigger status
            related_obj = event.get('relatedObject')
            if related_obj:
                if isinstance(related_obj, dict):
                    event_data['trigger_status'] = int(related_obj.get('status', -1))
                elif isinstance(related_obj, list) and related_obj:
                    # If relatedObject is a list, try to get status from first item
                    if isinstance(related_obj[0], dict):
                        event_data['trigger_status'] = int(related_obj[0].get('status', -1))

            # Add to event map with string key
            event_map[str(event_data['eventid'])] = event_data

        logger.debug(f"Created event map with {len(event_map)} entries")

        # Process each event ID to determine which should be closed
        updated_event_ids = []
        for event_id in event_ids:
            event_id_str = str(event_id)

            if event_id_str in event_map:
                logger.debug(f"Processing event ID: {event_id_str}")
                event = event_map[event_id_str]

                trigger_status = event.get('trigger_status', -1)
                has_hosts = bool(event.get('hosts', []))
                r_eventid = str(event.get('r_eventid', '0'))

                if trigger_status == 1:
                    updated_event_ids.append(event_id)
                    logger.warning(f"Event {event_id} - trigger is DISABLED")
                elif not has_hosts:
                    updated_event_ids.append(event_id)
                    logger.warning(f"Event {event_id} - host was DELETED")
                elif r_eventid != '0':
                    # updated_event_ids.append(event_id) //TODO пока выключим, так как тяжеоло аффектит МАСТЕР АЛЕРТЫ
                    logger.warning(f"Event {event_id} - is in OK state")
                else:
                    logger.warning(f"Event {event_id} - remains in ERROR state")
            else:
                # Event not found in Zabbix - mark for closing
                updated_event_ids.append(event_id)
                logger.warning(f"Event {event_id} not found in Zabbix")

        logger.warning(f"Found {len(updated_event_ids)} events to close")
        return updated_event_ids

    except Exception as e:
        logger.exception(f"Error processing Zabbix events: {e}")
        return []


def get_error_alerts_older_than(minutes=5):
    try:
        alert_module = import_module("alerta.models.alert")
        Alert = getattr(alert_module, "Alert")

        cutoff = datetime.utcnow() - timedelta(minutes=minutes)
        Query = namedtuple("Query", ["where", "vars", "sort", "group"])
        query = Query(
            where="1=1\nAND DATE(create_time) <= %(to_date)s\nAND \"status\" <> %(status)s",
            vars={'to_date': cutoff, 'status': 'closed'},
            sort="create_time DESC",
            group=[]
        )
        alerts = Alert.find_all_really(query=query)
        logger.warning(f"Found {len(alerts)} open alerts older than {minutes} minutes")
        return alerts

    except Exception as e:
        logger.exception(f"Error retrieving alerts: {e}")
        return []


def check_alerts_for_close(app):
    try:
        alert_module = import_module("alerta.models.alert")
        Alert = getattr(alert_module, "Alert")
    except Exception as e:
        logger.error(f"Failed to import required modules: {e}")
        return

    with app.app_context():
        alerts = get_error_alerts_older_than()
        if not alerts:
            logger.warning("No open alerts to process")
            return

        event_map = {}
        for alert in alerts:
            attrs = getattr(alert, "attributes", {}) or {}
            event_id = attrs.get("zabbix_id")
            if not event_id:
                continue
            event_map.setdefault(event_id, []).append(alert)

        if not event_map:
            logger.warning("No alerts with Zabbix event IDs found")
            return

        event_ids_to_close = poll_zabbix_events(list(event_map.keys()))
        if not event_ids_to_close:
            logger.warning("No Zabbix events to close")
            return

        event_ids_tuple = tuple(str(eid) for eid in event_ids_to_close)

        Query = namedtuple("Query", ["where", "vars", "sort", "group"])
        query_filtered_alerts = Query(
            where="attributes->>'zabbix_id' IN %(filtered_event_ids)s AND \"status\" <> %(status)s",
            vars={'filtered_event_ids': event_ids_tuple, 'status': 'closed'},
            sort="create_time DESC",
            group=[]
        )

        filtered_alerts = Alert.find_all_really(query_filtered_alerts)  # Find alerts to close
        if not filtered_alerts:
            logger.warning("No matching alerts to close")
            return
        logger.warning(f"Found {len(filtered_alerts)} alerts to close")

        g.login = "admin" # Set user for audit trail

        try:
            success_count, error_count = set_alerts_status(filtered_alerts)
            if success_count > 0:
                logger.warning(f"Successfully closed {success_count} alerts from Zabbix events")
            if error_count > 0:
                logger.warning(f"Failed to close {error_count} alerts")

        except Exception as exc:
            logger.exception(f"Unexpected error when closing alerts: {exc}")


def zabbix_login():
    try:
        zabbix = ZabbixAPI(ZABBIX_API_URL)
        zabbix.login(ZABBIX_USER, ZABBIX_PASSWORD)
        return zabbix
    except Exception as exc:
        logger.error("Ошибка подключения к Zabbix API: %s", exc)
        return None


scheduler = None

def init_zabbix_poll(app):
    global scheduler
    if scheduler and scheduler.running:
        logger.warning("Zabbix scheduler already running - skipping initialization")
        return

    try:
        scheduler = BackgroundScheduler()
        scheduler.add_job(
            func=lambda: check_alerts_for_close(app),
            trigger='interval',
            minutes=1,
            max_instances=1,
            coalesce=True,  # Combine missed executions
            id="zabbix_poll_job",
            replace_existing=True,
            misfire_grace_time=30  # Allow 30 seconds for misfires
        )
        scheduler.start()
        logger.info("Zabbix background polling started successfully")

    except Exception as e:
        logger.exception(f"Failed to initialize Zabbix polling scheduler: {e}")
        if scheduler:
            try:
                scheduler.shutdown()
            except:
                pass
            scheduler = None
