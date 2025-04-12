from datetime import datetime
import logging
from typing import Optional, Tuple

from flask import current_app, g

from alerta.app import plugins, db
from alerta.exceptions import (AlertaException, ApiError, BlackoutPeriod,
                               ForwardingLoop, HeartbeatReceived,
                               InvalidAction, RateLimit, RejectException)
from alerta.models.alert import Alert
from alerta.models.enums import Scope
from alerta.utils.pattern_cache import PatternCache
from alerta.utils.format import CustomJSONEncoder
import json

def assign_customer(wanted: str = None, permission: str = Scope.admin_alerts) -> Optional[str]:
    customers = g.get('customers', [])
    if wanted:
        if Scope.admin in g.scopes or permission in g.scopes:
            return wanted
        if wanted not in customers:
            raise ApiError(f"not allowed to set customer to '{wanted}'", 400)
        else:
            return wanted
    if customers:
        if len(customers) > 1:
            raise ApiError('must define customer as more than one possibility', 400)
        else:
            return customers[0]
    return None


def process_alert(alert: Alert) -> Alert:
    logging.debug('Processing alert: %s', alert)
    wanted_plugins, wanted_config = plugins.routing(alert)

    skip_plugins = False
    for plugin in wanted_plugins:
        if alert.is_suppressed:
            skip_plugins = True
            break
        try:
            alert = plugin.pre_receive(alert, config=wanted_config)
        except TypeError:
            alert = plugin.pre_receive(alert)  # for backward compatibility
        except (RejectException, HeartbeatReceived, BlackoutPeriod, RateLimit, ForwardingLoop, AlertaException):
            raise
        except Exception as e:
            if current_app.config['PLUGINS_RAISE_ON_ERROR']:
                raise RuntimeError(f"Error while running pre-receive plugin '{plugin.name}': {str(e)}")
            else:
                logging.error(f"Error while running pre-receive plugin '{plugin.name}': {str(e)}")
        if not alert:
            raise SyntaxError(f"Plugin '{plugin.name}' pre-receive hook did not return modified alert")


    try:
        is_new_alert = True
        if alert.origin and alert.origin.startswith("zabbix/"):
            alert, is_new_alert = alert.from_zabbix_create()
        else:
            alert = alert.create()

        if not is_new_alert:
            return alert

        cache = PatternCache()
        patterns = cache.get_patterns()
        logging.debug(f"Loaded patterns from cache: {patterns}")

        for pattern in patterns:
            if not pattern['is_active']:
                continue # skip inactive patterns
            try:
                # check if pattern matches alert
                matches = alert.pattern_match_duplicated(pattern_query=pattern['sql_rule'])
                if matches:
                    logging.debug(f"Match found for pattern '{pattern['name']}' with alert {alert.id}")
                    # print(f"Match found for pattern '{pattern['name']}' with alert {alert.id}")

                    incident = matches[0]  # picking first match as incident

                    # print(f"~~~ '{type(incident)}'")

                    time_window = current_app.config['PATTERN_GROUPING_TIME_WINDOW']

                    # check if incident is within time window
                    if incident.last_receive_time and incident.status == 'closed' and alert.create_time:
                        if (alert.create_time - incident.last_receive_time).seconds > time_window:
                            logging.debug(f"Alert is not within time window for pattern '{pattern['name']}'")
                            # print(f"Alert is not within time window for pattern '{pattern['name']}'")
                            continue

                    # if incident have patterns, check incident pattern priority
                    if 'patterns' in incident.attributes and incident.attributes['patterns']:
                        first_pattern = incident.attributes['patterns'][0]
                        first_pattern_priority = cache.get_pattern_priority_by_name(first_pattern)
                        if pattern['priority'] > first_pattern_priority:
                            logging.debug(f"Alert pattern priority is lower than incident pattern priority")
                            # print(f"Alert pattern priority is lower than incident pattern priority")
                            continue

                    if 'duplicate alerts' in incident.attributes and incident.attributes['duplicate alerts']:
                        childs = incident.get_children()
                        skip = False
                        for child in childs:
                            child_pattern_id = child.attributes.get('pattern_id')
                            if child_pattern_id is None or child_pattern_id != pattern['id']:
                                logging.debug(f"Pattern: {pattern['name']} - {child.id} is not a duplicate of incident {incident.id}")
                                # print(f"Pattern: {pattern['name']} - {child.id} is not a duplicate of incident {incident.id}")
                                skip = True
                                break
                        if skip:
                            logging.debug(f"Pattern: {pattern['name']} - SKIP")
                            # print(f"Pattern: {pattern['name']} - SKIP")
                            continue

                    incident = incident.deduplicate(alert)
                    # update alert info
                    # print(f"Pattern~1: {type(alert.attributes)} - TYPE")
                    alert.attributes['incident'] = False
                    alert.attributes['pattern_name'] = pattern['name']
                    alert.attributes['pattern_id'] = pattern['id']
                    alert.attributes['wasIncident'] = False
                    alert.attributes = alert.update_attributes(alert.attributes)

                    # update incident info
                    # print(f"Pattern~2: {type(incident.attributes)} - TYPE")
                    if incident.status == 'closed' or incident.status == 'expired':
                        previous_status = incident.get_previous_status()
                        if previous_status and alert.status != 'closed':
                            incident = incident.set_status(previous_status, text='Reopen rule')
                    incident.attributes['duplicate alerts'].append(alert.id)
                    if 'patterns' not in incident.attributes:
                        incident.attributes['patterns'] = []
                    incident.attributes['patterns'].append(pattern['name'])
                    incident.update_attributes(incident.attributes)

                    # adding history record
                    try:
                        db.add_pattern_history(
                            pattern_name=pattern['name'],
                            pattern_id=pattern['id'],
                            incident_id=incident.id,
                            alert_id=alert.id,
                        )
                    except Exception as e:
                        raise ApiError(f"Failed to add pattern history entry: {str(e)}")
                    logging.debug(f"History record added. Pattern: {pattern['name']}, Incident: {incident.id}, Alert: {alert.id}")
                    # print(f"History record added. Pattern: {pattern['name']}, Incident: {incident.id}, Alert: {alert.id}")

                    # stop processing patterns
                    break
            except Exception as e:
                logging.error(f"Error while matching pattern '{pattern['name']}': {str(e)}")

    except Exception as e:
        raise ApiError(str(e))

    wanted_plugins, wanted_config = plugins.routing(alert)

    alert_was_updated: bool = False
    for plugin in wanted_plugins:
        if skip_plugins:
            break
        try:
            updated = plugin.post_receive(alert, config=wanted_config)
        except TypeError:
            updated = plugin.post_receive(alert)  # for backward compatibility
        except AlertaException:
            raise
        except Exception as e:
            if current_app.config['PLUGINS_RAISE_ON_ERROR']:
                raise ApiError(f"Error while running post-receive plugin '{plugin.name}': {str(e)}")
            else:
                logging.error(f"Error while running post-receive plugin '{plugin.name}': {str(e)}")
        if updated:
            alert = updated
            alert_was_updated = True

    if alert_was_updated:
        alert.update_tags(alert.tags)
        alert.attributes = alert.update_attributes(alert.attributes)

    return alert


def process_action(alert: Alert, action: str, text: str, timeout: int = None, post_action: bool = False) -> Tuple[Alert, str, str, Optional[int], Optional[bool]]:
    logging.debug('Processing action: %s', action)
    wanted_plugins, wanted_config = plugins.routing(alert)

    updated = None
    alert_was_updated = False
    for plugin in wanted_plugins:
        if alert.is_suppressed:
            break
        try:
            if post_action:
                updated = plugin.post_action(alert, action, text, timeout=timeout, config=wanted_config)
            else:
                updated = plugin.take_action(alert, action, text, timeout=timeout, config=wanted_config)
        except NotImplementedError:
            pass  # plugin does not support take_action() method or post_action() method
        except (RejectException, ForwardingLoop, InvalidAction, AlertaException):
            raise
        except Exception as e:
            if current_app.config['PLUGINS_RAISE_ON_ERROR']:
                raise ApiError(f"Error while running action plugin '{plugin.name}': {str(e)}")
            else:
                logging.error(f"Error while running action plugin '{plugin.name}': {str(e)}")

        if isinstance(updated, Alert):
            updated = updated, action, text, timeout
        if isinstance(updated, tuple):
            if len(updated) == 4:
                alert, action, text, timeout = updated
            elif len(updated) == 3:
                alert, action, text = updated
        if updated:
            alert_was_updated = True

    if alert_was_updated:
        alert.update_tags(alert.tags)
        alert.attributes = alert.update_attributes(alert.attributes)

    return alert, action, text, timeout, alert_was_updated


def process_note(alert: Alert, text: str) -> Tuple[Alert, str]:

    wanted_plugins, wanted_config = plugins.routing(alert)

    updated = None
    alert_was_updated = False
    for plugin in wanted_plugins:
        try:
            updated = plugin.take_note(alert, text, config=wanted_config)
        except NotImplementedError:
            pass  # plugin does not support take_note() method
        except (RejectException, ForwardingLoop, AlertaException):
            raise
        except Exception as e:
            if current_app.config['PLUGINS_RAISE_ON_ERROR']:
                raise ApiError(f"Error while running note plugin '{plugin.name}': {str(e)}")
            else:
                logging.error(f"Error while running note plugin '{plugin.name}': {str(e)}")

        if isinstance(updated, Alert):
            updated = updated, text
        if isinstance(updated, tuple) and len(updated) == 2:
            alert, text = updated
        if updated:
            alert_was_updated = True

    if alert_was_updated:
        alert.update_tags(alert.tags)
        alert.update_attributes(alert.attributes)

    return alert, text


def process_status(alert: Alert, status: str, text: str) -> Tuple[Alert, str, str]:
    logging.debug('Processing status: %s', status)
    wanted_plugins, wanted_config = plugins.routing(alert)

    updated = None
    alert_was_updated = False
    for plugin in wanted_plugins:
        if alert.is_suppressed:
            break
        try:
            updated = plugin.status_change(alert, status, text, config=wanted_config)
        except TypeError:
            updated = plugin.status_change(alert, status, text)  # for backward compatibility
        except (RejectException, AlertaException):
            raise
        except Exception as e:
            if current_app.config['PLUGINS_RAISE_ON_ERROR']:
                raise ApiError(f"Error while running status plugin '{plugin.name}': {str(e)}")
            else:
                logging.error(f"Error while running status plugin '{plugin.name}': {str(e)}")
        if updated:
            alert_was_updated = True
            try:
                alert, status, text = updated
            except Exception:
                alert = updated

    if alert_was_updated:
        alert.update_tags(alert.tags)
        alert.attributes = alert.update_attributes(alert.attributes)

    return alert, status, text


def process_delete(alert: Alert) -> bool:

    wanted_plugins, wanted_config = plugins.routing(alert)

    delete = True
    for plugin in wanted_plugins:
        try:
            delete = delete and plugin.delete(alert, config=wanted_config)
        except NotImplementedError:
            pass  # plugin does not support delete() method
        except (RejectException, AlertaException):
            raise
        except Exception as e:
            if current_app.config['PLUGINS_RAISE_ON_ERROR']:
                raise ApiError(f"Error while running delete plugin '{plugin.name}': {str(e)}")
            else:
                logging.error(f"Error while running delete plugin '{plugin.name}': {str(e)}")

    return delete and alert.delete()
