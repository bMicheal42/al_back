from datetime import datetime, timezone
import threading
from typing import Dict, List, Any

from flask import current_app, g, jsonify, request
from flask_cors import cross_origin

from alerta.app import qb, db
from alerta.auth.decorators import permission
from alerta.exceptions import (AlertaException, ApiError, BlackoutPeriod,
                               ForwardingLoop, HeartbeatReceived,
                               InvalidAction, RateLimit, RejectException)
from alerta.models.alert import Alert
from alerta.models.enums import Scope
from alerta.models.metrics import Timer, timer
from alerta.models.note import Note
from alerta.models.switch import Switch
from alerta.utils.api import (assign_customer, process_action, process_alert,
                              process_delete, process_note, process_status)
from alerta.utils.audit import write_audit_trail
from alerta.utils.paging import Page
from alerta.utils.response import absolute_url, jsonp
from alerta.utils.pattern_cache import PatternCache
from alerta.utils.format import CustomJSONEncoder
import json
import logging
from . import api
from collections import namedtuple

receive_timer = Timer('alerts', 'received', 'Received alerts', 'Total time and number of received alerts')
gets_timer = Timer('alerts', 'queries', 'Alert queries', 'Total time and number of alert queries')
status_timer = Timer('alerts', 'status', 'Alert status change', 'Total time and number of alerts with status changed')
tag_timer = Timer('alerts', 'tagged', 'Tagging alerts', 'Total time to tag number of alerts')
untag_timer = Timer('alerts', 'untagged', 'Removing tags from alerts', 'Total time to un-tag and number of alerts')
attrs_timer = Timer('alerts', 'attributes', 'Alert attributes change',
                    'Total time and number of alerts with attributes changed')
delete_timer = Timer('alerts', 'deleted', 'Deleted alerts', 'Total time and number of deleted alerts')
count_timer = Timer('alerts', 'counts', 'Count alerts', 'Total time and number of count queries')

Query = namedtuple('Query', ['where', 'vars', 'sort', 'group'])
Query.__new__.__defaults__ = ('1=1', {}, '(select 1)', 'status')

receive_lock = threading.Lock()

@api.route('/alert', methods=['OPTIONS', 'POST'])
@cross_origin()
@permission(Scope.write_alerts)
@timer(receive_timer)
@jsonp
def receive():
    if not receive_lock.acquire(timeout=5):
        return jsonify(status='error', message='Server busy, try again later'), 503

    try:
        try:
            alert = Alert.parse(request.json)
        except ValueError as e:
            raise ApiError(str(e), 400)

        alert.customer = assign_customer(wanted=alert.customer)

        logging.warning(f"[alert_post] - json: {request.json}")
        logging.warning(json.dumps(request.json, indent=4, ensure_ascii=False, cls=CustomJSONEncoder))

        def audit_trail_alert(event: str):
            write_audit_trail.send(
                current_app._get_current_object(), event=event, message=alert.text, user=g.login,
                customers=g.customers, scopes=g.scopes, resource_id=alert.id, type='alert', request=request
            )

        try:
            alert = process_alert(alert)
        except RejectException as e:
            audit_trail_alert(event='alert-rejected')
            raise ApiError(str(e), 403)
        except RateLimit as e:
            audit_trail_alert(event='alert-rate-limited')
            return jsonify(status='error', message=str(e), id=alert.id), 429
        except HeartbeatReceived as heartbeat:
            audit_trail_alert(event='alert-heartbeat')
            return jsonify(status='ok', message=str(heartbeat), id=heartbeat.id), 202
        except BlackoutPeriod as e:
            audit_trail_alert(event='alert-blackout')
            return jsonify(status='ok', message=str(e), id=alert.id), 202
        except ForwardingLoop as e:
            return jsonify(status='ok', message=str(e)), 202
        except AlertaException as e:
            raise ApiError(e.message, code=e.code, errors=e.errors)
        except Exception as e:
            raise ApiError(str(e), 500)

        write_audit_trail.send(
            current_app._get_current_object(), event='alert-received', message=alert.text, user=g.login,
            customers=g.customers, scopes=g.scopes, resource_id=alert.id, type='alert', request=request
        )

        if alert:
            return jsonify(status='ok', id=alert.id, alert=alert.serialize), 201
        else:
            raise ApiError('insert or update of received alert failed', 500)

    finally:
        receive_lock.release()

@api.route('/alert/<alert_id>', methods=['OPTIONS', 'GET'])
@cross_origin()
@permission(Scope.read_alerts)
@timer(gets_timer)
@jsonp
def get_alert(alert_id):
    customers = g.get('customers', None)
    alert = Alert.find_by_id(alert_id, customers)

    if alert:
        return jsonify(status='ok', total=1, alert=alert.serialize)
    else:
        raise ApiError('not found', 404)


# set status
@api.route('/alert/<alert_id>/status', methods=['OPTIONS', 'PUT'])
@cross_origin()
@permission(Scope.write_alerts)
@timer(status_timer)
@jsonp
def set_status(alert_id):
    status = request.json.get('status', None)
    text = request.json.get('text', '')
    timeout = request.json.get('timeout', None)

    if not status:
        raise ApiError("must supply 'status' as json data", 400)

    customers = g.get('customers', None)
    alert = Alert.find_by_id(alert_id, customers)

    if not alert:
        raise ApiError('not found', 404)

    try:
        alert, status, text = process_status(alert, status, text)
        alert = alert.from_status(status, text, timeout)
    except RejectException as e:
        write_audit_trail.send(current_app._get_current_object(), event='alert-status-rejected', message=alert.text,
                               user=g.login, customers=g.customers, scopes=g.scopes, resource_id=alert.id, type='alert',
                               request=request)
        raise ApiError(str(e), 400)
    except AlertaException as e:
        raise ApiError(e.message, code=e.code, errors=e.errors)
    except Exception as e:
        raise ApiError(str(e), 500)

    write_audit_trail.send(current_app._get_current_object(), event='alert-status-changed', message=text, user=g.login,
                           customers=g.customers, scopes=g.scopes, resource_id=alert.id, type='alert', request=request)
    if alert:
        return jsonify(status='ok')
    else:
        raise ApiError('failed to set status', 500)


def background_post_action(app, g_data, alert, action, text, timeout):
    with app.app_context():
        with app.test_request_context():
            g.login = g_data.get("login")
            g.customers = g_data.get("customers")
            g.scopes = g_data.get("scopes")
            try:
                process_action(alert, action, text, timeout, post_action=True)
            except Exception as e:
                app.logger.warning(f"Error at separated post_action: {e}")


# action alert
@api.route('/alert/<alert_id>/action', methods=['OPTIONS', 'PUT'])
@cross_origin()
@permission(Scope.write_alerts)
@timer(status_timer)
@jsonp
def action_alert(alert_id):
    action = request.json.get('action', None)
    text = request.json.get('text', f'{action} operator action')
    timeout = request.json.get('timeout', None)
    user_req_date = request.headers.get('X-TimeStamp')
    got_date = datetime.utcnow().replace(tzinfo=timezone.utc)
    if user_req_date:
        user_req_date = datetime.fromtimestamp(int(user_req_date) / 1000, tz=timezone.utc)
    logging.debug(f'action: {action}, text: {text}, timeout: {timeout}')
    if not action:
        raise ApiError("must supply 'action' as json data", 400)

    customers = g.get('customers', None)
    alert = Alert.find_by_id(alert_id, customers)

    if not alert:
        raise ApiError('not found', 404)

    try:
        # pre action
        alert, action, text, timeout, was_updated = process_action(alert, action, text, timeout)
        # update status
        alert = alert.from_action(action, text, timeout)
        if was_updated:
            alert = alert.recalculate_incident_close()
            alert.recalculate_status_durations()
            
            # Добавляем атрибут 'acked-by' при действии ack
            if action == 'ack':
                alert.attributes['acked-by'] = g.login
                
            alert.update_attributes(alert.attributes)
        # post action
        g_data = {
            "login": g.get("login"),
            "customers": customers,
            "scopes": g.get("scopes")
        }

        thread = threading.Thread(target=background_post_action, args=(current_app._get_current_object(), g_data, alert, action, text, timeout))
        thread.start()
    except RejectException as e:
        write_audit_trail.send(current_app._get_current_object(), event='alert-action-rejected', message=alert.text,
                               user=g.login, customers=g.customers, scopes=g.scopes, resource_id=alert.id, type='alert',
                               request=request)
        raise ApiError(str(e), 400)
    except InvalidAction as e:
        raise ApiError(str(e), 409)
    except ForwardingLoop as e:
        return jsonify(status='ok', message=str(e)), 202
    except AlertaException as e:
        raise ApiError(e.message, code=e.code, errors=e.errors)
    except Exception as e:
        raise ApiError(str(e), 500)

    write_audit_trail.send(current_app._get_current_object(), event='alert-actioned', message=text, user=g.login,
                           customers=g.customers, scopes=g.scopes, resource_id=alert.id, type='alert', request=request)

    if alert:
        finish = datetime.utcnow().replace(tzinfo=timezone.utc)
        current_app.logger.info(f"""
        [Action log] ID: {alert.id} - {g.login}
            Action: {action}
            Created: {user_req_date}
            Got: {got_date} ({(got_date - user_req_date) if user_req_date else None})
            Answer: {finish} ({(finish - user_req_date) if user_req_date else None})
        """)
        return jsonify(status='ok')
    else:
        raise ApiError('failed to action alert', 500)


# tag
@api.route('/alert/<alert_id>/tag', methods=['OPTIONS', 'PUT'])
@cross_origin()
@permission(Scope.write_alerts)
@timer(tag_timer)
@jsonp
def tag_alert(alert_id):
    tags = request.json.get('tags', None)

    if not tags:
        raise ApiError("must supply 'tags' as json list")

    customers = g.get('customers', None)
    alert = Alert.find_by_id(alert_id, customers)

    if not alert:
        raise ApiError('not found', 404)

    write_audit_trail.send(current_app._get_current_object(), event='alert-tagged', message='', user=g.login,
                           customers=g.customers, scopes=g.scopes, resource_id=alert.id, type='alert', request=request)

    if alert.tag(tags):
        return jsonify(status='ok')
    else:
        raise ApiError('failed to tag alert', 500)


# untag
@api.route('/alert/<alert_id>/untag', methods=['OPTIONS', 'PUT'])
@cross_origin()
@permission(Scope.write_alerts)
@timer(untag_timer)
@jsonp
def untag_alert(alert_id):
    tags = request.json.get('tags', None)

    if not tags:
        raise ApiError("must supply 'tags' as json list")

    customers = g.get('customers', None)
    alert = Alert.find_by_id(alert_id, customers)

    if not alert:
        raise ApiError('not found', 404)

    write_audit_trail.send(current_app._get_current_object(), event='alert-untagged', message='', user=g.login,
                           customers=g.customers, scopes=g.scopes, resource_id=alert.id, type='alert', request=request)

    if alert.untag(tags):
        return jsonify(status='ok')
    else:
        raise ApiError('failed to untag alert', 500)


# update attributes
@api.route('/alert/<alert_id>/attributes', methods=['OPTIONS', 'PUT'])
@cross_origin()
@permission(Scope.write_alerts)
@timer(attrs_timer)
@jsonp
def update_attributes(alert_id):
    attributes = request.json.get('attributes', None)

    if not attributes:
        raise ApiError("must supply 'attributes' as json data", 400)

    customers = g.get('customers', None)
    alert = Alert.find_by_id(alert_id, customers)

    if not alert:
        raise ApiError('not found', 404)

    write_audit_trail.send(current_app._get_current_object(), event='alert-attributes-updated', message='', user=g.login,
                           customers=g.customers, scopes=g.scopes, resource_id=alert.id, type='alert', request=request)

    if alert.update_attributes(attributes):
        return jsonify(status='ok')
    else:
        raise ApiError('failed to update attributes', 500)

def process_move_diffs(alerts_dict: Dict[str, Dict], data: List[Dict]) -> Dict[str, Dict]:
    save_alerts = {}

    def find_earliest(ids: set) -> str:
        return min(ids, key=lambda x: alerts_dict[x].create_time)

    data_ids = {x['id'] for x in data}
    main_parent_id = find_earliest({x['id'] for x in data})
    main_parent = alerts_dict[main_parent_id]
    if not hasattr(main_parent, 'attributes'):
        main_parent.attributes = {}

    moved_alerts = set()

    for item in data:
        alert_id = item['id']
        alert = alerts_dict[alert_id]
        if not hasattr(alert, 'attributes'):
            main_parent.attributes = {}

        parent_id = item.get('parentId')
        all_flag = item.get('all', False)
        is_incident = alert.attributes.get('incident', False)
        duplicates = alert.attributes.get('duplicate alerts', [])

        if not is_incident:
            # moving non-incident alerts
            moved_alerts.add(alert_id)
            if parent_id:
                parent = alerts_dict[parent_id]
                if not hasattr(parent, 'attributes'):
                    parent.attributes = {}
                parent.attributes['duplicate alerts'] = [x for x in parent.attributes.get('duplicate alerts', []) if x != alert_id]
                save_alerts[parent_id] = parent.attributes
        else:
            # moving incident alerts
            if all_flag:
                for d_id in duplicates:
                    moved_alerts.add(d_id)
                if alert_id != main_parent_id:
                    moved_alerts.add(alert_id)
                    alert.attributes['duplicate alerts'] = []
                    alert.attributes['incident'] = False
                    save_alerts[alert_id] = alert.attributes
            else:
                if alert_id != main_parent_id:
                    moved_alerts.add(alert_id)
                    alert.attributes["incident"] = False
                    save_alerts[alert_id] = alert.attributes
                # deleting duplicates from data_ids
                for d_id in duplicates[:]:
                    if d_id in data_ids:
                        moved_alerts.add(d_id)
                        duplicates.remove(d_id)
                        save_alerts[alert_id] = alert.attributes

                # forming sub-group
                if len(duplicates) > 1:
                    sub_parent_id = find_earliest(set(duplicates))
                    sub_parent = alerts_dict[sub_parent_id]
                    if not hasattr(sub_parent, 'attributes'):
                        sub_parent.attributes = {}
                    sub_parent.attributes['duplicate alerts'] = [d for d in duplicates if d != sub_parent_id]
                elif len(duplicates) == 1:
                    sub_parent_id = duplicates[0]
                    sub_parent = alerts_dict[sub_parent_id]
                    if not hasattr(sub_parent, 'attributes'):
                        sub_parent.attributes = {}
                    sub_parent.attributes['duplicate alerts'] = []
                else:
                    # non-dublicate - skip
                    continue

                sub_parent.attributes['incident'] = True
                save_alerts[sub_parent_id] = sub_parent.attributes

                if alert_id != sub_parent_id:
                    alert.attributes['incident'] = False
                    alert.attributes['duplicate alerts'] = []
                    save_alerts[alert_id] = alert.attributes

    # writing main group
    main_parent.attributes['incident'] = True
    main_parent.attributes['duplicate alerts'] = main_parent.attributes.get('duplicate alerts', [])
    main_parent.attributes['duplicate alerts'].extend(a for a in moved_alerts if a not in main_parent.attributes['duplicate alerts'] and a != main_parent_id)
    save_alerts[main_parent_id] = main_parent.attributes

    return save_alerts

def recalculate_patterns(alerts_dict: Dict[str, Dict], pre_save_alerts: Dict[str, Dict]) -> Dict[str, Dict]:
    cache = PatternCache()
    patterns = cache.get_patterns()
    logging.debug(f"Loaded patterns from cache: {patterns}")

    for alert_id, attributes in list(pre_save_alerts.items()):
        if not attributes.get('incident', False):  # Skip if incident is False
            continue
        if not attributes.get('duplicate alerts'):  # Skip if "duplicate alerts" is empty or missing
            continue

        logging.debug(f"Processing alert {alert_id} with incident status")
        alert = alerts_dict[alert_id]

        for pattern in patterns:
            if not pattern.get('is_active', False):
                continue
            try:
                if not alert_id in alerts_dict:
                    logging.warning(f"Not found in alerts_dict {alert_id}")
                # Check if pattern matches alert
                duplicate_ids = attributes.get('duplicate alerts', [])
                logging.debug(f"Checking duplicates for {alert_id}: {duplicate_ids}")

                alert.attributes = attributes
                matches = alert.pattern_match_childrens(
                    child_alert_ids=duplicate_ids,
                    pattern_query=pattern['sql_rule']
                )

                incident_attributes = pre_save_alerts[alert_id]
                incident_attributes['patterns'] = []

                if matches:
                    logging.debug(f"Pattern '{pattern['name']}' matched alert {alert_id}")

                    incident_attributes['patterns'].append(pattern['name'])

                    for child_id in duplicate_ids:
                        child_source = alerts_dict.get(child_id)
                        if not child_source:
                            raise ApiError(f"Child alert {child_id} not found for pattern regroup", 404)
                        child_source = child_source.attributes
                        if child_id in pre_save_alerts:
                            child_source = pre_save_alerts[child_id]

                        logging.debug(f"Updating child {child_id} for alert {alert_id}")

                        pre_save_alerts[child_id] = child_source
                        child_attributes = pre_save_alerts[child_id]
                        child_attributes['pattern_name'] = pattern['name']
                        child_attributes['pattern_id'] = pattern['id']

                        logging.debug(f"Updated child {child_id}: {child_attributes}")

                    # Stop processing further patterns once a match is found
                    break

            except Exception as e:
                logging.error(f"Error while matching pattern '{pattern['name']}': {str(e)}", exc_info=True)
                continue

    return pre_save_alerts

def sync_jira_fields(alerts_dict: Dict[str, Dict], save_alerts: Dict[str, Dict]) -> None:
    """
    Move jira keys to new parent. If conflict found (>1 jira keys - skip and warning)
    """
    jira_keys = {"jira_key", "jira_url", "jira_status"}

    for alert_id, attributes in list(save_alerts.items()):
        if not attributes.get("incident", False):
            continue

        duplicates = attributes.get("duplicate alerts", [])
        if not duplicates:
            continue

        for child_id in duplicates:
            child = alerts_dict[child_id]

            if child_id not in save_alerts:
                save_alerts[child_id] = child.attributes.copy()

            child_attrs = save_alerts[child_id]

            child_jira_data = {key: child.attributes.get(key) for key in jira_keys}
            if not any(child_jira_data.values()):
                continue

            for key, value in child_jira_data.items():
                if value is not None:
                    attributes[key] = value
                    child_attrs[key] = None

            logging.info(f"✅ Перенесены Jira-ключи {list(child_jira_data.keys())} из {child_id} в {alert_id}.")

def recalculate_last_receive_times(alerts_dict: Dict[str, Dict], save_alerts: Dict[str, Dict]) -> Dict[str, Any]:
    last_receive_times = {}

    def find_latest(ids: set) -> str:
        return max(ids, key=lambda x: alerts_dict[x].receive_time)

    for alert_id, attributes in list(save_alerts.items()):
        alert = alerts_dict[alert_id]

        is_incident = attributes.get('incident', False)
        duplicates = attributes.get('duplicate alerts', [])
        last_receive_time = getattr(alert, "last_receive_time", None)
        receive_time = getattr(alert, "receive_time", None)

        if not isinstance(receive_time, (str, datetime)) or (last_receive_time and not isinstance(last_receive_time, (str, datetime))):
            logging.error(f"Invalid type for receive_time in alert {alert_id}: receive_time={receive_time}, last_receive_time={last_receive_time}")
            continue

        if not is_incident:
            continue
        else:
            if not duplicates and last_receive_time != receive_time:
                last_receive_times[alert_id] = receive_time
            elif duplicates:
                latest_id = find_latest(set(duplicates))
                latest = alerts_dict[latest_id]
                latest_receive_time = getattr(latest, "receive_time", None)

                if latest_receive_time != last_receive_time:
                    last_receive_times[alert_id] = latest_receive_time

    return last_receive_times
@api.route('/alerts/move/<string:target_id>', methods=['OPTIONS', 'POST'])
@cross_origin()
@permission(Scope.write_alerts)
@timer(attrs_timer)
@jsonp
def move_alerts(target_id):
    """
    Move alerts to a new or existing incident.
    :param target_id: ID for chosen target alert
    :param request.json: list of objects with id: id, isIncident: boolean, parentId: id
    """
    if not request.json or not isinstance(request.json, list):
        raise ApiError("The request body must be a JSON array with moving objects data", 400)

    data = [item.copy() for item in request.json if isinstance(item, dict)]
    for item in data:
        if not isinstance(item, dict) or 'id' not in item:
            raise ApiError("Each item in the list must be an object with at least an 'id' field", 400)

    if not target_id == 'new':
        data.append({"id": target_id, "isIncident": True, "all": True})

    # Unique ids for alerts and their parents
    unique_ids = set()
    for alert_data in data:
        if alert_data.get("isIncident") and alert_data["id"] not in unique_ids:
            unique_ids.add(alert_data["id"])
        elif "parentId" in alert_data and alert_data["parentId"] not in unique_ids:
            unique_ids.add(alert_data["parentId"])

    # get all alerts from data and its parents if presented in data
    alerts = Alert.find_by_ids(list(unique_ids))
    if not alerts or not all(alerts):
        raise ApiError("Some of alerts not found", 404)

    extra_ids = set()  # getting all childs for all figurants

    for alert in alerts:
        if alert.attributes.get("incident"):
            duplicates = set(alert.attributes.get("duplicate alerts", []))
            new_ids = duplicates - unique_ids
            extra_ids.update(new_ids)

    if extra_ids:
        new_alerts = Alert.find_by_ids(list(extra_ids))
        alerts.extend(new_alerts)
        unique_ids.update(extra_ids)

    alerts_dict = {alert.id: alert for alert in alerts}

    # Check if cannot to obtain all alerts in dict
    data_ids = {alert_data["id"] for alert_data in data if "id" in alert_data}
    missing_ids = data_ids - alerts_dict.keys()

    if missing_ids:
        raise ApiError('Cannot find all targets to moving alerts', 404)
        logging.warning(f"[MOVE] Some IDs from data are missing in alerts_dict: {missing_ids}")

    logging.debug("[move] alerts_dict:")
    logging.debug(json.dumps(alerts_dict, indent=4, ensure_ascii=False, cls=CustomJSONEncoder))

    pre_save_alerts = process_move_diffs(alerts_dict, data)
    logging.debug("[move] pre_save_alerts:")
    logging.debug(json.dumps(pre_save_alerts, indent=4, ensure_ascii=False))
    save_alerts = recalculate_patterns(alerts_dict, pre_save_alerts)
    sync_jira_fields(alerts_dict, save_alerts)
    logging.debug("[move] save_alerts after jira sync:")
    logging.debug(json.dumps(save_alerts, indent=4, ensure_ascii=False, cls=CustomJSONEncoder))

    if not Alert.mass_update_attributes(save_alerts):
        raise ApiError('Failed to update attributes', 500)

    new_last_receive_times = recalculate_last_receive_times(alerts_dict, save_alerts)

    if not Alert.mass_update_last_receive_time(new_last_receive_times):
        raise ApiError('Failed to update lastReceiveTime fields', 500)

    # incident close updates
    close_updates = {}
    for alert_id, attributes in save_alerts.items():
        if attributes.get('incident'):
            incident = Alert.find_by_id(alert_id)
            close_updates[alert_id] = incident.recalculate_incident_close()

    db.add_move_history(
        user_name=g.login,
        attributes_dict=save_alerts,
    )

    write_audit_trail.send(
        current_app._get_current_object(),
        event='alerts-moved',
        message=f"Moved alerts to target",
        updates=save_alerts,
        user=g.login,
        customers=g.customers,
        scopes=g.scopes,
        resource_id=target_id,
        type='alert',
        request=request
    )

    return jsonify({
        "status": "ok",
        "updates": save_alerts,
        "close_updates": close_updates
    })

@api.route('/alerts/move_history', methods=['OPTIONS', 'GET'])
@cross_origin()
@permission(Scope.write_alerts)
@jsonp
def move_alerts_history():
    try:
        limit = request.args.get('limit', 100, type=int)
        offset = request.args.get('offset', 0, type=int)
        history = db.get_move_history(limit=limit, offset=offset)
        return jsonify(history=history, count=len(history))
    except Exception as e:
        raise ApiError(f"Failed to fetch alert move history: {str(e)}")


# delete
@api.route('/alert/<alert_id>', methods=['OPTIONS', 'DELETE'])
@cross_origin()
@permission(Scope.delete_alerts)
@timer(delete_timer)
@jsonp
def delete_alert(alert_id):
    customers = g.get('customers', None)
    alert = Alert.find_by_id(alert_id, customers)

    if not alert:
        raise ApiError('not found', 404)

    try:
        deleted = process_delete(alert)
    except RejectException as e:
        write_audit_trail.send(current_app._get_current_object(), event='alert-delete-rejected', message=alert.text,
                               user=g.login, customers=g.customers, scopes=g.scopes, resource_id=alert.id, type='alert',
                               request=request)
        raise ApiError(str(e), 400)
    except AlertaException as e:
        raise ApiError(e.message, code=e.code, errors=e.errors)
    except Exception as e:
        raise ApiError(str(e), 500)

    write_audit_trail.send(current_app._get_current_object(), event='alert-deleted', message='', user=g.login,
                           customers=g.customers, scopes=g.scopes, resource_id=alert.id, type='alert', request=request)

    if deleted:
        return jsonify(status='ok')
    else:
        raise ApiError('failed to delete alert', 500)


@api.route('/alerts', methods=['OPTIONS', 'GET'])
@cross_origin()
@permission(Scope.read_alerts)
@timer(gets_timer)
@jsonp
def search_alerts():
    query_time = datetime.utcnow()
    query = qb.alerts.from_params(request.args, customers=g.customers, query_time=query_time)
    show_raw_data = request.args.get('show-raw-data', default=False, type=lambda x: x.lower() in ['true', 't', '1', 'yes', 'y', 'on'])
    show_history = request.args.get('show-history', default=True, type=lambda x: x.lower() in ['true', 't', '1', 'yes', 'y', 'on'])
    severity_count = Alert.get_counts_by_severity(query)
    status_count = Alert.get_counts_by_status(query)

    total = sum(severity_count.values())
    paging = Page.from_params(request.args, total)

    alerts = Alert.find_all(query, raw_data=show_raw_data, history=show_history, page=paging.page, page_size=paging.page_size)

    # incident counts
    new_where = f"({query.where}) AND (attributes->>'incident')::boolean = true" if query.where else "(attributes->>'incident')::boolean = true"
    incident_query = Query(where=new_where, vars=query.vars, sort=query.sort, group=query.group)

    incident_severity_count = Alert.get_counts_by_severity(incident_query)
    incident_status_count = Alert.get_counts_by_status(incident_query)
    incident_total = sum(incident_severity_count.values())
    incident_paging = Page.from_params(request.args, incident_total)

    if alerts:
        return jsonify(
            status='ok',
            page=incident_paging.page,
            pageSize=incident_paging.page_size,
            pages=incident_paging.pages,
            more=incident_paging.has_more,
            alerts=[alert.serialize for alert in alerts],
            total=total,
            incidentTotal=incident_total,
            statusCounts=status_count,
            incidentStatusCounts=incident_status_count,
            severityCounts=severity_count,
            incidentSeverityCounts=incident_severity_count,
            lastTime=max([alert.last_receive_time for alert in alerts]),
            autoRefresh=Switch.find_by_name('auto-refresh-allow').is_on
        )
    else:
        return jsonify(
            status='ok',
            message='not found',
            page=paging.page,
            pageSize=paging.page_size,
            pages=0,
            more=False,
            alerts=[],
            total=0,
            severityCounts=severity_count,
            statusCounts=status_count,
            lastTime=query_time,
            autoRefresh=Switch.find_by_name('auto-refresh-allow').is_on
        )


@api.route('/alerts/history', methods=['OPTIONS', 'GET'])
@cross_origin()
@permission(Scope.read_alerts)
@timer(gets_timer)
@jsonp
def history():
    query = qb.alerts.from_params(request.args, customers=g.customers)
    paging = Page.from_params(request.args, items=0)
    history = Alert.get_history(query, paging.page, paging.page_size)

    if history:
        return jsonify(
            status='ok',
            history=[h.serialize for h in history],
            total=len(history)
        )
    else:
        return jsonify(
            status='ok',
            message='not found',
            history=[],
            total=0
        )


# severity counts
# status counts
@api.route('/alerts/count', methods=['OPTIONS', 'GET'])
@cross_origin()
@permission(Scope.read_alerts)
@timer(count_timer)
@jsonp
def get_counts():
    query = qb.alerts.from_params(request.args, customers=g.customers)
    severity_count = Alert.get_counts_by_severity(query)
    status_count = Alert.get_counts_by_status(query)

    # incident counts
    new_where = f"({query.where}) AND (attributes->>'incident')::boolean = true" if query.where else "(attributes->>'incident')::boolean = true"
    incident_query = Query(where=new_where, vars=query.vars, sort=query.sort, group=query.group)

    incident_severity_count = Alert.get_counts_by_severity(incident_query)
    incident_status_count = Alert.get_counts_by_status(incident_query)
    incident_total = sum(incident_severity_count.values())

    return jsonify(
        status='ok',
        total=sum(severity_count.values()),
        incidentTotal=incident_total,
        severityCounts=severity_count,
        incidentSeverityCounts=incident_severity_count,
        statusCounts=status_count,
        incidentStatusCounts=incident_status_count,
        autoRefresh=Switch.find_by_name('auto-refresh-allow').is_on
    )


# top 10 counts
@api.route('/alerts/top10/count', methods=['OPTIONS', 'GET'])
@api.route('/alerts/topn/count', methods=['OPTIONS', 'GET'])
@cross_origin()
@permission(Scope.read_alerts)
@timer(count_timer)
@jsonp
def get_topn_count():
    query = qb.alerts.from_params(request.args, customers=g.customers)
    paging = Page.from_params(request.args, 1)
    topn = Alert.get_topn_count(query, topn=paging.page_size)

    if topn:
        return jsonify(
            status='ok',
            top10=topn,
            total=len(topn)
        )
    else:
        return jsonify(
            status='ok',
            message='not found',
            top10=[],
            total=0
        )


# top 10 flapping
@api.route('/alerts/top10/flapping', methods=['OPTIONS', 'GET'])
@api.route('/alerts/topn/flapping', methods=['OPTIONS', 'GET'])
@cross_origin()
@permission(Scope.read_alerts)
@timer(count_timer)
@jsonp
def get_topn_flapping():
    query = qb.alerts.from_params(request.args, customers=g.customers)
    paging = Page.from_params(request.args, 1)
    topn = Alert.get_topn_flapping(query, topn=paging.page_size)

    if topn:
        return jsonify(
            status='ok',
            top10=topn,
            total=len(topn)
        )
    else:
        return jsonify(
            status='ok',
            message='not found',
            top10=[],
            total=0
        )


# top 10 standing
@api.route('/alerts/top10/standing', methods=['OPTIONS', 'GET'])
@api.route('/alerts/topn/standing', methods=['OPTIONS', 'GET'])
@cross_origin()
@permission(Scope.read_alerts)
@timer(count_timer)
@jsonp
def get_topn_standing():
    query = qb.alerts.from_params(request.args, customers=g.customers)
    paging = Page.from_params(request.args, 1)
    topn = Alert.get_topn_standing(query, topn=paging.page_size)

    if topn:
        return jsonify(
            status='ok',
            top10=topn,
            total=len(topn)
        )
    else:
        return jsonify(
            status='ok',
            message='not found',
            top10=[],
            total=0
        )


# get alert environments
@api.route('/environments', methods=['OPTIONS', 'GET'])
@cross_origin()
@permission(Scope.read_alerts)
@timer(gets_timer)
@jsonp
def get_environments():
    query = qb.alerts.from_params(request.args, customers=g.customers)
    environments = Alert.get_environments(query)

    if environments:
        return jsonify(
            status='ok',
            environments=environments,
            total=len(environments)
        )
    else:
        return jsonify(
            status='ok',
            message='not found',
            environments=[],
            total=0
        )


# get alert services
@api.route('/services', methods=['OPTIONS', 'GET'])
@cross_origin()
@permission(Scope.read_alerts)
@timer(gets_timer)
@jsonp
def get_services():
    query = qb.alerts.from_params(request.args, customers=g.customers)
    services = Alert.get_services(query)

    if services:
        return jsonify(
            status='ok',
            services=services,
            total=len(services)
        )
    else:
        return jsonify(
            status='ok',
            message='not found',
            services=[],
            total=0
        )


# get alert groups
@api.route('/alerts/groups', methods=['OPTIONS', 'GET'])
@cross_origin()
@permission(Scope.read_alerts)
@timer(gets_timer)
@jsonp
def get_groups():
    query = qb.alerts.from_params(request.args, customers=g.customers)
    groups = Alert.get_groups(query)

    if groups:
        return jsonify(
            status='ok',
            groups=groups,
            total=len(groups)
        )
    else:
        return jsonify(
            status='ok',
            message='not found',
            groups=[],
            total=0
        )


# get alert tags
@api.route('/alerts/tags', methods=['OPTIONS', 'GET'])
@cross_origin()
@permission(Scope.read_alerts)
@timer(gets_timer)
@jsonp
def get_tags():
    query = qb.alerts.from_params(request.args, customers=g.customers)
    tags = Alert.get_tags(query)

    if tags:
        return jsonify(
            status='ok',
            tags=tags,
            total=len(tags)
        )
    else:
        return jsonify(
            status='ok',
            message='not found',
            tags=[],
            total=0
        )


# add note
@api.route('/alert/<alert_id>/note', methods=['OPTIONS', 'PUT'])
@cross_origin()
@permission(Scope.write_alerts)
@jsonp
def add_note(alert_id):
    note_text = request.json.get('text') or request.json.get('note')

    if not note_text:
        raise ApiError("must supply 'note' text", 400)

    customers = g.get('customers', None)
    alert = Alert.find_by_id(alert_id, customers)

    if not alert:
        raise ApiError('not found', 404)

    try:
        alert, note_text = process_note(alert, note_text)
        note = alert.add_note(note_text)
    except RejectException as e:
        write_audit_trail.send(current_app._get_current_object(), event='alert-note-rejected', message='',
                               user=g.login, customers=g.customers, scopes=g.scopes, resource_id=note.id, type='note',
                               request=request)
        raise ApiError(str(e), 400)
    except ForwardingLoop as e:
        return jsonify(status='ok', message=str(e)), 202
    except AlertaException as e:
        raise ApiError(e.message, code=e.code, errors=e.errors)
    except Exception as e:
        raise ApiError(str(e), 500)

    write_audit_trail.send(current_app._get_current_object(), event='alert-note-added', message='', user=g.login,
                           customers=g.customers, scopes=g.scopes, resource_id=note.id, type='note', request=request)

    if note:
        return jsonify(status='ok', id=note.id, note=note.serialize), 201, {'Location': absolute_url(f'/alert/{alert.id}/note/{note.id}')}
    else:
        raise ApiError('failed to add note for alert', 500)


# list notes for an alert
@api.route('/alert/<alert_id>/notes', methods=['OPTIONS', 'GET'])
@cross_origin()
@permission(Scope.read_alerts)
@jsonp
def get_notes(alert_id):
    customers = g.get('customers', None)
    alert = Alert.find_by_id(alert_id, customers)

    if not alert:
        raise ApiError('not found', 404)

    notes = alert.get_alert_notes()

    if notes:
        return jsonify(
            status='ok',
            notes=[note.serialize for note in notes],
            total=len(notes)
        )
    else:
        return jsonify(
            status='ok',
            message='not found',
            notes=[],
            total=0
        )


# update note
@api.route('/alert/<alert_id>/note/<note_id>', methods=['OPTIONS', 'PUT'])
@cross_origin()
@permission(Scope.write_alerts)
@jsonp
def update_note(alert_id, note_id):
    if not request.json:
        raise ApiError('nothing to change', 400)

    customers = g.get('customers', None)
    alert = Alert.find_by_id(alert_id, customers)

    if not alert:
        raise ApiError('not found', 404)

    note = Note.find_by_id(note_id)

    if not note:
        raise ApiError('not found', 404)

    update = request.json
    update['user'] = g.login

    write_audit_trail.send(current_app._get_current_object(), event='alert-note-updated', message='', user=g.login,
                           customers=g.customers, scopes=g.scopes, resource_id=note.id, type='note',
                           request=request)

    _, update['text'] = process_note(alert, update.get('text'))
    updated = note.update(**update)
    if updated:
        return jsonify(status='ok', note=updated.serialize)
    else:
        raise ApiError('failed to update note', 500)


# delete note
@api.route('/alert/<alert_id>/note/<note_id>', methods=['OPTIONS', 'DELETE'])
@cross_origin()
@permission(Scope.write_alerts)
@jsonp
def delete_note(alert_id, note_id):
    customers = g.get('customers', None)
    alert = Alert.find_by_id(alert_id, customers)

    if not alert:
        raise ApiError('alert not found', 404)

    note = Note.find_by_id(note_id)

    if not note:
        raise ApiError('note not found', 404)

    write_audit_trail.send(current_app._get_current_object(), event='alert-note-deleted', message='', user=g.login,
                           customers=g.customers, scopes=g.scopes, resource_id=note.id, type='note', request=request)

    if alert.delete_note(note_id):
        return jsonify(status='ok')
    else:
        raise ApiError('failed to delete note', 500)
