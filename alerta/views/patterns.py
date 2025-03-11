import logging

from flask import g, jsonify, request
from flask_cors import cross_origin

from alerta.app import db
from alerta.auth.decorators import permission
from alerta.exceptions import ApiError
from alerta.models.enums import Scope
from alerta.models.pattern import Pattern
from alerta.models.metrics import Timer, timer
from alerta.utils.response import jsonp
from alerta.utils.pattern_cache import PatternCache
from alerta.models.alert import Alert
from . import api

gets_timer = Timer('patterns', 'queries', 'Pattern queries', 'Total time and number of pattern queries')
create_timer = Timer('patterns', 'create', 'Create pattern', 'Total time and number of pattern created')
update_timer = Timer('patterns', 'update', 'Update pattern', 'Total time and number of pattern updated')
delete_timer = Timer('patterns', 'delete', 'Delete pattern', 'Total time and number of pattern deleted')

# Get all patterns
@api.route('/patterns', methods=['OPTIONS', 'GET'])
@cross_origin()
@permission(Scope.read_alerts)
@timer(gets_timer)
@jsonp
def get_patterns():
    patterns = db.get_patterns()
    return jsonify([{
        'id': p['id'],
        'name': p['name'],
        'sql_rule': p['sql_rule'],
        'priority': p['priority'],
        'is_active': p['is_active'],
        'create_time': p['create_time'],
        'update_time': p['update_time']
    } for p in patterns])

@api.route('/patterns/query_test', methods=['OPTIONS', 'POST'])
@cross_origin()
@permission(Scope.read_alerts)
@timer(gets_timer)
@jsonp
def pattern_query_test():
    data = request.json
    if not data.get('id') or not data.get('pattern_query'):
        raise ApiError("'id' and 'pattern_query' are required fields", 400)

    cache = PatternCache()
    patterns = cache.get_patterns()

    pattern_query = data.get('pattern_query')

    alert = Alert.find_by_id(data.get('id'))
    if not alert:
        raise ApiError(f"Alert with id {data.get('id')} not found", 404)

    pattern_duplicates = alert.pattern_match_duplicated(pattern_query=pattern_query)

    return jsonify({
        'message': 'Pattern query result',
        'original_alert': alert,
        'pattern_query': pattern_query,
        'pattern_duplicates': pattern_duplicates
    })

@api.route('/patterns/incident_test', methods=['OPTIONS', 'POST'])
@cross_origin()
@permission(Scope.read_alerts)
@timer(gets_timer)
@jsonp
def incident_query_test():
    data = request.json
    if not data.get('id') or not data.get('pattern_query'):
        raise ApiError("'id' and 'pattern_query' are required fields", 400)

    cache = PatternCache()
    patterns = cache.get_patterns()

    pattern_query = data.get('pattern_query')

    alert = Alert.find_by_id(data.get('id'))
    if not alert:
        raise ApiError(f"Alert with id {data.get('id')} not found", 404)

    current_duplicates = alert.attributes.get('duplicate alerts', [])
    pattern_approved = alert.pattern_match_childrens(child_alert_ids=current_duplicates, pattern_query=pattern_query)

    return jsonify({
        'message': 'Pattern query result',
        'original_alert': alert,
        'pattern_query': pattern_query,
        'pattern_approved': pattern_approved
    })

@api.route('/patterns', methods=['OPTIONS', 'POST'])
@cross_origin()
@permission(Scope.write_alerts)
@timer(create_timer)
@jsonp
def create_pattern():
    data = request.json
    if not data.get('name') or not data.get('sql_rule'):
        raise ApiError("'name' and 'sql_rule' are required fields", 400)

    pattern = Pattern(
        name=data['name'],
        sql_rule=data['sql_rule'],
        priority=data.get('priority', 1),
        is_active=data.get('is_active', True)
    )

    pattern_id = db.create_pattern(name=pattern.name, sql_rule=pattern.sql_rule, priority=pattern.priority, is_active=pattern.is_active)
    pattern.id = pattern_id
    cache = PatternCache()
    cache.force_reload()
    return jsonify({'message': 'Pattern created', 'id': pattern.id}), 201

# Update an existing pattern
@api.route('/patterns/<int:pattern_id>', methods=['OPTIONS', 'PUT'])
@cross_origin()
@permission(Scope.write_alerts)
@timer(update_timer)
@jsonp
def update_pattern(pattern_id):
    data = request.json
    pattern = db.get_patterns()
    pattern = next((p for p in pattern if p['id'] == pattern_id), None)
    if not pattern:
        raise ApiError(f"Pattern with id {pattern_id} not found", 404)

    updated_fields = {}
    if 'name' in data:
        updated_fields['name'] = data['name']
    if 'sql_rule' in data:
        updated_fields['sql_rule'] = data['sql_rule']
    if 'priority' in data:
        updated_fields['priority'] = data['priority']
    if 'is_active' in data:
        updated_fields['is_active'] = data['is_active']

    if updated_fields:
        db.update_pattern(pattern_id, **updated_fields)
        cache = PatternCache()
        cache.force_reload()

    return jsonify({'message': 'Pattern updated'})

@api.route('/patterns/<int:pattern_id>', methods=['OPTIONS', 'DELETE'])
@cross_origin()
@permission(Scope.write_alerts)
@timer(delete_timer)
@jsonp
def delete_pattern(pattern_id):
    pattern = db.get_patterns()
    pattern = next((p for p in pattern if p['id'] == pattern_id), None)
    if not pattern:
        raise ApiError(f"Pattern with id {pattern_id} not found", 404)

    db.delete_pattern(pattern_id)
    cache = PatternCache()
    cache.force_reload()
    return jsonify({'message': 'Pattern deleted'})

@api.route('/patterns/cache/reload', methods=['POST', 'GET'])
@cross_origin()
@permission(Scope.admin)
def reload_patterns_cache():
    cache = PatternCache()
    cache.force_reload()
    return jsonify(status="ok", message="Patterns cache reloaded")

@api.route('/patterns/cached', methods=['GET'])
@cross_origin()
@permission(Scope.read_alerts)
def get_cached_patterns():
    cache = PatternCache()
    patterns = cache.get_patterns()
    return jsonify([{
        'id': p['id'],
        'name': p['name'],
        'sql_rule': p['sql_rule'],
        'priority': p['priority'],
        'is_active': p['is_active'],
        'create_time': p['create_time'],
        'update_time': p['update_time']
    } for p in patterns])

@api.route('/patterns/history', methods=['GET'])
@permission(Scope.read_alerts)
def get_pattern_history():
    try:
        limit = request.args.get('limit', 100, type=int)
        offset = request.args.get('offset', 0, type=int)
        history = db.get_pattern_history(limit=limit, offset=offset)
        return jsonify(history=history, count=len(history))
    except Exception as e:
        raise ApiError(f"Failed to fetch pattern history: {str(e)}")


@api.route('/patterns/history', methods=['POST'])
@permission(Scope.write_alerts)
def add_pattern_history():
    data = request.json
    pattern_name = data.get('pattern_name')
    pattern_id = data.get('pattern_id')
    incident_id = data.get('incident_id')
    alert_id = data.get('alert_id')

    if not (pattern_name and pattern_id and incident_id and alert_id):
        raise ApiError("Missing required fields: pattern_name, pattern_id, incident_id, alert_id", 400)

    try:
        db.add_pattern_history(pattern_name, pattern_id, incident_id, alert_id)
        return jsonify(status='ok', message='Pattern history entry added.')
    except Exception as e:
        raise ApiError(f"Failed to add pattern history entry: {str(e)}")
