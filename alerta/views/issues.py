import logging
from flask import current_app, g, jsonify, request, url_for
from flask_cors import cross_origin

from alerta.app import qb
from alerta.auth.decorators import permission
from alerta.exceptions import ApiError
from alerta.models.alert import Alert
from alerta.models.issue import Issue
from alerta.utils.api import assign_customer
from alerta.utils.audit import write_audit_trail
from alerta.utils.paging import Page
from alerta.utils.response import jsonp
from alerta.database.base import Query

from . import api


@api.route('/issue', methods=['OPTIONS', 'POST'])
@cross_origin()
@permission('write:issues')
@jsonp
def create_issue():
    try:
        issue = Issue.parse(request.json)
    except ValueError as e:
        raise ApiError(str(e), 400)

    try:
        issue = issue.create()
    except Exception as e:
        raise ApiError(str(e), 500)

    write_audit_trail.send(current_app._get_current_object(), event='issue-created', message='Issue created',
                          user=g.login, customers=g.customers, scopes=g.scopes, resource_id=issue.id,
                          type='issue', request=request)

    if issue:
        return jsonify(status='ok', id=issue.id, issue=issue.serialize), 201
    else:
        raise ApiError('Issue could not be created', 500)


@api.route('/issue/<issue_id>', methods=['OPTIONS', 'GET'])
@cross_origin()
@permission('read:issues')
@jsonp
def get_issue(issue_id):
    issue = Issue.find_by_id(issue_id)

    if issue:
        return jsonify(status='ok', total=1, issue=issue.serialize)
    else:
        raise ApiError('Issue not found', 404)


@api.route('/issues', methods=['OPTIONS', 'GET'])
@cross_origin()
@permission('read:issues')
@jsonp
def list_issues():
    query_params = request.args.to_dict()
    
    # Формируем условия для запроса
    where_conditions = []
    
    # Фильтры по статусу, если указаны
    if 'status' in query_params:
        where_conditions.append(f"status='{query_params['status']}'")
    
    # Фильтры по другим параметрам (при необходимости)
    if 'severity' in query_params:
        where_conditions.append(f"severity='{query_params['severity']}'")
    
    # Объединяем условия
    where_clause = " AND ".join(where_conditions) if where_conditions else "1=1"
    
    # Сортировка
    sort = query_params.get('sort', 'create_time DESC')
    
    # Создаем объект Query
    query = Query(where=where_clause, sort=sort, group="")
    
    # Пагинация
    page = Page.from_params(query_params, 1000)
    
    # Получаем данные
    issues = Issue.find_all(query, page.page, page.page_size)
    total = len(issues)
    
    # Расчет пагинации
    total_pages = total // page.page_size + (1 if total % page.page_size > 0 else 0)
    has_more = page.page < total_pages

    if issues:
        return jsonify(
            status='ok',
            page=page.page,
            pageSize=page.page_size,
            pages=total_pages,
            more=has_more,
            issues=[issue.serialize for issue in issues],
            total=total
        )
    else:
        return jsonify(
            status='ok',
            page=page.page,
            pageSize=page.page_size,
            pages=0,
            more=False,
            issues=[],
            total=0
        )


@api.route('/issue/<issue_id>', methods=['OPTIONS', 'PUT'])
@cross_origin()
@permission('write:issues')
@jsonp
def update_issue(issue_id):
    if not request.json:
        raise ApiError('Nothing to change', 400)

    issue = Issue.find_by_id(issue_id)

    if not issue:
        raise ApiError('Issue not found', 404)

    update = request.json
    update_kwargs = {}
    
    if 'summary' in update:
        update_kwargs['summary'] = update['summary']
    if 'severity' in update:
        update_kwargs['severity'] = update['severity']
    if 'host_critical' in update:
        update_kwargs['host_critical'] = update['host_critical']
    if 'duty_admin' in update:
        update_kwargs['duty_admin'] = update['duty_admin']
    if 'description' in update:
        update_kwargs['description'] = update['description']
    if 'status' in update:
        update_kwargs['status'] = update['status']
    if 'inc_key' in update:
        update_kwargs['inc_key'] = update['inc_key']
    if 'slack_link' in update:
        update_kwargs['slack_link'] = update['slack_link']
    if 'disaster_link' in update:
        update_kwargs['disaster_link'] = update['disaster_link']
    if 'escalation_group' in update:
        update_kwargs['escalation_group'] = update['escalation_group']
    if 'attributes' in update:
        update_kwargs['attributes'] = update['attributes']
        
    if 'text' in update:
        text = update['text']
    else:
        text = 'Issue updated'
        
    try:
        updated = issue.update(**update_kwargs, text=text)
    except Exception as e:
        raise ApiError(str(e), 500)
        
    write_audit_trail.send(current_app._get_current_object(), event='issue-updated', message=text,
                         user=g.login, customers=g.customers, scopes=g.scopes, resource_id=issue.id,
                         type='issue', request=request)

    if updated:
        return jsonify(status='ok', issue=updated.serialize)
    else:
        raise ApiError('Issue not updated', 500)


@api.route('/issue/<issue_id>/alerts', methods=['OPTIONS', 'GET'])
@cross_origin()
@permission('read:issues')
@jsonp
def get_issue_alerts(issue_id):
    issue = Issue.find_by_id(issue_id)

    if not issue:
        raise ApiError('Issue not found', 404)
        
    query = Query(where=f"issue_id='{issue_id}'", sort="create_time DESC", group="")
    alerts = Alert.find_all_really(query)
    
    if alerts:
        return jsonify(
            status='ok',
            issue=issue.serialize,
            alerts=[alert.serialize for alert in alerts],
            total=len(alerts)
        )
    else:
        return jsonify(
            status='ok',
            issue=issue.serialize,
            alerts=[],
            total=0
        )


@api.route('/issue/<issue_id>', methods=['OPTIONS', 'DELETE'])
@cross_origin()
@permission('write:issues')
@jsonp
def delete_issue(issue_id):
    issue = Issue.find_by_id(issue_id)

    if not issue:
        raise ApiError('Issue not found', 404)
        
    # Массовое отвязывание всех алертов от проблемы
    try:
        if issue.alerts:
            # Используем массовый метод Alert.unlink_alerts_from_issue для отвязывания всех алертов
            Alert.unlink_alerts_from_issue(issue.alerts)
    except Exception as e:
        current_app.logger.warning(f'Failed to unlink alerts from issue {issue_id}: {str(e)}')
        
    try:
        deleted = Issue.delete_by_id(issue_id)
    except Exception as e:
        raise ApiError(str(e), 500)
        
    write_audit_trail.send(current_app._get_current_object(), event='issue-deleted', message='Issue deleted',
                         user=g.login, customers=g.customers, scopes=g.scopes, resource_id=issue_id,
                         type='issue', request=request)

    if deleted:
        return jsonify(status='ok')
    else:
        raise ApiError('Issue not deleted', 500)


@api.route('/issues/merge', methods=['OPTIONS', 'POST'])
@cross_origin()
@permission('write:issues')
@jsonp
def merge_issues():
    """
    Слияние алертов между проблемами.
    
    Принимает массив объектов в формате:
    [
      {
        issue_id: string,     // ID проблемы
        all?: boolean,        // Флаг перемещения всех алертов (опционально)
        alert_ids: string[]   // Список ID алертов для перемещения
      }
    ]
    """
    if not request.json:
        raise ApiError('No data provided', 400)
    
    try:
        merge_data = request.json
        
        # Проверка входных данных
        if not isinstance(merge_data, list) or len(merge_data) < 2:
            raise ApiError('Invalid input: need at least 2 issues to merge', 400)
        
        # Собираем информацию об issues
        issue_data = []
        incident_count = 0
        
        for item in merge_data:
            issue_id = item['issue_id']
            issue = Issue.find_by_id(issue_id)
            
            if not issue:
                logging.error(f'Issue {issue_id} not found')
                continue
                
            # Проверяем, является ли issue инцидентом
            is_incident = bool(issue.inc_key)
            if is_incident:
                incident_count += 1
                
            issue_info = {
                'issue': issue,
                'all': item.get('all', False),
                'alert_ids': item.get('alert_ids', []),
                'is_incident': is_incident,
                'create_time': issue.create_time
            }
            
            issue_data.append(issue_info)
        
        if len(issue_data) < 2:
            raise ApiError('Need at least 2 valid issues to merge', 400)
            
        # Если больше одного инцидента - ошибка
        if incident_count > 1:
            raise ApiError('Cannot merge multiple incidents', 400)
        
        # Определяем целевой issue TODO дорогая операция?
        target_issue = None
        incident_target = None # Проверяем наличие инцидента с all=True
        for item in issue_data:
            if item['is_incident'] and item['all']:
                incident_target = item
                break
        
        if incident_target:
            target_issue = incident_target['issue']
        else:
            target_issue = sorted(issue_data, key=lambda x: x['create_time'])[0]['issue']
        
        # Получаем список исходных issues, исключая целевой
        source_issues = [item for item in issue_data if item['issue'].id != target_issue.id]
        
        # Подготавливаем все ID алертов для массового перемещения
        all_alert_ids_to_move = []
        alerts_by_source = {}
        
        for source in source_issues:
            issue = source['issue']
            is_all = source['all']
            alert_ids = source['alert_ids']
            
            # Определяем список алертов для переноса
            alerts_to_move = []
            if is_all:
                alerts_to_move = issue.alerts
            else:
                alerts_to_move = alert_ids
                
            # Сохраняем алерты для каждого источника
            alerts_by_source[issue.id] = {
                'issue': issue,
                'alerts_to_move': alerts_to_move,
                'is_all': is_all
            }
            
            # Добавляем ID в общий список для массового поиска
            all_alert_ids_to_move.extend(alerts_to_move)
        
        # Если нет алертов для перемещения, возвращаем исходный target_issue
        if not all_alert_ids_to_move:
            return jsonify(status='ok', issue=target_issue.serialize)
        
        # Получаем все объекты Alert одним запросом
        all_alerts = Alert.find_by_ids(all_alert_ids_to_move) if all_alert_ids_to_move else []
        alert_map = {alert.id: alert for alert in all_alerts}
        
        # Перемещаем алерты из исходных issues в целевой
        for source_id, source_data in alerts_by_source.items():
            issue = source_data['issue']
            alerts_to_move = source_data['alerts_to_move']
            is_all = source_data['is_all']
            
            # Удаляем алерты из исходного issue
            if alerts_to_move:
                issue.mass_remove_alerts(alerts_to_move)
            
            # Находим объекты Alert для перемещения из нашего словаря
            alert_objs = [alert_map[alert_id] for alert_id in alerts_to_move if alert_id in alert_map]
            
            # Добавляем алерты в целевой issue
            if alert_objs:
                target_issue.mass_add_alerts(alert_objs)
            
            # Если все алерты удалены, удаляем исходный issue
            if is_all or len(issue.alerts) == 0:
                Issue.delete_by_id(issue.id)
        
        # Обновляем атрибуты целевого issue
        target_issue = target_issue.recalculate_and_update_issue()
        
        write_audit_trail.send(current_app._get_current_object(), event='issues-merged', 
                             message='Issues merged',
                             user=g.login, customers=g.customers, scopes=g.scopes, 
                             resource_id=target_issue.id, type='issue', request=request)
        
        return jsonify(status='ok', issue=target_issue.serialize)
        
    except ApiError:
        # Пробрасываем ошибки API дальше
        raise
    except Exception as e:
        # Логируем и возвращаем другие ошибки
        current_app.logger.exception(f'Error merging issues: {str(e)}')
        raise ApiError(f'Error merging issues: {str(e)}', 500)
