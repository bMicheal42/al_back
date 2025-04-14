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
    page = Page.from_params(query_params)

    total = 0
    issues = []

    query = qb.from_params(query_params)
    issues = Issue.find_all(query, page.page, page.page_size)
    total = len(issues)

    if issues:
        return jsonify(
            status='ok',
            page=page.page,
            pageSize=page.page_size,
            pages=page.pages(total),
            more=page.has_more(total),
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
        
    query = {'issue_id': issue_id}
    page = Page.from_params(request.args)
    
    alerts = Alert.find_all(query, page.page, page.page_size)
    
    if alerts:
        return jsonify(
            status='ok',
            issue=issue.serialize,
            page=page.page,
            pageSize=page.page_size,
            pages=page.pages(len(alerts)),
            more=page.has_more(len(alerts)),
            alerts=[alert.serialize for alert in alerts],
            total=len(alerts)
        )
    else:
        return jsonify(
            status='ok',
            issue=issue.serialize,
            page=page.page,
            pageSize=page.page_size,
            pages=0,
            more=False,
            alerts=[],
            total=0
        )


@api.route('/issue/<issue_id>/alert/<alert_id>', methods=['OPTIONS', 'PUT'])
@cross_origin()
@permission('write:issues')
@jsonp
def add_alert_to_issue(issue_id, alert_id):
    issue = Issue.find_by_id(issue_id)
    if not issue:
        raise ApiError('Issue not found', 404)
        
    alert = Alert.find_by_id(alert_id)
    if not alert:
        raise ApiError('Alert not found', 404)
        
    if alert.issue_id and alert.issue_id != issue_id:
        # Alert already assigned to another issue
        raise ApiError('Alert already assigned to another issue', 409)
        
    try:
        alert = alert.link_to_issue(issue_id)
        issue = issue.add_alert(alert_id)
    except Exception as e:
        raise ApiError(str(e), 500)
        
    write_audit_trail.send(current_app._get_current_object(), event='alert-linked', message='Alert linked to issue',
                         user=g.login, customers=g.customers, scopes=g.scopes, resource_id=alert.id,
                         type='alert', request=request)
                         
    return jsonify(status='ok', issue=issue.serialize, alert=alert.serialize)


@api.route('/issue/<issue_id>/alert/<alert_id>', methods=['OPTIONS', 'DELETE'])
@cross_origin()
@permission('write:issues')
@jsonp
def remove_alert_from_issue(issue_id, alert_id):
    issue = Issue.find_by_id(issue_id)
    if not issue:
        raise ApiError('Issue not found', 404)
        
    alert = Alert.find_by_id(alert_id)
    if not alert:
        raise ApiError('Alert not found', 404)
        
    if not alert.issue_id or alert.issue_id != issue_id:
        # Alert not assigned to this issue
        raise ApiError('Alert not assigned to this issue', 409)
        
    try:
        alert = alert.unlink_from_issue()
        issue = issue.remove_alert(alert_id)
    except Exception as e:
        raise ApiError(str(e), 500)
        
    write_audit_trail.send(current_app._get_current_object(), event='alert-unlinked', message='Alert unlinked from issue',
                         user=g.login, customers=g.customers, scopes=g.scopes, resource_id=alert.id,
                         type='alert', request=request)
                         
    return jsonify(status='ok', issue=issue.serialize, alert=alert.serialize)


@api.route('/issue/<issue_id>', methods=['OPTIONS', 'DELETE'])
@cross_origin()
@permission('write:issues')
@jsonp
def delete_issue(issue_id):
    issue = Issue.find_by_id(issue_id)

    if not issue:
        raise ApiError('Issue not found', 404)
        
    # Unlink all alerts from this issue
    for alert_id in issue.alerts:
        try:
            alert = Alert.find_by_id(alert_id)
            if alert and alert.issue_id == issue_id:
                alert.unlink_from_issue()
        except Exception as e:
            current_app.logger.warning(f'Failed to unlink alert {alert_id}: {str(e)}')
        
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


@api.route('/issue/<issue_id>/resolve', methods=['OPTIONS', 'PUT'])
@cross_origin()
@permission('write:issues')
@jsonp
def resolve_issue(issue_id):
    issue = Issue.find_by_id(issue_id)

    if not issue:
        raise ApiError('Issue not found', 404)
        
    text = request.json.get('text', '') if request.json else ''
    
    try:
        issue = issue.resolve(text=text)
    except Exception as e:
        raise ApiError(str(e), 500)
        
    write_audit_trail.send(current_app._get_current_object(), event='issue-resolved', message='Issue resolved',
                         user=g.login, customers=g.customers, scopes=g.scopes, resource_id=issue.id,
                         type='issue', request=request)

    return jsonify(status='ok', issue=issue.serialize)


@api.route('/issue/<issue_id>/reopen', methods=['OPTIONS', 'PUT'])
@cross_origin()
@permission('write:issues')
@jsonp
def reopen_issue(issue_id):
    issue = Issue.find_by_id(issue_id)

    if not issue:
        raise ApiError('Issue not found', 404)
        
    text = request.json.get('text', '') if request.json else ''
    
    try:
        issue = issue.reopen(text=text)
    except Exception as e:
        raise ApiError(str(e), 500)
        
    write_audit_trail.send(current_app._get_current_object(), event='issue-reopened', message='Issue reopened',
                         user=g.login, customers=g.customers, scopes=g.scopes, resource_id=issue.id,
                         type='issue', request=request)

    return jsonify(status='ok', issue=issue.serialize) 