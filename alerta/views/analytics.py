import logging
import math
import json
from io import BytesIO

from flask import g, jsonify, request, send_file
from flask_cors import cross_origin

from alerta.app import db
from alerta.auth.decorators import permission
from alerta.exceptions import ApiError
from alerta.models.enums import Scope
from alerta.models.metrics import Timer, timer
from alerta.utils.response import jsonp
from datetime import datetime
from . import api

gets_analytics = Timer('analytics', 'queries', 'First-step analysis - MTTD',
                       'Total time and number of First-step analysis - MTTD analytics')
raw_analytics = Timer('analytics', 'raw', 'Raw analtyics data', 'Total time and number of prepared raw data')


def is_iso_datetime(date_str):
    if not isinstance(date_str, str):
        return None
    try:
        if date_str.endswith("Z"):
            date_str = date_str[:-1]
        return datetime.fromisoformat(date_str)
    except ValueError:
        return None


# datetime to sec
def get_sec(date):
    return int(date.timestamp())


# calc severity value
def get_severity_value(severity):
    severity_map = {"critical": 3, "high": 2, "medium": 1}
    return severity_map.get(severity, 0)


# prepare raw data to calculate stats
def prepare_info(raw):
    alerts_dict = {alert["id"]: alert.copy() for alert in raw}
    original_order = [alert["id"] for alert in raw]

    ids = sorted(original_order, key=lambda id_: alerts_dict[id_].get("incident", False), reverse=True)

    for id_ in ids:
        current = alerts_dict[id_]
        current["incident_resolve_time"] = current.get("zabbix_resolve_time")

        if get_severity_value(current.get("severity", "medium")) == 0:
            current["severity"] = "medium"

        if current.get("incident"):
            current["duplicate_count"] = len(current.get("duplicate_alerts", []))
            current["inc_severity"] = current["severity"]
            need_update_inc_resolution = bool(current.get("resolve_time") and not current.get("zabbix_resolve_time"))

            for child_id in current.get("duplicate_alerts", []):
                child = alerts_dict.get(child_id)
                if child:
                    child["parent_id"] = current["id"]

                    # Повышение инцидентной серьезности, если у дубликата выше
                    if get_severity_value(child.get("severity", "medium")) > get_severity_value(
                            current["inc_severity"]):
                        current["inc_severity"] = child["severity"]

                    if need_update_inc_resolution and child.get("zabbix_resolve_time"):
                        current["incident_resolve_time"] = child["zabbix_resolve_time"]
                        need_update_inc_resolution = False

                    if current.get("false_positive_time"):
                        child["false_positive_time"] = current["false_positive_time"]

            if current.get("false_positive_time") and current.get("ack_time"):
                current["inc_ttu_false_positive_sec"] = get_sec(current["false_positive_time"]) - get_sec(
                    current["ack_time"])

            if current.get("fixing_time") and current.get("ack_time"):
                current["inc_ttu_fixing_sec"] = get_sec(current["fixing_time"]) - get_sec(current["ack_time"])
        else:
            if current.get("zabbix_resolve_time") and not current.get("resolve_time"):
                current["resolve_time"] = current["zabbix_resolve_time"]

        if current.get("ack_time"):
            current["alert_ttd_sec"] = get_sec(current["ack_time"]) - get_sec(current["receive_time"])

        if current.get("resolve_time"):
            current["alert_ttr_sec"] = get_sec(current["resolve_time"]) - get_sec(current["receive_time"])

        current["flap"] = bool(current.get("resolve_time") and (current.get("alert_ttr_sec") or 0) < 300)

    for id_ in ids:
        current = alerts_dict[id_]
        current.pop("duplicate_alerts", None)
        current.pop("zabbix_resolve_time", None)

    return [alerts_dict[id_] for id_ in original_order]


def calculate_percentile(values, percentile):
    if not values:
        return 0
    values.sort()
    index = math.ceil((percentile / 100) * len(values)) - 1
    return round(values[max(0, index)] / 60, 2)


def calculate_stats(values):
    stats = {}
    grouped_by_severity = {"total": values, "critical": [], "high": [], "medium": []}

    for alert in values:
        if alert["severity"] in grouped_by_severity:
            grouped_by_severity[alert["severity"]].append(alert)

    for severity, alerts in grouped_by_severity.items():
        grouped_by_acked_by = {"all": alerts}

        for alert in alerts:
            acked_by = alert.get("acked_by")
            if acked_by:
                grouped_by_acked_by.setdefault(acked_by, []).append(alert)

        stats[severity] = {}

        for acked_by, alerts_subset in grouped_by_acked_by.items():
            acked = [a for a in alerts_subset if a.get("ack_time")]
            acked_in_sla = [a for a in acked if a.get("alert_ttd_sec", 0) < 600]
            alert_ttd_sec = [a["alert_ttd_sec"] for a in acked if
                             "alert_ttd_sec" in a and a["alert_ttd_sec"] is not None and a["alert_ttd_sec"] > 0]

            is_total = severity == "total"
            incidents = [a for a in alerts_subset if
                         ((is_total and a.get("inc_severity")) or a.get("inc_severity") == severity) and a.get(
                             "acked_by")]
            incidents_no_fp = [inc for inc in incidents if not inc.get("false_positive_time")]
            incidents_fp = [inc for inc in incidents if inc.get("false_positive_time")]

            jira_incidents = [inc for inc in incidents if (
                        (is_total and inc.get("inc_severity")) or inc.get("inc_severity") == severity) and inc.get(
                "jira_url")]
            confirmed_problems_fixing_times = [inc["inc_ttu_fixing_sec"] for inc in jira_incidents if
                                               inc.get("inc_ttu_fixing_sec") and inc["inc_ttu_fixing_sec"] > 0]
            false_positives_fixing_times = [inc["inc_ttu_false_positive_sec"] for inc in incidents_fp if
                                            inc.get("inc_ttu_false_positive_sec") and inc[
                                                "inc_ttu_false_positive_sec"] > 0]

            stats[severity][acked_by] = {
                "alertsCount": len(alerts_subset),
                "mttd": {
                    "ackCount": len(acked),
                    "ackPercent": round(len(acked) / len(grouped_by_severity[severity]) * 100,
                                        2) if alerts_subset else 0,
                    "ackInSla": round(len(acked_in_sla) / len(acked) * 100, 2) if acked else 0,
                    "perc99": calculate_percentile(alert_ttd_sec, 99),
                    "perc90": calculate_percentile(alert_ttd_sec, 90),
                    "perc75": calculate_percentile(alert_ttd_sec, 75),
                },
                "counts": {
                    "incidents": len(incidents_no_fp),
                    "duplicates": sum(a.get("duplicate_count", 0) for a in incidents_no_fp),
                    "falsePositives": sum(a.get("duplicate_count", 0) + 1 for a in incidents_fp),
                    "flaps": sum(1 for a in alerts_subset if
                                 a.get("alert_ttr_sec") and a.get("acked_by") and a["alert_ttr_sec"] < 300),
                },
                "mttu": {
                    "totalIncidents": len(incidents),
                    "confirmedProblems": len(jira_incidents),
                    "confirmedProblemsMttuPerc75": calculate_percentile(confirmed_problems_fixing_times, 75),
                    "confirmedProblemsMttuPerc90": calculate_percentile(confirmed_problems_fixing_times, 90),
                    "falsePositives": len(incidents_fp),
                    "falsePositivesMttuPerc75": calculate_percentile(false_positives_fixing_times, 75),
                    "falsePositivesMttuPerc90": calculate_percentile(false_positives_fixing_times, 90),
                },
                "mttr": {
                    "totalAlerts": len(alerts_subset),
                    "resolvedAlerts": sum(1 for a in alerts_subset if a.get("resolve_time")),
                    "resolvedPercent": round(
                        sum(1 for a in alerts_subset if a.get("resolve_time")) / len(alerts_subset) * 100,
                        2) if alerts_subset else 0,
                    "resolvedMttrPerc50": calculate_percentile([a["alert_ttr_sec"] for a in alerts_subset if
                                                                a.get("alert_ttr_sec") and a["alert_ttr_sec"] > 0], 50),
                    "resolvedMttrPerc90": calculate_percentile([a["alert_ttr_sec"] for a in alerts_subset if
                                                                a.get("alert_ttr_sec") and a["alert_ttr_sec"] > 0], 90),
                },
            }

    return stats


@api.route('/analytics', methods=['OPTIONS', 'GET'])
@cross_origin()
@permission(Scope.admin)
@timer(gets_analytics)
@jsonp
def get_alerts_analytics():
    from_date = request.args.get('from')
    to_date = request.args.get('to')

    if not from_date and not to_date:
        raise ApiError(f"Missing required fields 'from' and/or 'to'", 400)

    from_date = is_iso_datetime(from_date) if from_date else None
    to_date = is_iso_datetime(to_date) if to_date else None

    if request.args.get('from') and from_date is None:
        raise ApiError(f"Invalid format for 'from'. Expected ISO 8601 datetime string.", 400)

    if request.args.get('to') and to_date is None:
        raise ApiError(f"Invalid format for 'to'. Expected ISO 8601 datetime string.", 400)

    raw_data = db.get_analytics_data(from_date=from_date, to_date=to_date, full=False)

    prepared = prepare_info(raw_data)
    calculated = calculate_stats(prepared)

    return jsonify({
        'status': 'ok',
        'calculated': calculated
    })


@api.route('/analytics/raw', methods=['OPTIONS', 'GET'])
@cross_origin()
@permission(Scope.admin)
@timer(raw_analytics)
@jsonp
def get_alerts_raw_analytics():
    from_date = request.args.get('from')
    to_date = request.args.get('to')

    if not from_date and not to_date:
        raise ApiError(f"Missing required fields 'from' and/or 'to'", 400)

    from_date = is_iso_datetime(from_date) if from_date else None
    to_date = is_iso_datetime(to_date) if to_date else None

    if request.args.get('from') and from_date is None:
        raise ApiError(f"Invalid format for 'from'. Expected ISO 8601 datetime string.", 400)

    if request.args.get('to') and to_date is None:
        raise ApiError(f"Invalid format for 'to'. Expected ISO 8601 datetime string.", 400)

    raw_data = db.get_analytics_data(from_date=from_date, to_date=to_date, full=True)

    prepared = prepare_info(raw_data)

    return jsonify({
        'status': 'ok',
        'raw': prepared
    })
