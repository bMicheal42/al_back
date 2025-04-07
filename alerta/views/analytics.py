import logging
import math
import json

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

severity_values = {
    "medium": 3,
    "high": 4,
    "critical": 5,
}

def format_date(value):
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(value, str) and "T" in value:
        return value[:19].replace("T", " ")
    return value or ""

def format_model(row):
    parent = row.get("parent") or {}

    return {
        "severity": severity_values.get(row.get("severity"), 0),
        # "host_id(url)": f"https://monitoring.sdventures.com/hostinventories.php?filter_field=name&filter_exact=1&filter_field_value={row.get('host', '')}",
        # "host_name": row.get("host") or "",
        # "trigger_id": row.get("zabbix_trigger_id") or "",
        # "trigger_name": row.get("text") or "",
        "acknowledged": 1 if row.get("acked_by") else 0,
        # "day_shift": "",
        # "disaster": "",
        "created_time": format_date(row.get("receive_time")) or "",
        "ackned_time": format_date(row.get("ack_time")) if row.get("ack_time") else "",
        "MTTD": row.get("alert_ttd_sec") or "",
        "acknowledged_user": row.get("acked_by") or "",
        "inc_user": (row.get("acked_by") or "") if row.get("jira_url") else "",
        "inc_time": format_date(row.get("fixing_time")) if row.get("jira_url") and row.get("fixing_time") else "",
        "inc": row.get("jira_url") or "",
        "dupl_user": "" if row.get("incident") else (
            row.get("acked_by") or parent.get("acked_by") if row.get("resolve_time") and parent.get("jira_url") else ""
        ),
        "dupl_time": "" if row.get("incident") else (
            parent.get("fixing_time").strftime("%Y-%m-%d %H:%M:%S") if isinstance(parent.get("fixing_time"), datetime) and row.get("resolve_time") and parent.get("jira_url") else ""
        ),
        "dupl": "" if row.get("incident") else (
            (parent.get("jira_url") or "") if row.get("resolve_time") else ""
        ),
        "false_pos_user": (row.get("acked_by") or "") if row.get("false_positive_time") else "",
        "false_pos_time": format_date(row.get("false_positive_time")) if row.get("false_positive_time") else "" or "",
        "false_pos": 1 if row.get("false_positive_time") else 0,
        "flap_user": (row.get("acked_by") or "") if row.get("alert_ttr_sec", float("inf")) < 300 else "",
        "flap_time": format_date(row.get("resolve_time")) if row.get("resolve_time") else "" or "",
        "flap": 1 if row.get("alert_ttr_sec", float("inf")) < 300 else 0,
        "resolved_time": format_date(row.get("resolve_time")) if row.get("resolve_time") else "" or "",
        "MTTR(sec)": row.get("alert_ttr_sec") if row.get("alert_ttr_sec") else "" or "",
        # "project_group": row.get("project_group") or "",
        # "info_system": row.get("info_system") or "",
        # "event_url": (
        #     f"https://monitoring.sdventures.com/tr_events.php?triggerid={row['zabbix_trigger_id']}&eventid={row['zabbix_id']}"
        #     if row.get("zabbix_trigger_id") and row.get("zabbix_id")
        #     else ""
        # ),
        "MTTU": row.get("inc_ttu_fixing_sec") or row.get("inc_ttu_false_positive_sec") or "",
        "was_incident": row.get("was_incident") or False,
        # "alerta_url": (
        #     f"{location['origin'] or 'http://zabbix.npdev.lan:8081'}/alert/{row['id']}"
        #     if row.get("id")
        #     else ""
        # ),
    }

def transform_raw(raw):
    row_dict = {row["id"]: row for row in raw if "id" in row}

    return [
        format_model({**row, "parent": row_dict.get(row.get("parent_id"), {})})
        for row in raw
    ]

def try_float(value, default=0):
    if value is None or value == "":
        return default
    try:
        return float(value)
    except (ValueError, TypeError):
        return default

def calculate_percentile(values, percentile):
    if not values:
        return 0
    values.sort()
    rank = (percentile / 100) * (len(values) - 1)
    lower_index = math.floor(rank)
    upper_index = math.ceil(rank)

    if lower_index == upper_index:
        return round(values[lower_index] / 60, 2)

    lower_value = values[lower_index]
    upper_value = values[upper_index]
    weight = rank - lower_index

    return round((lower_value + weight * (upper_value - lower_value)) / 60, 2)


def calculate_stats(values):
    stats = {}
    grouped_by_severity = {"total": values, "5": [], "4": [], "3": []}

    for alert in values:
        if str(alert["severity"]) in grouped_by_severity:
            grouped_by_severity[str(alert["severity"])].append(alert)

    for severity, alerts in grouped_by_severity.items():
        grouped_by_acked_by = {"all": alerts}

        for alert in alerts:
            grouping_name = alert.get("acknowledged_user") or alert.get("dupl_user") or alert.get("false_pos_user")
            if grouping_name:
                if grouping_name not in grouped_by_acked_by:
                    grouped_by_acked_by[grouping_name] = []
                grouped_by_acked_by[grouping_name].append(alert)

        stats[severity] = {}

        for acked_by, alerts_subset in grouped_by_acked_by.items():
            # counts
            incidents = [a for a in alerts_subset if a.get("inc")]
            duplicates = [a for a in alerts_subset if a.get("dupl_user")]
            false_poses = [a for a in alerts_subset if a.get("false_pos_user")]
            flaps = [a for a in alerts_subset if a.get("flap_user")]
            wasGrouped = [a for a in alerts_subset if not a.get("was_incident")]
            wasNotGrouped = [a for a in alerts_subset if a.get("was_incident")]

            # mttd
            acked = [a for a in alerts_subset if a.get("ackned_time")]
            acked_in_sla = [a for a in acked if try_float(a.get("MTTD")) < 600 and a.get("acknowledged_user")]
            alert_ttd_sec = [try_float(a["MTTD"]) for a in acked if a.get("acknowledged_user") and a.get("MTTD") is not None and a["MTTD"] != "" and try_float(a["MTTD"]) > 0]

            # mttu
            confirmed_problems_fixing_times = [try_float(inc["MTTU"]) for inc in incidents if inc.get("MTTU") is not None and inc["MTTU"] != "" and try_float(inc["MTTU"]) > 0]
            false_positives_fixing_times = [try_float(inc["MTTU"]) for inc in false_poses if inc.get("MTTU") is not None and inc["MTTU"] != "" and try_float(inc["MTTU"]) > 0]

            # mttr
            mttr_times = [try_float(a["MTTR(sec)"]) for a in alerts_subset if a.get("MTTR(sec)") is not None and a["MTTR(sec)"] != "" and try_float(a["MTTR(sec)"]) > 0]

            stats[severity][acked_by] = {
                "alertsCount": len(alerts_subset),
                "counts": {
                    "incidents": len(incidents) or 0,
                    "duplicates": len(duplicates) or 0,
                    "falsePositives": len(false_poses) or 0,
                    "flaps": len(flaps) or 0,
                    "wasGrouped": len(wasGrouped) or 0,
                    "wasNotGrouped": len(wasNotGrouped) or 0,
                },
                "mttd": {
                    "ackCount": len(acked),
                    "ackPercent": round(len(acked) / len(grouped_by_severity[severity]) * 100, 2) if alerts_subset else 0,
                    "ackInSla": round(len(acked_in_sla) / len(acked) * 100, 2) if acked else 0,
                    "perc99": calculate_percentile(alert_ttd_sec, 99),
                    "perc90": calculate_percentile(alert_ttd_sec, 90),
                    "perc75": calculate_percentile(alert_ttd_sec, 75),
                },
                "mttu": {
                    "confirmedProblems": len(incidents),
                    "confirmedProblemsMttuPerc75": calculate_percentile(confirmed_problems_fixing_times, 75),
                    "confirmedProblemsMttuPerc90": calculate_percentile(confirmed_problems_fixing_times, 90),
                    "falsePositives": len(false_poses),
                    "falsePositivesMttuPerc75": calculate_percentile(false_positives_fixing_times, 75),
                    "falsePositivesMttuPerc90": calculate_percentile(false_positives_fixing_times, 90),
                },
                "mttr": {
                    "totalAlerts": len(alerts_subset),
                    "resolvedAlerts": sum(1 for a in alerts_subset if a.get("resolved_time")),
                    "resolvedPercent": round(sum(1 for a in alerts_subset if a.get("resolved_time")) / len(alerts_subset) * 100, 2) if alerts_subset else 0,
                    "resolvedMttrPerc50": calculate_percentile(mttr_times, 50),
                    "resolvedMttrPerc90": calculate_percentile(mttr_times, 90),
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

    raw_data = prepare_info(db.get_analytics_data(from_date=from_date, to_date=to_date, full=False))

    calc_models = transform_raw(raw_data)
    calculated = calculate_stats(calc_models)

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
