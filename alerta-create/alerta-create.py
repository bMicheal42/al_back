import argparse
import json
import requests
import time

# для локальной разработки используется
ALERTA_API_URL = 'http://localhost:8080/alert'
# ключ, который нужно сгенерировать командой alerta key
API_KEY = 'GAEIHRdty0jrIf5UKzwcogICOGJLy_ES_cVgQIuZ_'

info = """
This script is used to send alerts to Alerta, either one at a time using command-line
arguments or multiple alerts from a JSON configuration file.

Examples:
   1. Send a single "PROBLEM" alert (default):
      python alerta-create.py -host my-host -pg my-project-group -sys my-system -ip 192.168.1.10 -id 987654321 -owner1 cp-admins -owner2 cp-sre
   2. Resolve with "OK" alert (you must provide the same attributes.zabbix_id with -id):
      python alerta-create.py -id 987654321 -ok
   3. Send a "PROBLEM" alert with high severity:
      python alerta-create.py -host my-host -high -id 987654500
   4. Send a "PROBLEM" alert with critical severity:
      python alerta-create.py -host my-host -crit-id 987654600
   5. Send mass for trig name cosinus and host pattern
     python alerta-create.py -f triggerNameAndHost_PROBLEM.json
     python alerta-create.py -f triggerNameAndHost_OK.json
   6. Send mass for host pattern
     python alerta-create.py -f host_PROBLEM.json
     python alerta-create.py -f host_OK.json
   7. Send mass for trig name cosinus and host
     python alerta-create.py -f projectGroupAndInfoSystem_PROBLEM.json
     python alerta-create.py -f projectGroupAndInfoSystem_OK.json
"""

HEADERS = {
    'Content-Type': 'application/json',
    'Authorization': f'Key {API_KEY}'
}


def send_alert(payload):
    response = requests.post(ALERTA_API_URL, json=payload, headers=HEADERS)
    if response.status_code == 201:
        parsed = json.loads(response.text)
        alert = parsed.get('alert', {})
        id = alert.get('id', '<NO ID>')
        host = alert.get('event', '<NO HOST>')
        summary = alert.get('text', '<NO TEXT>')
        tags = alert.get('tags', [])
        sys = next(tag.split(':')[1] for tag in tags if tag.startswith('InfoSystem:')) or '<NO SYS>'
        pg = next(tag.split(':')[1] for tag in tags if tag.startswith('ProjectGroup:')) or '<NO PG>'
        print(f'✅ Alert created: {id}, InfoSystem: {sys}, ProjectGroup: {pg}, host: {host}, summary: {summary}')
        return True
    else:
        print(f'❌ Failed to process alert: {response.text}')
        return False


def load_alerts_from_json(json_file):
    try:
        with open(json_file, 'r') as f:
            alerts = json.load(f)
        return alerts
    except FileNotFoundError:
        print(f"❌ Error: JSON file '{json_file}' not found.")
        return None
    except json.JSONDecodeError:
        print(f"❌ Error: Invalid JSON format in '{json_file}'.")
        return None


def main():
    parser = argparse.ArgumentParser(description=info, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-host', default='TST-HOST-226', help='Hostname of the alert')
    parser.add_argument('-vhost', default='TST-V-HOST-226', help='Visible Hostname of the alert')
    parser.add_argument('-owner1', default='hosting-admin-team', help='Owner_1 of the alert')
    parser.add_argument('-owner2', help='Owner_2 of the alert')
    parser.add_argument('-pg', default='INFRA', help='ProjectGroup name')
    parser.add_argument('-sys', default='Virtualization', help='InfoSystem name')
    parser.add_argument('-t', '--text', default='Host is not available (by ICMP and Zabbix-agent)',
                        help='Alert summary (text)')
    parser.add_argument('-hw', help='Hardware identifier')
    parser.add_argument('-ip', default='10.6.130.13', help='IP address')
    parser.add_argument('-id', default='11658361', help='Zabbix ID')
    parser.add_argument('-ok', action='store_true', help='Send a OK alert instead of PROBLEM')
    parser.add_argument('-high', action='store_true', help='Send a alert with high severity')
    parser.add_argument('-crit', action='store_true', help='Send a alert with critical severity')
    parser.add_argument('-f', '--file', help='Path to JSON file with alerts.')
    args = parser.parse_args()

    if args.file:
        alerts = load_alerts_from_json(args.file)
        if alerts:
            for alert in alerts:
                send_alert(alert)
                time.sleep(1)
    else:
        zabbix_status = 'OK' if args.ok else 'PROBLEM'
        value = '50 %' if args.ok else '89.5 %'

        tags = [
            f"InfoSystem:{args.sys}",
            f"ProjectGroup:{args.pg}",
            'class:os'
        ]
        if args.owner1:
            tags.append(f"Owner_1:{args.owner1}")
        if args.owner2:
            tags.append(f"Owner_2:{args.owner2}")
        if args.hw:
            tags.append(f"Hardware:{args.hw}")
        if zabbix_status == 'OK':
            tags.append('__channel_id_#zabbix-etalon:C07BL15084V')
            tags.append(
                '__message_link_#zabbix-etalon:https://datinggrp.slack.com/archives/C07BL15084V/p1740482954517469')
            tags.append('__message_ts_#zabbix-etalon:1740482954.517469')

        severity = 'medium'
        if args.high:
            severity = 'high'
        if args.crit:
            severity = 'critical'

        ZABBIX_SEVERITY_BACKWARD_MAPPING = {
            'medium': 'Средняя',
            'high': 'Высокая',
            'critical': 'Критическая'
        }

        payload = {
            "resource": "icmpping",
            "event": args.host,
            "environment": "Production",
            "severity": severity,
            "correlate": [],
            "service": [
                "F1-ITI-HOST",
                " f1-zbx-prx2",
                " Facility - F1",
                " !Hyper-V servers",
                " Hyper-V servers hosting",
                " Insight - ИС - Виртуализация",
                " intel-8280",
                " Netbox - Гипервизоры",
                " Stafford (CP-F1)",
                " !Windows servers",
                " !Авторегистрация агентов",
                " !Группа проектов - CP",
                " Группа проектов - CP",
                " ИС - Виртуализация",
                " !Площадка - F1",
                " Площадка - F1",
                " Получатели: Дежурная смена"
            ],
            "group": "Zabbix",
            "value": value,
            "text": args.text,
            "tags": tags,
            "attributes": {
                "ip": args.ip,
                "thresholdInfo": "Hyper-V NEW: max(/F1-HOST-226/icmpping,#3)=0 and max(/F1-HOST-226/zabbix[host,agent,available],{$AGENT.TIMEOUT})=0",
                "zabbix_id": args.id,
                "zabbix_status": zabbix_status,
                "zabbix_severity": ZABBIX_SEVERITY_BACKWARD_MAPPING[severity],
                "zabbix_visible_hostname": "F1-HOST-226",
                "zabbix_description": "1 <!subteam^S06MQ7M2SPR> https://knowledge.sdventures.com/display/HITI/Hyper-V+Monitoring+Instructions",
                "zabbix_trigger_id": "123123"
            },
            "origin": "zabbix/co-zbbx-srv",
            "type": "zabbixAlert",
            # "createTime": "2025-02-26T18:49:36.471Z",
        }
        send_alert(payload)


if __name__ == '__main__':
    main()
