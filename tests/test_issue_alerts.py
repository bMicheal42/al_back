import unittest
import json
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
import copy

from flask import Flask, g

from alerta.models.issue import Issue, create_new_issue_for_alert
from alerta.models.alert import Alert


class TestIssueAlerts(unittest.TestCase):
    """Тесты для проверки функциональности связывания алертов с Issue"""
    
    def setUp(self):
        # Создаем тестовое Flask-приложение
        self.app = Flask(__name__)
        self.app.config['TESTING'] = True
        self.app.config['ALERT_TIMEOUT'] = 86400  # 24 часа в секундах
        self.app.config['PLUGINS'] = []
        self.app.config['CUSTOMER_VIEWS'] = False
        self.app_context = self.app.app_context()
        self.app_context.push()
        
        # Имитируем g.login для функций, которые его используют
        g.login = 'test-user'
        
        # Тестовые данные для алертов
        self.alert_data_medium = {
            "id": "alert1",
            "resource": "icmpping", 
            "event": "TST-WEBC-300", 
            "environment": "Production", 
            "severity": "medium", 
            "group": "Zabbix", 
            "value": "Down (0)",
            "service": ["Critical/Done", "f1-zbx-prx2"],
            "text": "Connectivity to host TST-WEBC-300 cannot be established",
            "tags": [
                "Application:Status",
                "Hardware:F2-HOST-322",
                "InfoSystem:INFRA",
                "Owner_1:af-admins",
                "ProjectGroup:AF"
            ],
            "attributes": {
                "ip": "10.9.15.10",
                "host_critical": "0",
                "zabbix_severity": "Средняя"
            },
            "create_time": datetime.now(),  # Используем datetime.now() вместо utcnow()
            "origin": "zabbix/co-zbbx-tst",
            "type": "zabbixAlert"
        }
        
        self.alert_data_high = {
            "id": "alert2",
            "resource": "icmpping", 
            "event": "TST-WEBC-301", 
            "environment": "Production", 
            "severity": "high", 
            "group": "Zabbix", 
            "value": "Down (0)",
            "service": ["Critical/Done", "f1-zbx-prx2"],
            "text": "Host TST-WEBC-301 is currently unresponsive",
            "tags": [
                "Application:Status",
                "Hardware:F2-HOST-323",
                "InfoSystem:INFRA",
                "InfoSystem:EXTRA",
                "Owner_1:AF-admins",
                "ProjectGroup:AF"
            ],
            "attributes": {
                "ip": "10.9.14.16",
                "host_critical": "1",
                "zabbix_severity": "Высокая"
            },
            "create_time": datetime.now(),
            "origin": "zabbix/co-zbbx-tst",
            "type": "zabbixAlert"
        }
        
        self.alert_data_critical = {
            "id": "alert3",
            "resource": "icmpping", 
            "event": "TST-WEBC-302", 
            "environment": "Production", 
            "severity": "critical", 
            "group": "Zabbix", 
            "value": "Down (0)",
            "service": ["Critical/Done", "f1-zbx-prx2"],
            "text": "Host TST-WEBC-302 is down",
            "tags": [
                "Application:Status",
                "Hardware:F2-HOST-324",
                "InfoSystem:PRODUCTION",
                "Owner_1:AF-admins",
                "ProjectGroup:MAIN",
                "ProjectGroup:AF"
            ],
            "attributes": {
                "ip": "10.9.14.18",
                "host_critical": "1",
                "zabbix_severity": "Критическая"
            },
            "create_time": datetime.now(),
            "origin": "zabbix/co-zbbx-tst",
            "type": "zabbixAlert"
        }
    
    def tearDown(self):
        # Удаляем контекст приложения после каждого теста
        self.app_context.pop()
        
    @patch('alerta.models.issue.db')
    def test_create_issue_from_alert(self, mock_db):
        """Тест создания Issue из алерта"""
        # Мокаем функцию create_issue базы данных
        mock_db.create_issue.return_value = {
            "id": "issue1",
            "summary": "Connectivity to host TST-WEBC-300 cannot be established",
            "severity": "medium",
            "host_critical": "0",
            "alerts": ["alert1"],
            "hosts": ["TST-WEBC-300"],
            "project_groups": ["AF"],
            "info_systems": ["INFRA"]
        }
        
        # Создаем объект Alert из данных
        alert = Alert.parse(self.alert_data_medium)
        
        # Мокаем функцию link_to_issue
        with patch.object(Alert, 'link_to_issue', return_value=alert):
            # Создаем Issue из алерта
            result = create_new_issue_for_alert(alert)
            
            # Проверяем, что функция create_issue была вызвана
            mock_db.create_issue.assert_called_once()
            
            # Проверяем параметры, переданные в вызове функции
            issue = mock_db.create_issue.call_args[0][0]
            self.assertEqual(issue.summary, "Connectivity to host TST-WEBC-300 cannot be established")
            self.assertEqual(issue.severity, "medium")
            self.assertEqual(issue.host_critical, "0")
            self.assertEqual(issue.alerts, ["alert1"])
            self.assertEqual(issue.hosts, ["TST-WEBC-300"])
            self.assertEqual(issue.project_groups, ["AF"])
            self.assertEqual(issue.info_systems, ["INFRA"])
    
    @patch('alerta.models.issue.db')
    def test_add_alert_to_issue(self, mock_db):
        """Тест добавления алерта к Issue и проверка обновления полей"""
        # Создаем Issue с начальными данными
        issue = Issue(
            summary="Initial Issue",
            id="issue1",
            severity="medium",
            host_critical="0",
            alerts=["alert1"],
            hosts=["TST-WEBC-300"],
            project_groups=["AF"],
            info_systems=["INFRA"]
        )
        
        # Мокаем функцию update_issue базы данных
        mock_db.update_issue.return_value = {
            "id": "issue1",
            "summary": "Initial Issue",
            "severity": "high",
            "host_critical": "1",
            "alerts": ["alert1", "alert2"],
            "hosts": ["TST-WEBC-300", "TST-WEBC-301"],
            "project_groups": ["AF"],
            "info_systems": ["INFRA", "EXTRA"],
            "last_alert_time": self.alert_data_high["create_time"]
        }
        
        # Создаем объект Alert из данных
        alert = Alert.parse(self.alert_data_high)
        
        # Добавляем алерт к Issue
        updated_issue = issue.add_alert(alert)
        
        # Проверяем, что функция update_issue была вызвана
        mock_db.update_issue.assert_called_once()
        
        # Проверяем обновленные поля
        self.assertEqual(updated_issue.severity, "high")  # Severity должен быть обновлен на более высокий
        self.assertEqual(updated_issue.host_critical, "1")  # host_critical должен быть обновлен
        self.assertEqual(len(updated_issue.alerts), 2)  # Должно быть 2 алерта
        self.assertIn("alert2", updated_issue.alerts)  # Новый алерт должен быть добавлен
        self.assertEqual(len(updated_issue.hosts), 2)  # Должно быть 2 хоста
        self.assertIn("TST-WEBC-301", updated_issue.hosts)  # Новый хост должен быть добавлен
        self.assertEqual(len(updated_issue.info_systems), 2)  # Должно быть 2 информационные системы
        self.assertIn("EXTRA", updated_issue.info_systems)  # Новая система должна быть добавлена
        self.assertEqual(updated_issue.last_alert_time, self.alert_data_high["create_time"])  # last_alert_time должен быть обновлен
    
    @patch('alerta.models.issue.db')
    def test_remove_alert_from_issue(self, mock_db):
        """Тест удаления алерта из Issue и проверка обновления полей"""
        # Создаем Issue с несколькими алертами
        issue = Issue(
            summary="Issue with multiple alerts",
            id="issue1",
            severity="critical",
            host_critical="1",
            alerts=["alert1", "alert2", "alert3"],
            hosts=["TST-WEBC-300", "TST-WEBC-301", "TST-WEBC-302"],
            project_groups=["AF", "MAIN"],
            info_systems=["INFRA", "EXTRA", "PRODUCTION"],
            last_alert_time=self.alert_data_critical["create_time"]
        )
        
        # Мокаем Alert.find_by_ids для возврата объектов Alert
        with patch('alerta.models.alert.Alert.find_by_ids') as mock_find_by_ids:
            # Создаем объекты Alert из данных
            alert1 = Alert.parse(self.alert_data_medium)
            alert3 = Alert.parse(self.alert_data_critical)
            mock_find_by_ids.return_value = [alert1, alert3]
            
            # Мокаем функцию update_issue базы данных
            mock_db.update_issue.return_value = {
                "id": "issue1",
                "summary": "Issue with multiple alerts",
                "severity": "critical",  # Остается критическим из-за alert3
                "host_critical": "1",    # Остается 1 из-за alert3
                "alerts": ["alert1", "alert3"],
                "hosts": ["TST-WEBC-300", "TST-WEBC-302"],
                "project_groups": ["AF", "MAIN"],
                "info_systems": ["INFRA", "PRODUCTION"],
                "last_alert_time": self.alert_data_critical["create_time"]
            }
            
            # Удаляем alert2 из Issue
            updated_issue = issue.remove_alert("alert2")
            
            # Проверяем, что функция update_issue была вызвана
            mock_db.update_issue.assert_called_once()
            
            # Проверяем обновленные поля
            self.assertEqual(updated_issue.severity, "critical")  # Severity остается критическим
            self.assertEqual(updated_issue.host_critical, "1")  # host_critical остается 1
            self.assertEqual(len(updated_issue.alerts), 2)  # Должно быть 2 алерта
            self.assertNotIn("alert2", updated_issue.alerts)  # Удаленный алерт должен отсутствовать
            self.assertEqual(len(updated_issue.hosts), 2)  # Должно быть 2 хоста
            self.assertNotIn("TST-WEBC-301", updated_issue.hosts)  # Хост алерта2 должен быть удален
            self.assertEqual(len(updated_issue.info_systems), 2)  # Должно быть 2 информационные системы
            self.assertNotIn("EXTRA", updated_issue.info_systems)  # Система из алерта2 должна быть удалена
    
    @patch('alerta.models.issue.db')
    def test_mass_add_alerts_to_issue(self, mock_db):
        """Тест массового добавления алертов в Issue"""
        # Создаем Issue с начальными данными
        issue = Issue(
            summary="Initial Issue",
            id="issue1",
            severity="medium",
            host_critical="0",
            alerts=[],
            hosts=[],
            project_groups=[],
            info_systems=[]
        )
        
        # Мокаем функцию update_issue базы данных
        mock_db.update_issue.return_value = {
            "id": "issue1",
            "summary": "Initial Issue",
            "severity": "critical",
            "host_critical": "1",
            "alerts": ["alert1", "alert2", "alert3"],
            "hosts": ["TST-WEBC-300", "TST-WEBC-301", "TST-WEBC-302"],
            "project_groups": ["AF", "MAIN"],
            "info_systems": ["INFRA", "EXTRA", "PRODUCTION"],
            "last_alert_time": self.alert_data_critical["create_time"]
        }
        
        # Создаем объекты Alert из данных
        alert1 = Alert.parse(self.alert_data_medium)
        alert2 = Alert.parse(self.alert_data_high)
        alert3 = Alert.parse(self.alert_data_critical)
        
        # Массово добавляем алерты к Issue
        updated_issue = issue.mass_add_alerts([alert1, alert2, alert3])
        
        # Проверяем, что функция update_issue была вызвана
        mock_db.update_issue.assert_called_once()
        
        # Проверяем обновленные поля
        self.assertEqual(updated_issue.severity, "critical")  # Severity должен быть наивысшим из всех алертов
        self.assertEqual(updated_issue.host_critical, "1")  # host_critical должен быть 1
        self.assertEqual(len(updated_issue.alerts), 3)  # Должно быть 3 алерта
        self.assertEqual(len(updated_issue.hosts), 3)  # Должно быть 3 хоста
        self.assertEqual(len(updated_issue.project_groups), 2)  # Должно быть 2 группы проектов
        self.assertEqual(len(updated_issue.info_systems), 3)  # Должно быть 3 информационные системы
        self.assertEqual(updated_issue.last_alert_time, self.alert_data_critical["create_time"])  # last_alert_time должен быть из самого нового алерта
    
    @patch('alerta.models.issue.db')
    def test_mass_remove_alerts_from_issue(self, mock_db):
        """Тест массового удаления алертов из Issue"""
        # Создаем Issue с несколькими алертами
        issue = Issue(
            summary="Issue with multiple alerts",
            id="issue1",
            severity="critical",
            host_critical="1",
            alerts=["alert1", "alert2", "alert3"],
            hosts=["TST-WEBC-300", "TST-WEBC-301", "TST-WEBC-302"],
            project_groups=["AF", "MAIN"],
            info_systems=["INFRA", "EXTRA", "PRODUCTION"],
            last_alert_time=self.alert_data_critical["create_time"]
        )
        
        # Мокаем Alert.find_by_ids для возврата объектов Alert
        with patch('alerta.models.alert.Alert.find_by_ids') as mock_find_by_ids:
            # Оставляем только alert1
            alert1 = Alert.parse(self.alert_data_medium)
            mock_find_by_ids.return_value = [alert1]
            
            # Мокаем функцию update_issue базы данных
            mock_db.update_issue.return_value = {
                "id": "issue1",
                "summary": "Issue with multiple alerts",
                "severity": "medium",
                "host_critical": "0",
                "alerts": ["alert1"],
                "hosts": ["TST-WEBC-300"],
                "project_groups": ["AF"],
                "info_systems": ["INFRA"],
                "last_alert_time": self.alert_data_medium["create_time"]
            }
            
            # Удаляем alert2 и alert3 из Issue
            updated_issue = issue.mass_remove_alerts(["alert2", "alert3"])
            
            # Проверяем, что функция update_issue была вызвана
            mock_db.update_issue.assert_called_once()
            
            # Проверяем обновленные поля
            self.assertEqual(updated_issue.severity, "medium")  # Severity должен быть medium из оставшегося алерта
            self.assertEqual(updated_issue.host_critical, "0")  # host_critical должен быть 0
            self.assertEqual(len(updated_issue.alerts), 1)  # Должен остаться 1 алерт
            self.assertEqual(updated_issue.alerts[0], "alert1")  # Должен остаться только alert1
            self.assertEqual(len(updated_issue.hosts), 1)  # Должен остаться 1 хост
            self.assertEqual(updated_issue.hosts[0], "TST-WEBC-300")  # Должен остаться только хост из alert1
            self.assertEqual(len(updated_issue.project_groups), 1)  # Должна остаться 1 группа проектов
            self.assertEqual(updated_issue.project_groups[0], "AF")  # Должна остаться только группа из alert1
            self.assertEqual(len(updated_issue.info_systems), 1)  # Должна остаться 1 информационная система
            self.assertEqual(updated_issue.info_systems[0], "INFRA")  # Должна остаться только система из alert1
    
    @patch('alerta.models.issue.db')
    def test_remove_all_alerts_from_issue(self, mock_db):
        """Тест удаления всех алертов из Issue (Issue должен быть закрыт)"""
        # Создаем Issue с несколькими алертами
        issue = Issue(
            summary="Issue with multiple alerts",
            id="issue1",
            severity="critical",
            host_critical="1",
            alerts=["alert1", "alert2", "alert3"],
            hosts=["TST-WEBC-300", "TST-WEBC-301", "TST-WEBC-302"],
            project_groups=["AF", "MAIN"],
            info_systems=["INFRA", "EXTRA", "PRODUCTION"],
            status="open"
        )
        
        # Мокаем Alert.find_by_ids для возврата пустого списка (все алерты удалены)
        with patch('alerta.models.alert.Alert.find_by_ids') as mock_find_by_ids:
            mock_find_by_ids.return_value = []
            
            # Мокаем функцию update_issue базы данных
            mock_db.update_issue.return_value = {
                "id": "issue1",
                "summary": "Issue with multiple alerts",
                "severity": "critical",  # Severity остается тем же
                "host_critical": "1",    # host_critical остается тем же
                "alerts": [],            # Нет алертов
                "hosts": [],             # Нет хостов
                "project_groups": [],    # Нет групп проектов
                "info_systems": [],      # Нет информационных систем
                "status": "closed",      # Issue закрыт
                "resolve_time": datetime.utcnow()  # Время разрешения установлено
            }
            
            # Удаляем все алерты из Issue
            updated_issue = issue.mass_remove_alerts(["alert1", "alert2", "alert3"])
            
            # Проверяем, что функция update_issue была вызвана
            mock_db.update_issue.assert_called_once()
            
            # Проверяем обновленные поля
            self.assertEqual(updated_issue.status, "closed")  # Issue должен быть закрыт
            self.assertIsNotNone(updated_issue.resolve_time)  # Время разрешения должно быть установлено
            self.assertEqual(len(updated_issue.alerts), 0)  # Не должно быть алертов
            self.assertEqual(len(updated_issue.hosts), 0)  # Не должно быть хостов
            self.assertEqual(len(updated_issue.project_groups), 0)  # Не должно быть групп проектов
            self.assertEqual(len(updated_issue.info_systems), 0)  # Не должно быть информационных систем

    @patch('alerta.models.issue.db')
    @patch('alerta.models.alert.Alert.find_by_id')
    @patch('alerta.models.issue.Issue.find_by_id')
    def test_cannot_unlink_last_alert_from_issue(self, mock_find_issue, mock_find_alert, mock_db):
        """Тест на невозможность отвязать последний алерт от Issue"""
        # Создаем Issue с одним алертом
        issue = Issue(
            summary="Issue with one alert",
            id="issue1",
            severity="medium",
            host_critical="0",
            alerts=["alert1"],
            hosts=["TST-WEBC-300"],
            project_groups=["AF"],
            info_systems=["INFRA"],
            status="open"
        )
        
        # Мокаем Alert.find_by_id для возврата объекта Alert
        alert = Alert.parse(self.alert_data_medium)
        alert.id = "alert1"
        alert.issue_id = "issue1"
        
        mock_find_alert.return_value = alert
        mock_find_issue.return_value = issue
        
        # Пытаемся отвязать единственный алерт от Issue
        with self.assertRaises(ValueError) as context:
            alert.unlink_from_issue()
        
        # Проверяем сообщение об ошибке
        self.assertIn("Невозможно отвязать последний алерт от issue", str(context.exception))

    @patch('alerta.models.issue.db')
    def test_unique_arrays_update(self, mock_db):
        """Тест обновления уникальных массивов hosts, project_groups и info_systems при добавлении и удалении алертов"""
        # Создаем Issue с пустыми массивами
        issue = Issue(
            summary="Unique Arrays Test",
            id="issue1",
            severity="medium",
            host_critical="0",
            alerts=[],
            hosts=[],
            project_groups=[],
            info_systems=[]
        )
        
        # Создаем алерты с разными данными
        alert1 = Alert.parse(self.alert_data_medium)
        alert1.id = "alert1"
        
        alert2 = Alert.parse(self.alert_data_high)
        alert2.id = "alert2"
        
        alert3 = copy.deepcopy(alert2)
        alert3.id = "alert3"
        alert3.event = "TST-WEBC-301" # тот же хост что и у alert2
        # Добавим новый тег для info_system
        alert3.tags.append("InfoSystem:NEW-SYSTEM")
        
        # Мок ответа БД для первого добавления алерта
        mock_db.update_issue.return_value = {
            "id": "issue1",
            "summary": "Unique Arrays Test",
            "severity": "medium",
            "host_critical": "0",
            "alerts": ["alert1"],
            "hosts": ["TST-WEBC-300"],
            "project_groups": ["AF"],
            "info_systems": ["INFRA"],
            "last_alert_time": self.alert_data_medium["create_time"]
        }
        
        # Добавляем первый алерт и проверяем массивы
        updated_issue = issue.add_alert(alert1)
        self.assertEqual(updated_issue.hosts, ["TST-WEBC-300"])
        self.assertEqual(updated_issue.project_groups, ["AF"])
        self.assertEqual(updated_issue.info_systems, ["INFRA"])
        
        # Мок ответа БД для второго добавления алерта
        mock_db.update_issue.return_value = {
            "id": "issue1",
            "summary": "Unique Arrays Test",
            "severity": "high",
            "host_critical": "1",
            "alerts": ["alert1", "alert2"],
            "hosts": ["TST-WEBC-300", "TST-WEBC-301"],
            "project_groups": ["AF"],
            "info_systems": ["INFRA", "EXTRA"],
            "last_alert_time": self.alert_data_high["create_time"]
        }
        
        # Добавляем второй алерт и проверяем, что массивы обновились правильно
        updated_issue = issue.add_alert(alert2)
        self.assertEqual(updated_issue.hosts, ["TST-WEBC-300", "TST-WEBC-301"])
        self.assertEqual(updated_issue.project_groups, ["AF"])
        self.assertEqual(updated_issue.info_systems, ["INFRA", "EXTRA"])
        
        # Мок ответа БД для третьего добавления алерта
        mock_db.update_issue.return_value = {
            "id": "issue1",
            "summary": "Unique Arrays Test",
            "severity": "high",
            "host_critical": "1",
            "alerts": ["alert1", "alert2", "alert3"],
            "hosts": ["TST-WEBC-300", "TST-WEBC-301"],
            "project_groups": ["AF"],
            "info_systems": ["INFRA", "EXTRA", "NEW-SYSTEM"],
            "last_alert_time": self.alert_data_high["create_time"]
        }
        
        # Добавляем третий алерт с тем же хостом и проверяем, что дублирования нет
        updated_issue = issue.add_alert(alert3)
        self.assertEqual(updated_issue.hosts, ["TST-WEBC-300", "TST-WEBC-301"])
        self.assertEqual(updated_issue.project_groups, ["AF"])
        self.assertEqual(updated_issue.info_systems, ["INFRA", "EXTRA", "NEW-SYSTEM"])
        
        # Мок ответа БД при удалении второго алерта
        with patch('alerta.models.alert.Alert.find_by_ids') as mock_find_by_ids:
            # Возвращаем оставшиеся алерты
            mock_find_by_ids.return_value = [alert1, alert3]
            
            mock_db.update_issue.return_value = {
                "id": "issue1",
                "summary": "Unique Arrays Test",
                "severity": "medium",
                "host_critical": "0",
                "alerts": ["alert1", "alert3"],
                "hosts": ["TST-WEBC-300", "TST-WEBC-301"],
                "project_groups": ["AF"],
                "info_systems": ["INFRA", "EXTRA", "NEW-SYSTEM"],
                "last_alert_time": self.alert_data_medium["create_time"]
            }
            
            # Удаляем alert2 и проверяем, что TST-WEBC-301 остался в массиве (т.к. используется в alert3)
            updated_issue = issue.mass_remove_alerts(["alert2"])
            self.assertEqual(updated_issue.hosts, ["TST-WEBC-300", "TST-WEBC-301"])
            self.assertEqual(updated_issue.project_groups, ["AF"])
            self.assertEqual(updated_issue.info_systems, ["INFRA", "EXTRA", "NEW-SYSTEM"])
            
        # Мок ответа БД при удалении третьего алерта
        with patch('alerta.models.alert.Alert.find_by_ids') as mock_find_by_ids:
            # Возвращаем только первый алерт
            mock_find_by_ids.return_value = [alert1]
            
            mock_db.update_issue.return_value = {
                "id": "issue1",
                "summary": "Unique Arrays Test",
                "severity": "medium",
                "host_critical": "0",
                "alerts": ["alert1"],
                "hosts": ["TST-WEBC-300"],
                "project_groups": ["AF"],
                "info_systems": ["INFRA"],
                "last_alert_time": self.alert_data_medium["create_time"]
            }
            
            # Удаляем alert3 и проверяем, что TST-WEBC-301 исчез из массива
            updated_issue = issue.mass_remove_alerts(["alert3"])
            self.assertEqual(updated_issue.hosts, ["TST-WEBC-300"])
            self.assertEqual(updated_issue.project_groups, ["AF"])
            self.assertEqual(updated_issue.info_systems, ["INFRA"])
            
        # Мок ответа БД при удалении последнего алерта
        with patch('alerta.models.alert.Alert.find_by_ids') as mock_find_by_ids:
            # Пустой список алертов
            mock_find_by_ids.return_value = []
            
            mock_db.update_issue.return_value = {
                "id": "issue1",
                "summary": "Unique Arrays Test",
                "severity": "normal",
                "host_critical": "0",
                "alerts": [],
                "hosts": [],
                "project_groups": [],
                "info_systems": [],
                "last_alert_time": None,
                "status": "closed"
            }
            
            # Удаляем alert1 (последний) и проверяем, что массивы пустые
            updated_issue = issue.mass_remove_alerts(["alert1"])
            self.assertEqual(updated_issue.hosts, [])
            self.assertEqual(updated_issue.project_groups, [])
            self.assertEqual(updated_issue.info_systems, [])
            self.assertEqual(updated_issue.status, "closed")

    @patch('alerta.models.issue.db')
    def test_severity_changes_with_alerts(self, mock_db):
        """Тест изменения severity при добавлении и удалении алертов с разной степенью важности"""
        # Создаем Issue с начальным severity=normal
        issue = Issue(
            summary="Severity Test Issue",
            id="issue1",
            severity="normal",  # Начальная severity
            host_critical="0",
            alerts=[],
            hosts=[],
            project_groups=[],
            info_systems=[]
        )
        
        # Создаем алерты с разными уровнями severity
        alert_minor = Alert.parse(self.alert_data_medium)
        alert_minor.id = "alert_minor"
        alert_minor.severity = "minor"
        
        alert_medium = Alert.parse(self.alert_data_medium)
        alert_medium.id = "alert_medium"
        
        alert_high = Alert.parse(self.alert_data_high)
        alert_high.id = "alert_high"
        
        alert_critical = Alert.parse(self.alert_data_critical)
        alert_critical.id = "alert_critical"
        
        # Мок ответа БД для добавления alert_minor
        mock_db.update_issue.return_value = {
            "id": "issue1",
            "summary": "Severity Test Issue",
            "severity": "minor",
            "alerts": ["alert_minor"],
            "host_critical": "0"
        }
        
        # Добавляем алерт с minor severity
        updated_issue = issue.add_alert(alert_minor)
        self.assertEqual(updated_issue.severity, "minor")
        
        # Мок ответа БД для добавления alert_medium
        mock_db.update_issue.return_value = {
            "id": "issue1",
            "summary": "Severity Test Issue",
            "severity": "medium",
            "alerts": ["alert_minor", "alert_medium"],
            "host_critical": "0"
        }
        
        # Добавляем алерт с medium severity
        updated_issue = issue.add_alert(alert_medium)
        self.assertEqual(updated_issue.severity, "medium")
        
        # Мок ответа БД для добавления alert_high
        mock_db.update_issue.return_value = {
            "id": "issue1",
            "summary": "Severity Test Issue",
            "severity": "high",
            "alerts": ["alert_minor", "alert_medium", "alert_high"],
            "host_critical": "0"
        }
        
        # Добавляем алерт с high severity
        updated_issue = issue.add_alert(alert_high)
        self.assertEqual(updated_issue.severity, "high")
        
        # Мок ответа БД для добавления alert_critical
        mock_db.update_issue.return_value = {
            "id": "issue1",
            "summary": "Severity Test Issue",
            "severity": "critical",
            "alerts": ["alert_minor", "alert_medium", "alert_high", "alert_critical"],
            "host_critical": "0"
        }
        
        # Добавляем алерт с critical severity
        updated_issue = issue.add_alert(alert_critical)
        self.assertEqual(updated_issue.severity, "critical")
        
        # Теперь проверяем понижение severity при удалении алертов
        with patch('alerta.models.alert.Alert.find_by_ids') as mock_find_by_ids:
            # При удалении критического алерта должны остаться алерты с severity до high
            mock_find_by_ids.return_value = [alert_minor, alert_medium, alert_high]
            
            mock_db.update_issue.return_value = {
                "id": "issue1",
                "summary": "Severity Test Issue",
                "severity": "high",
                "alerts": ["alert_minor", "alert_medium", "alert_high"],
                "host_critical": "0"
            }
            
            # Удаляем критический алерт, severity должен понизиться до high
            updated_issue = issue.remove_alert("alert_critical")
            self.assertEqual(updated_issue.severity, "high")
            
            # При удалении high алерта должны остаться алерты с severity до medium
            mock_find_by_ids.return_value = [alert_minor, alert_medium]
            
            mock_db.update_issue.return_value = {
                "id": "issue1",
                "summary": "Severity Test Issue",
                "severity": "medium",
                "alerts": ["alert_minor", "alert_medium"],
                "host_critical": "0"
            }
            
            # Удаляем high алерт, severity должен понизиться до medium
            updated_issue = issue.remove_alert("alert_high")
            self.assertEqual(updated_issue.severity, "medium")
            
            # При удалении medium алерта должен остаться алерт с minor severity
            mock_find_by_ids.return_value = [alert_minor]
            
            mock_db.update_issue.return_value = {
                "id": "issue1",
                "summary": "Severity Test Issue",
                "severity": "minor",
                "alerts": ["alert_minor"],
                "host_critical": "0"
            }
            
            # Удаляем medium алерт, severity должен понизиться до minor
            updated_issue = issue.remove_alert("alert_medium")
            self.assertEqual(updated_issue.severity, "minor")

    @patch('alerta.models.issue.db')
    def test_host_critical_changes_with_alerts(self, mock_db):
        """Тест изменения host_critical при добавлении и удалении алертов"""
        # Создаем Issue без алертов
        issue = Issue(
            summary="Host Critical Test Issue",
            id="issue1",
            severity="normal",
            host_critical="0",  # Начальное значение host_critical
            alerts=[],
            hosts=[],
            project_groups=[],
            info_systems=[]
        )
        
        # Создаем алерты с разными значениями host_critical
        alert_non_critical = Alert.parse(self.alert_data_medium)
        alert_non_critical.id = "alert_non_critical"
        alert_non_critical.attributes['host_critical'] = "0"
        
        alert_critical = Alert.parse(self.alert_data_high)
        alert_critical.id = "alert_critical"
        alert_critical.attributes['host_critical'] = "1"
        
        # Мок ответа БД для добавления не критичного алерта
        mock_db.update_issue.return_value = {
            "id": "issue1",
            "summary": "Host Critical Test Issue",
            "severity": "medium",
            "host_critical": "0",
            "alerts": ["alert_non_critical"]
        }
        
        # Добавляем алерт с host_critical=0
        updated_issue = issue.add_alert(alert_non_critical)
        self.assertEqual(updated_issue.host_critical, "0")
        
        # Мок ответа БД для добавления критичного алерта
        mock_db.update_issue.return_value = {
            "id": "issue1",
            "summary": "Host Critical Test Issue",
            "severity": "high",
            "host_critical": "1",  # Должно измениться на 1
            "alerts": ["alert_non_critical", "alert_critical"]
        }
        
        # Добавляем алерт с host_critical=1
        updated_issue = issue.add_alert(alert_critical)
        self.assertEqual(updated_issue.host_critical, "1")
        
        # Проверяем изменение host_critical при удалении алерта
        with patch('alerta.models.alert.Alert.find_by_ids') as mock_find_by_ids:
            # При удалении критичного алерта должен остаться только не критичный
            mock_find_by_ids.return_value = [alert_non_critical]
            
            mock_db.update_issue.return_value = {
                "id": "issue1",
                "summary": "Host Critical Test Issue",
                "severity": "medium",
                "host_critical": "0",  # Должно измениться обратно на 0
                "alerts": ["alert_non_critical"]
            }
            
            # Удаляем критичный алерт, host_critical должен вернуться к 0
            updated_issue = issue.remove_alert("alert_critical")
            self.assertEqual(updated_issue.host_critical, "0")

    @patch('alerta.models.issue.db')
    def test_last_alert_time_updates(self, mock_db):
        """Тест обновления last_alert_time при добавлении и удалении алертов"""
        # Создаем Issue без алертов
        issue = Issue(
            summary="Last Alert Time Test Issue",
            id="issue1",
            severity="normal",
            host_critical="0",
            alerts=[],
            hosts=[],
            project_groups=[],
            info_systems=[],
            last_alert_time=None
        )
        
        # Создаем алерты с разными временами создания
        older_time = datetime.now() - timedelta(hours=2)
        newer_time = datetime.now() - timedelta(hours=1)
        newest_time = datetime.now()
        
        alert1 = Alert.parse(self.alert_data_medium)
        alert1.id = "alert1"
        alert1.create_time = older_time
        
        alert2 = Alert.parse(self.alert_data_high)
        alert2.id = "alert2"
        alert2.create_time = newer_time
        
        alert3 = Alert.parse(self.alert_data_critical)
        alert3.id = "alert3"
        alert3.create_time = newest_time
        
        # Мок ответа БД для добавления первого алерта
        mock_db.update_issue.return_value = {
            "id": "issue1",
            "summary": "Last Alert Time Test Issue",
            "severity": "medium",
            "host_critical": "0",
            "alerts": ["alert1"],
            "last_alert_time": older_time
        }
        
        # Добавляем первый алерт, last_alert_time должен быть установлен
        updated_issue = issue.add_alert(alert1)
        self.assertEqual(updated_issue.last_alert_time, older_time)
        
        # Мок ответа БД для добавления второго алерта с более новым временем
        mock_db.update_issue.return_value = {
            "id": "issue1",
            "summary": "Last Alert Time Test Issue",
            "severity": "high",
            "host_critical": "0",
            "alerts": ["alert1", "alert2"],
            "last_alert_time": newer_time
        }
        
        # Добавляем второй алерт, last_alert_time должен обновиться
        updated_issue = issue.add_alert(alert2)
        self.assertEqual(updated_issue.last_alert_time, newer_time)
        
        # Мок ответа БД для добавления третьего алерта с самым новым временем
        mock_db.update_issue.return_value = {
            "id": "issue1",
            "summary": "Last Alert Time Test Issue",
            "severity": "critical",
            "host_critical": "0",
            "alerts": ["alert1", "alert2", "alert3"],
            "last_alert_time": newest_time
        }
        
        # Добавляем третий алерт, last_alert_time должен обновиться
        updated_issue = issue.add_alert(alert3)
        self.assertEqual(updated_issue.last_alert_time, newest_time)
        
        # Проверяем изменение last_alert_time при удалении алерта
        with patch('alerta.models.alert.Alert.find_by_ids') as mock_find_by_ids:
            # При удалении самого нового алерта, последнее время должно стать равным времени alert2
            mock_find_by_ids.return_value = [alert1, alert2]
            
            mock_db.update_issue.return_value = {
                "id": "issue1",
                "summary": "Last Alert Time Test Issue",
                "severity": "high",
                "host_critical": "0",
                "alerts": ["alert1", "alert2"],
                "last_alert_time": newer_time
            }
            
            # Удаляем самый новый алерт, last_alert_time должен стать равным времени alert2
            updated_issue = issue.remove_alert("alert3")
            self.assertEqual(updated_issue.last_alert_time, newer_time)
            
            # При удалении alert2, последнее время должно стать равным времени alert1
            mock_find_by_ids.return_value = [alert1]
            
            mock_db.update_issue.return_value = {
                "id": "issue1",
                "summary": "Last Alert Time Test Issue",
                "severity": "medium",
                "host_critical": "0",
                "alerts": ["alert1"],
                "last_alert_time": older_time
            }
            
            # Удаляем alert2, last_alert_time должен стать равным времени alert1
            updated_issue = issue.remove_alert("alert2")
            self.assertEqual(updated_issue.last_alert_time, older_time)

    @patch('alerta.models.issue.db')
    def test_arrays_updates(self, mock_db):
        """Тест обновления уникальных массивов hosts, project_groups и info_systems при добавлении и удалении алертов"""
        # Создаем Issue без алертов
        issue = Issue(
            summary="Arrays Test Issue",
            id="issue1",
            severity="normal",
            host_critical="0",
            alerts=[],
            hosts=[],
            project_groups=[],
            info_systems=[]
        )
        
        # Создаем алерты с разными значениями host, project_groups и info_systems
        alert1 = Alert.parse(self.alert_data_medium)
        alert1.id = "alert1"
        alert1.resource = "server1"
        alert1.tags = {
            "project_group": ["project1", "project2"],
            "info_system": ["system1"]
        }
        
        alert2 = Alert.parse(self.alert_data_high)
        alert2.id = "alert2"
        alert2.resource = "server2"
        alert2.tags = {
            "project_group": ["project2", "project3"],
            "info_system": ["system2"]
        }
        
        alert3 = Alert.parse(self.alert_data_critical)
        alert3.id = "alert3"
        alert3.resource = "server1"  # Дублирование с alert1
        alert3.tags = {
            "project_group": ["project3", "project4"],
            "info_system": ["system1", "system3"]  # system1 уже есть в alert1
        }
        
        # Мок ответа БД для добавления первого алерта
        mock_db.update_issue.return_value = {
            "id": "issue1",
            "summary": "Arrays Test Issue",
            "severity": "medium",
            "host_critical": "0",
            "alerts": ["alert1"],
            "hosts": ["server1"],
            "project_groups": ["project1", "project2"],
            "info_systems": ["system1"]
        }
        
        # Добавляем первый алерт
        updated_issue = issue.add_alert(alert1)
        self.assertEqual(updated_issue.hosts, ["server1"])
        self.assertEqual(updated_issue.project_groups, ["project1", "project2"])
        self.assertEqual(updated_issue.info_systems, ["system1"])
        
        # Мок ответа БД для добавления второго алерта
        mock_db.update_issue.return_value = {
            "id": "issue1",
            "summary": "Arrays Test Issue",
            "severity": "high",
            "host_critical": "0",
            "alerts": ["alert1", "alert2"],
            "hosts": ["server1", "server2"],
            "project_groups": ["project1", "project2", "project3"],
            "info_systems": ["system1", "system2"]
        }
        
        # Добавляем второй алерт
        updated_issue = issue.add_alert(alert2)
        self.assertEqual(updated_issue.hosts, ["server1", "server2"])
        self.assertEqual(updated_issue.project_groups, ["project1", "project2", "project3"])
        self.assertEqual(updated_issue.info_systems, ["system1", "system2"])
        
        # Мок ответа БД для добавления третьего алерта
        mock_db.update_issue.return_value = {
            "id": "issue1",
            "summary": "Arrays Test Issue",
            "severity": "critical",
            "host_critical": "0",
            "alerts": ["alert1", "alert2", "alert3"],
            "hosts": ["server1", "server2"],  # server1 уже есть
            "project_groups": ["project1", "project2", "project3", "project4"],
            "info_systems": ["system1", "system2", "system3"]
        }
        
        # Добавляем третий алерт
        updated_issue = issue.add_alert(alert3)
        # Проверяем, что дубликаты не добавились
        self.assertEqual(updated_issue.hosts, ["server1", "server2"])
        self.assertEqual(updated_issue.project_groups, ["project1", "project2", "project3", "project4"])
        self.assertEqual(updated_issue.info_systems, ["system1", "system2", "system3"])
        
        # Проверяем удаление значений из массивов при удалении алертов
        with patch('alerta.models.alert.Alert.find_by_ids') as mock_find_by_ids:
            # При удалении третьего алерта, hosts не должны измениться, 
            # но project4 и system3 должны быть удалены
            mock_find_by_ids.return_value = [alert1, alert2]
            
            mock_db.update_issue.return_value = {
                "id": "issue1",
                "summary": "Arrays Test Issue",
                "severity": "high",
                "host_critical": "0",
                "alerts": ["alert1", "alert2"],
                "hosts": ["server1", "server2"],
                "project_groups": ["project1", "project2", "project3"],
                "info_systems": ["system1", "system2"]
            }
            
            # Удаляем третий алерт
            updated_issue = issue.remove_alert("alert3")
            self.assertEqual(updated_issue.hosts, ["server1", "server2"])
            self.assertEqual(updated_issue.project_groups, ["project1", "project2", "project3"])
            self.assertEqual(updated_issue.info_systems, ["system1", "system2"])
            
            # При удалении второго алерта, server2 должен быть удален,
            # project3 тоже, как и system2
            mock_find_by_ids.return_value = [alert1]
            
            mock_db.update_issue.return_value = {
                "id": "issue1",
                "summary": "Arrays Test Issue",
                "severity": "medium",
                "host_critical": "0",
                "alerts": ["alert1"],
                "hosts": ["server1"],
                "project_groups": ["project1", "project2"],
                "info_systems": ["system1"]
            }
            
            # Удаляем второй алерт
            updated_issue = issue.remove_alert("alert2")
            self.assertEqual(updated_issue.hosts, ["server1"])
            self.assertEqual(updated_issue.project_groups, ["project1", "project2"])
            self.assertEqual(updated_issue.info_systems, ["system1"])

    @patch('alerta.models.issue.db')
    def test_alert_issue_link_unlink(self, mock_db):
        """Тест корректного связывания alert_id и issue_id при линковании и отлинковании"""
        # Создаем Issue без алертов
        issue = Issue(
            summary="Link Unlink Test Issue",
            id="issue123",
            severity="normal",
            host_critical="0",
            alerts=[],
            hosts=[],
            project_groups=[],
            info_systems=[]
        )
        
        # Создаем алерт
        alert = Alert.parse(self.alert_data_medium)
        alert.id = "alert456"
        
        # Патчим функцию link_to_issue в классе Alert
        with patch.object(Alert, 'link_to_issue', return_value=alert) as mock_link:
            # Мокаем ответ БД при добавлении алерта в issue
            mock_db.update_issue.return_value = {
                "id": "issue123",
                "summary": "Link Unlink Test Issue",
                "severity": "medium",
                "host_critical": "0",
                "alerts": ["alert456"],
                "hosts": ["TST-WEBC-300"],
                "project_groups": ["AF"],
                "info_systems": ["INFRA"]
            }
            
            # Добавляем алерт к issue
            updated_issue = issue.add_alert(alert)
            
            # Не проверяем вызов метода, просто проверяем результат
            self.assertIn("alert456", updated_issue.alerts)
            self.assertEqual(updated_issue.severity, "medium")
            self.assertEqual(updated_issue.hosts, ["TST-WEBC-300"])
            self.assertEqual(updated_issue.project_groups, ["AF"])
            self.assertEqual(updated_issue.info_systems, ["INFRA"])
            
        # Теперь тестируем удаление алерта из issue
        with patch('alerta.models.alert.Alert.find_by_ids') as mock_find_by_ids:
            # Мокаем find_by_ids для возврата пустого списка (все алерты удалены)
            mock_find_by_ids.return_value = []
            
            # Мокаем ответ БД при удалении алерта
            mock_db.update_issue.return_value = {
                "id": "issue123",
                "summary": "Link Unlink Test Issue",
                "severity": "normal",
                "host_critical": "0",
                "alerts": [],
                "hosts": [],
                "project_groups": [],
                "info_systems": []
            }
            
            # Удаляем алерт из issue
            updated_issue = issue.remove_alert("alert456")
            
            # Проверяем, что issue больше не содержит алерт
            self.assertNotIn("alert456", updated_issue.alerts)
            
            # Проверяем остальные атрибуты issue
            self.assertEqual(updated_issue.severity, "normal")
            self.assertEqual(updated_issue.hosts, [])
            self.assertEqual(updated_issue.project_groups, [])
            self.assertEqual(updated_issue.info_systems, [])


if __name__ == '__main__':
    unittest.main() 