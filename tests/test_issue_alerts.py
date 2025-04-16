import unittest
import json
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

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


if __name__ == '__main__':
    unittest.main() 