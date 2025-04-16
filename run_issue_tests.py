#!/usr/bin/env python

import unittest
import sys
import os
from termcolor import colored
from unittest.runner import TextTestResult, TextTestRunner

# Добавляем текущий каталог в путь для импорта
sys.path.insert(0, os.path.abspath('.'))

from tests.test_issue_alerts import TestIssueAlerts

class DetailedTestResult(TextTestResult):
    def startTest(self, test):
        super().startTest(test)
        print(colored(f"\n\n{'='*60}", 'blue'))
        print(colored(f"Запуск теста: {test.id()}", 'blue', attrs=['bold']))
        print(colored(f"{'='*60}", 'blue'))
    
    def addSuccess(self, test):
        super().addSuccess(test)
        print(colored("\n✓ УСПЕШНО", 'green', attrs=['bold']))
    
    def addError(self, test, err):
        super().addError(test, err)
        print(colored(f"\n✗ ОШИБКА: {err[1]}", 'red', attrs=['bold']))
    
    def addFailure(self, test, err):
        super().addFailure(test, err)
        print(colored(f"\n✗ НЕУДАЧА: {err[1]}", 'red', attrs=['bold']))

class DetailedTestRunner(TextTestRunner):
    resultclass = DetailedTestResult

def run_issue_tests():
    """Запускает все тесты для функциональности Issue с подробным выводом."""
    
    print(colored("\nЗапуск всех тестов для функциональности Issue\n", 'blue', attrs=['bold']))
    
    # Загружаем все тесты из класса TestIssueAlerts
    test_loader = unittest.TestLoader()
    suite = test_loader.loadTestsFromTestCase(TestIssueAlerts)
    
    # Запускаем тесты с детальным выводом
    runner = DetailedTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result

if __name__ == "__main__":
    # Проверяем наличие термина для цветного вывода
    if len(sys.argv) > 1:
        # Если передан аргумент с названием конкретного теста
        test_name = sys.argv[1]
        suite = unittest.TestSuite()
        test_loader = unittest.TestLoader()
        
        try:
            test = test_loader.loadTestsFromName(f'tests.test_issue_alerts.TestIssueAlerts.{test_name}')
            suite.addTest(test)
            print(colored(f"\nЗапуск теста: {test_name}\n", 'blue', attrs=['bold']))
        except AttributeError:
            print(colored(f"Ошибка: Тест '{test_name}' не найден в классе TestIssueAlerts", 'red'))
            sys.exit(1)
        
        runner = DetailedTestRunner(verbosity=2)
        result = runner.run(suite)
        sys.exit(not result.wasSuccessful())
    else:
        # Запускаем все тесты Issue
        result = run_issue_tests()
        sys.exit(not result.wasSuccessful()) 