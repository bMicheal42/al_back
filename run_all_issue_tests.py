#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
import sys

from run_detailed_tests import DetailedTestRunner
from tests.test_issue_alerts import TestIssueAlerts

def run_all_issue_tests():
    """Запуск всех тестов Issue с подробным выводом"""
    
    print("\033[1;36m")  # Голубой цвет, жирный
    print("=" * 80)
    print("ЗАПУСК ВСЕХ ТЕСТОВ ISSUE")
    print("=" * 80)
    print("\033[0m")  # Сброс стиля
    
    # Создаем тест-сьют из всех тестов TestIssueAlerts
    suite = unittest.TestLoader().loadTestsFromTestCase(TestIssueAlerts)
    
    # Запускаем тесты с детальным выводом
    runner = DetailedTestRunner()
    runner.run(suite)


if __name__ == "__main__":
    run_all_issue_tests() 