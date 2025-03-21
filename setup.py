#!/usr/bin/env python

import os

import setuptools


def read(filename):
    return open(os.path.join(os.path.dirname(__file__), filename)).read()


setuptools.setup(
    name='alerta-server',
    version=read('VERSION'),
    description='Alerta server WSGI application',
    long_description=read('README.md'),
    long_description_content_type='text/markdown',
    url='https://github.com/guardian/alerta',
    license='Apache License 2.0',
    author='Nick Satterly',
    author_email='nfsatterly@gmail.com',
    packages=setuptools.find_packages(exclude=['tests']),
    install_requires=[
        'bcrypt',
        'blinker',
        'cryptography',
        'Flask>=2.0.1',
        'Flask-Compress>=1.4.0',
        'Flask-Cors>=3.0.2',
        'mohawk',
        'PyJWT>=2.0.0',
        'pyparsing',
        'python-dateutil',
        'pytz',
        'PyYAML',
        'requests',
        'requests-hawk',
        'sentry-sdk[flask]>=0.10.2',
    ],
    extras_require={
        'mongodb': ['pymongo'],
        'postgres': ['psycopg2']
    },
    include_package_data=True,
    zip_safe=False,
    entry_points={
        'console_scripts': [
            'alertad = alerta.commands:cli'
        ],
        'alerta.plugins': [
            'remote_ip = alerta.plugins.remote_ip:RemoteIpAddr',
            'reject = alerta.plugins.reject:RejectPolicy',
            'heartbeat = alerta.plugins.heartbeat:HeartbeatReceiver',
            'blackout = alerta.plugins.blackout:BlackoutHandler',
            'acked_by = alerta.plugins.acked_by:AckedBy',
            'escalate = alerta.plugins.escalate:EscalateSeverity',
            'forwarder = alerta.plugins.forwarder:Forwarder',
            'timeout = alerta.plugins.timeout:TimeoutPolicy'
        ],
        'alerta.webhooks': [
            'cloudwatch = alerta.webhooks.cloudwatch:CloudWatchWebhook',
            'grafana = alerta.webhooks.grafana:GrafanaWebhook',
            'graylog = alerta.webhooks.graylog:GraylogWebhook',
            'newrelic = alerta.webhooks.newrelic:NewRelicWebhook',
            'pagerduty = alerta.webhooks.pagerduty:PagerDutyWebhook',
            'pingdom = alerta.webhooks.pingdom:PingdomWebhook',
            'prometheus = alerta.webhooks.prometheus:PrometheusWebhook',
            'riemann = alerta.webhooks.riemann:RiemannWebhook',
            'serverdensity = alerta.webhooks.serverdensity:ServerDensityWebhook',
            'slack = alerta.webhooks.slack:SlackWebhook',
            'jira = alerta.webhooks.jira:JiraWebhook',
            'stackdriver = alerta.webhooks.stackdriver:StackDriverWebhook',
            'telegram = alerta.webhooks.telegram:TelegramWebhook'
        ]
    },
    keywords='alert monitoring system wsgi application api',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Web Environment',
        'Environment :: Plugins',
        'Framework :: Flask',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Telecommunications Industry',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 3.12',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.9',
        'Topic :: System :: Monitoring',
    ],
    python_requires='>=3.9'
)
