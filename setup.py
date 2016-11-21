from setuptools import setup, find_packages

setup(
    name="ch-prometheus-smart-exporter",
    version="0.1",
    description="S.M.A.R.T. exporter for Prometheus",
    url="https://gitlab.cloudandheat.com/jonas.wielicki/prometheus_smart_exporter",
    author="Jonas Wielicki",
    author_email="jonas.wielicki@cloudandheat.com",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "prometheus_smart_exporter=prometheus_smart_exporter:main",
        ]
    },
    install_requires=[
        "prometheus_client>=0.0.14",
    ]
)
