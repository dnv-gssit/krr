import asyncio
import datetime
from typing import Optional, no_type_check

import requests
from kubernetes import config as k8s_config
from kubernetes.client import ApiClient
from prometheus_api_client import PrometheusConnect, Retry
from requests.adapters import HTTPAdapter
from requests.exceptions import ConnectionError, HTTPError

from robusta_krr.core.abstract.strategies import ResourceHistoryData
from robusta_krr.core.models.config import Config
from robusta_krr.core.models.objects import K8sObjectData, PodData
from robusta_krr.core.models.result import ResourceType
from robusta_krr.utils.configurable import Configurable
from robusta_krr.utils.service_discovery import ServiceDiscovery

from .metrics import BaseMetricLoader


class PrometheusDiscovery(ServiceDiscovery):
    """
    Service discovery for Prometheus.
    """

    def find_prometheus_url(self, *, api_client: Optional[ApiClient] = None) -> Optional[str]:
        """
        Finds the Prometheus URL using selectors.

        Args:
            api_client (Optional[ApiClient]): A Kubernetes API client. Defaults to None.

        Returns:
            Optional[str]: The discovered Prometheus URL, or None if not found.
        """
        return super().find_url(
            selectors=[
                "app=kube-prometheus-stack-prometheus",
                "app=prometheus,component=server",
                "app=prometheus-server",
                "app=prometheus-operator-prometheus",
                "app=prometheus-msteams",
                "app=rancher-monitoring-prometheus",
                "app=prometheus-prometheus",
            ],
            api_client=api_client,
        )


class PrometheusNotFound(Exception):
    """
    An exception raised when Prometheus is not found.
    """

    pass


class CustomPrometheusConnect(PrometheusConnect):
    """
    Custom PrometheusConnect class to handle retries.
    """

    @no_type_check
    def __init__(
        self,
        url: str = "http://127.0.0.1:9090",
        headers: dict = None,
        disable_ssl: bool = False,
        retry: Retry = None,
        auth: tuple = None,
    ):
        super().__init__(url, headers, disable_ssl, retry, auth)
        self._session = requests.Session()
        self._session.mount(self.url, HTTPAdapter(max_retries=retry, pool_maxsize=10, pool_block=True))


class PrometheusLoader(Configurable):
    """
    A loader class for fetching metrics from Prometheus.
    """

    def __init__(
        self,
        config: Config,
        *,
        cluster: Optional[str] = None,
    ) -> None:
        """
        Initializes the Prometheus Loader.

        Args:
            config (Config): The configuration object.
            cluster (Optional[str]): The name of the cluster. Defaults to None.
        """

        super().__init__(config=config)

        self.info(f"Connecting to Prometheus for {cluster or 'default'} cluster")

        self.auth_header = self.config.prometheus_auth_header
        self.ssl_enabled = self.config.prometheus_ssl_enabled

        self.api_client = k8s_config.new_client_from_config(context=cluster) if cluster is not None else None
        self.prometheus_discovery = PrometheusDiscovery(config=self.config)

        self.url = self.config.prometheus_url
        self.url = self.url or self.prometheus_discovery.find_prometheus_url(api_client=self.api_client)

        if not self.url:
            raise PrometheusNotFound(
                f"Prometheus instance could not be found while scanning in {cluster or 'default'} cluster.\n"
                "\tTry using port-forwarding and/or setting the url manually (using the -p flag.)."
            )

        headers = {}

        if self.auth_header:
            headers = {"Authorization": self.auth_header}
        elif not self.config.inside_cluster:
            self.api_client.update_params_for_auth(headers, {}, ["BearerToken"])

        self.prometheus = CustomPrometheusConnect(url=self.url, disable_ssl=not self.ssl_enabled, headers=headers)
        self._check_prometheus_connection()

        self.info(f"Prometheus connected successfully for {cluster or 'default'} cluster")

    def _check_prometheus_connection(self):
        """
        Checks the connection to Prometheus.

        Raises:
            PrometheusNotFound: If the connection to Prometheus cannot be established.
        """

        try:
            response = self.prometheus._session.get(
                f"{self.prometheus.url}/api/v1/query",
                verify=self.prometheus.ssl_verification,
                headers=self.prometheus.headers,
                # This query should return empty results, but is correct
                params={"query": "example"},
            )
            response.raise_for_status()
        except (ConnectionError, HTTPError) as e:
            raise PrometheusNotFound(
                f"Couldn't connect to Prometheus found under {self.prometheus.url}\nCaused by {e.__class__.__name__}: {e})"
            ) from e

    async def gather_data(
        self,
        object: K8sObjectData,
        resource: ResourceType,
        period: datetime.timedelta,
        *,
        step: datetime.timedelta = datetime.timedelta(minutes=30),
    ) -> ResourceHistoryData:
        """
        Gathers data from Prometheus for a specified object and resource.

        Args:
            object (K8sObjectData): The Kubernetes object.
            resource (ResourceType): The resource type.
            period (datetime.timedelta): The time period for which to gather data.
            step (datetime.timedelta, optional): The time step between data points. Defaults to 30 minutes.

        Returns:
            ResourceHistoryData: The gathered resource history data.
        """

        self.debug(f"Gathering data for {object} and {resource}")

        await self.add_historic_pods(object, period)

        MetricLoaderType = BaseMetricLoader.get_by_resource(resource)
        metric_loader = MetricLoaderType(self.config, self.prometheus)
        return await metric_loader.load_data(object, period, step)

    async def add_historic_pods(self, object: K8sObjectData, period: datetime.timedelta) -> None:
        """
        Finds pods that have been deleted but still have some metrics in Prometheus.

        Args:
            object (K8sObjectData): The Kubernetes object.
            period (datetime.timedelta): The time period for which to gather data.
        """

        if len(object.pods) == 0:
            return

        period_literal = f"{int(period.total_seconds()) // 60 // 24}d"
        owner = await asyncio.to_thread(
            self.prometheus.custom_query,
            query=f'kube_pod_owner{{pod="{next(iter(object.pods)).name}"}}[{period_literal}]',
        )

        if owner == []:
            return

        owner = owner[0]["metric"]["owner_name"]

        related_pods = await asyncio.to_thread(
            self.prometheus.custom_query, query=f'kube_pod_owner{{owner_name="{owner}"}}[{period_literal}]'
        )

        current_pods = {p.name for p in object.pods}

        object.pods += [
            PodData(
                name=pod["metric"]["pod"],
                deleted=True,
            )
            for pod in related_pods
            if pod["metric"]["pod"] not in current_pods
        ]
