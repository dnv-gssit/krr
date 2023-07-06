import asyncio
from concurrent.futures import ThreadPoolExecutor
import datetime
from typing import List, Optional, Type

from kubernetes.client import ApiClient
from prometheus_api_client import PrometheusApiClientException
from requests.exceptions import ConnectionError, HTTPError

from robusta_krr.core.abstract.strategies import ResourceHistoryData
from robusta_krr.core.models.config import Config
from robusta_krr.core.models.objects import K8sObjectData, PodData
from robusta_krr.core.models.result import ResourceType
from robusta_krr.utils.service_discovery import ServiceDiscovery

from ..metrics import BaseMetricLoader
from ..prometheus_client import CustomPrometheusConnect
from .base_metric_service import MetricsNotFound, MetricsService


class PrometheusDiscovery(ServiceDiscovery):
    def find_metrics_url(self, *, api_client: Optional[ApiClient] = None) -> Optional[str]:
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
            ]
        )


class PrometheusNotFound(MetricsNotFound):
    """
    An exception raised when Prometheus is not found.
    """

    pass


class PrometheusMetricsService(MetricsService):
    """
    A class for fetching metrics from Prometheus.
    """

    def __init__(
        self,
        config: Config,
        *,
        cluster: Optional[str] = None,
        api_client: Optional[ApiClient] = None,
        service_discovery: Type[ServiceDiscovery] = PrometheusDiscovery,
        executor: Optional[ThreadPoolExecutor] = None,
    ) -> None:
        super().__init__(config=config, api_client=api_client, cluster=cluster, executor=executor)

        self.info(f"Connecting to {self.name()} for {self.cluster} cluster")

        self.auth_header = self.config.prometheus_auth_header
        self.ssl_enabled = self.config.prometheus_ssl_enabled

        self.prometheus_discovery = service_discovery(config=self.config, api_client=self.api_client)

        self.url = self.config.prometheus_url
        self.url = self.url or self.prometheus_discovery.find_metrics_url()

        if not self.url:
            raise PrometheusNotFound(
                f"{self.name()} instance could not be found while scanning in {self.cluster} cluster.\n"
                "\tTry using port-forwarding and/or setting the url manually (using the -p flag.)."
            )

        self.info(f"Using {self.name()} at {self.url} for cluster {cluster or 'default'}")

        headers = {}

        if self.auth_header:
            headers = {"Authorization": self.auth_header}
        elif not self.config.inside_cluster:
            self.api_client.update_params_for_auth(headers, {}, ["BearerToken"])

        self.prometheus = CustomPrometheusConnect(url=self.url, disable_ssl=not self.ssl_enabled, headers=headers)

    def check_connection(self):
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

    async def query(self, query: str) -> dict:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self.executor, lambda: self.prometheus.custom_query(query=query))

    def validate_cluster_name(self):
        cluster_label = self.config.prometheus_cluster_label
        cluster_names = self.get_cluster_names()

        if len(cluster_names) <= 1:
            # there is only one cluster of metrics in this prometheus
            return

        if not cluster_label:
            raise ClusterNotSpecifiedException(
                f"No label specified, Rerun krr with the flag `-l <cluster>` where <cluster> is one of {cluster_names}"
            )
        if cluster_label not in cluster_names:
            raise ClusterNotSpecifiedException(
                f"Label {cluster_label} does not exist, Rerun krr with the flag `-l <cluster>` where <cluster> is one of {cluster_names}"
            )

    def get_cluster_names(self) -> Optional[List[str]]:
        try:
            return self.prometheus.get_label_values(label_name=self.config.prometheus_label)
        except PrometheusApiClientException:
            self.error("Labels api not present on prometheus client")
            return []

    async def gather_data(
        self,
        object: K8sObjectData,
        resource: ResourceType,
        period: datetime.timedelta,
        step: datetime.timedelta = datetime.timedelta(minutes=30),
    ) -> ResourceHistoryData:
        """
        ResourceHistoryData: The gathered resource history data.
        """
        self.debug(f"Gathering data for {object} and {resource}")

        MetricLoaderType = BaseMetricLoader.get_by_resource(resource, self.config.strategy)
        await self.add_historic_pods(object, period)
        if resource == ResourceType.Memory:
            await self.get_oomkill_count(object, period, step)
        metric_loader = MetricLoaderType(self.config, self.prometheus, self.executor)
        return await metric_loader.load_data(object, period, step, self.name())

    async def get_oomkill_count(
        self, object: K8sObjectData, period: datetime.timedelta, step: datetime.timedelta
    ) -> None:
        """
        Counts the relevant (limit related) oomkills in designated period
        Args:
            object (K8sObjectData): The Kubernetes object.
            period (timedelta): The period to query, by default the past day.
        """
        # no limit so no oomkill isnt related to limit
        if not object.allocations.limits[ResourceType.Memory]:
            return
        pods_selector = "|".join(pod.name for pod in object.pods)
        int_bytes_mem_limit = int(object.allocations.limits[ResourceType.Memory])
        resolution = f"[{BaseMetricLoader.step_to_string(period)}:{BaseMetricLoader.step_to_string(step)}]"
        cluster_label = self.get_prometheus_cluster_label()
        query = f""" 
        max_over_time((max(kube_pod_container_resource_limits{{pod=~"{pods_selector}", container="{object.container}" {cluster_label}}}) by (pod, namespace, container) >= {int_bytes_mem_limit} * 
        max(kube_pod_container_status_last_terminated_reason{{reason="OOMKilled", pod=~"{pods_selector}", container="{object.container}" {cluster_label}}}) by (pod, namespace, container)){resolution})
        """

        oom_kill_series = self.prometheus.custom_query(query)
        if oom_kill_series:
            for series in oom_kill_series:
                # if there is an oomkill the series will be a list in the format [timestamp, mem_limit]
                if len(series["value"]) >= 2 and int(series["value"][1]) >= int_bytes_mem_limit:
                    object.oomkilled = True
                    break

    async def add_historic_pods(self, object: K8sObjectData, period: datetime.timedelta) -> None:
        """
        Finds pods that have been deleted but still have some metrics in Prometheus.
        Args:
            object (K8sObjectData): The Kubernetes object.
            period (datetime.timedelta): The time period for which to gather data.
        """

        days_literal = min(int(period.total_seconds()) // 60 // 24, 32)
        period_literal = f"{days_literal}d"
        pod_owners: list[str]
        pod_owner_kind: str
        cluster_label = self.get_prometheus_cluster_label()
        if object.kind == "Deployment":
            replicasets = await self.query(
                "kube_replicaset_owner{"
                f'owner_name="{object.name}", '
                f'owner_kind="Deployment", '
                f'namespace="{object.namespace}"'
                f"{cluster_label}"
                "}"
                f"[{period_literal}]"
            )
            pod_owners = [replicaset["metric"]["replicaset"] for replicaset in replicasets]
            pod_owner_kind = "ReplicaSet"
        else:
            pod_owners = [object.name]
            pod_owner_kind = object.kind

        owners_regex = "|".join(pod_owners)
        related_pods = await self.query(
            "kube_pod_owner{"
            f'owner_name=~"{owners_regex}", '
            f'owner_kind="{pod_owner_kind}", '
            f'namespace="{object.namespace}"'
            f"{cluster_label}"
            "}"
            f"[{period_literal}]"
        )

        current_pods = {p.name for p in object.pods}

        object.pods += [
            PodData(name=pod["metric"]["pod"], deleted=True)
            for pod in related_pods
            if pod["metric"]["pod"] not in current_pods
        ]
