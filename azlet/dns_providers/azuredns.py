from typing import Any

from azure.mgmt.dns import DnsManagementClient
from sewer.dns_providers import common


class AzureDnsDns(common.BaseDns):

    def __init__(self, subscription: str, rg: str, zone: str, credential, **kwargs: Any):
        self.dns_client = DnsManagementClient(
            credential, subscription
        )
        self.rg = rg
        self.zone = zone
        super().__init__(**kwargs)

    def create_prefix(self, domain_name: str) -> str:
        prefix = "_acme-challenge" + "." + domain_name
        if domain_name.endswith(self.zone):
            zone_name_len = len(self.zone) + 1
            prefix = prefix[0:-zone_name_len]
        return prefix

    def create_dns_record(self, domain_name: str, domain_dns_value: str):
        prefix = self.create_prefix(domain_name)
        self.dns_client.record_sets.create_or_update(
            self.rg, self.zone, prefix, "TXT", {
                "ttl": 1,
                "TXTRecords": [
                    {"value": [domain_dns_value]}
                ]
            })

    def delete_dns_record(self, domain_name, domain_dns_value):
        prefix = self.create_prefix(domain_name)
        self.dns_client.record_sets.delete(self.rg, self.zone, prefix, "TXT")
