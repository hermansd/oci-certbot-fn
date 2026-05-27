#!/usr/bin/env python3
# Copyright (c) 2026, Oracle OCI Certbot contributors
# Licensed under the Universal Permissive License v 1.0 as shown at
# https://oss.oracle.com/licenses/upl/
# SPDX-License-Identifier: UPL-1.0

from __future__ import annotations

import json
import os
import time

from oci_dns_common import dns_client, fail, txt_rdata, zone_name_or_id
from oci_dns_common import challenge_record_domain

try:
    import oci
    import oci.dns
except ImportError:
    oci = None


def main() -> None:
    if oci is None:
        fail("The oci package is required for OCI DNS hooks.")

    domain = os.getenv("CERTBOT_DOMAIN")
    validation = os.getenv("CERTBOT_VALIDATION")
    if not domain or not validation:
        fail("CERTBOT_DOMAIN and CERTBOT_VALIDATION are required.")

    zone = zone_name_or_id()
    record_domain = challenge_record_domain(domain)
    rdata = txt_rdata(validation)
    ttl = max(30, int(os.getenv("OCI_DNS_TTL", "30")))

    operation = oci.dns.models.RecordOperation(
        domain=record_domain,
        rtype="TXT",
        rdata=rdata,
        ttl=ttl,
        operation=oci.dns.models.RecordOperation.OPERATION_ADD,
    )
    details = oci.dns.models.PatchRRSetDetails(items=[operation])
    dns_client().patch_rr_set(zone, record_domain, "TXT", details)

    wait_seconds = int(os.getenv("OCI_DNS_PROPAGATION_SECONDS", "60"))
    if wait_seconds > 0:
        time.sleep(wait_seconds)

    print(
        json.dumps(
            {
                "zone": zone,
                "domain": record_domain,
                "rtype": "TXT",
                "ttl": ttl,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
