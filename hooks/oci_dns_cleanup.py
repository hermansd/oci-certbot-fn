#!/usr/bin/env python3
from __future__ import annotations

import os

from oci_dns_common import challenge_record_domain, dns_client, fail, service_error_status
from oci_dns_common import txt_rdata, zone_name_or_id

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
    operation = oci.dns.models.RecordOperation(
        domain=record_domain,
        rtype="TXT",
        rdata=txt_rdata(validation),
        operation=oci.dns.models.RecordOperation.OPERATION_REMOVE,
    )
    details = oci.dns.models.PatchRRSetDetails(items=[operation])

    try:
        dns_client().patch_rr_set(zone, record_domain, "TXT", details)
    except Exception as exc:
        if service_error_status(exc) == 404:
            return
        raise


if __name__ == "__main__":
    main()
