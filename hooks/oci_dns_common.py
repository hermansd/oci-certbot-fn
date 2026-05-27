# Copyright (c) 2026, Oracle OCI Certbot contributors
# Licensed under the Universal Permissive License v 1.0 as shown at
# https://oss.oracle.com/licenses/upl/
# SPDX-License-Identifier: UPL-1.0

from __future__ import annotations

import os
import sys
from pathlib import Path

try:
    import oci
    import oci.dns
except ImportError:
    oci = None


def dns_client():
    if oci is None:
        raise RuntimeError("The oci package is required for OCI DNS hooks.")

    mode = os.getenv("OCI_AUTH_MODE", "resource_principal").lower().replace("-", "_")
    client_config = {}
    signer = None

    if mode == "resource_principal":
        signer = oci.auth.signers.get_resource_principals_signer()
    elif mode == "instance_principal":
        signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
    elif mode == "config_file":
        profile = os.getenv("OCI_CONFIG_PROFILE", "DEFAULT")
        file_location = os.getenv("OCI_CONFIG_FILE", "~/.oci/config")
        client_config = oci.config.from_file(
            file_location=str(Path(file_location).expanduser()),
            profile_name=profile,
        )
    else:
        raise ValueError(
            "OCI_AUTH_MODE must be resource_principal, instance_principal, or config_file."
        )

    region = os.getenv("OCI_REGION")
    if region:
        client_config["region"] = region

    client = oci.dns.DnsClient(client_config, signer=signer)
    if region:
        client.base_client.set_region(region)
    return client


def zone_name_or_id() -> str:
    value = os.getenv("OCI_DNS_ZONE_NAME") or os.getenv("OCI_DNS_ZONE_ID")
    if not value:
        raise ValueError("OCI_DNS_ZONE_NAME or OCI_DNS_ZONE_ID is required for OCI DNS hooks.")
    return value.strip()


def challenge_record_domain(certbot_domain: str) -> str:
    domain = certbot_domain.strip().strip(".")
    if domain.startswith("*."):
        domain = domain[2:]
    return f"_acme-challenge.{domain}."


def txt_rdata(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def service_error_status(exc: Exception) -> int | None:
    if oci is None:
        return None
    service_error = oci.exceptions.ServiceError
    if isinstance(exc, service_error):
        return exc.status
    return None


def fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)
