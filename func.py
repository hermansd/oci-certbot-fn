# Copyright (c) 2026, Oracle OCI Certbot contributors
# Licensed under the Universal Permissive License v 1.0 as shown at
# https://oss.oracle.com/licenses/upl/
# SPDX-License-Identifier: UPL-1.0

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import traceback
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from stat import S_IFDIR, S_IFLNK, S_IFREG
from typing import Any

try:
    import oci
    import oci.load_balancer
    import oci.object_storage
    import oci.pagination
except ImportError:  # Allows local syntax checks before dependencies are installed.
    oci = None

try:
    from fdk import response as fdk_response
except ImportError:
    fdk_response = None


STATE_ROOT = Path("/tmp/certbot-state")
CERT_TEMP_DIR = STATE_ROOT / "certTemp"
CONFIG_DIR = CERT_TEMP_DIR / "config"
WORK_DIR = CERT_TEMP_DIR / "work"
LOGS_DIR = CERT_TEMP_DIR / "logs"
CONFIG_DIR_ARG = "certTemp/config"
WORK_DIR_ARG = "certTemp/work"
LOGS_DIR_ARG = "certTemp/logs"
DEFAULT_SECTIGO_ACME_SERVER = "https://acme.sectigo.com/v2/DV"
LETSENCRYPT_ACME_SERVER = "https://acme-v02.api.letsencrypt.org/directory"
LETSENCRYPT_STAGING_ACME_SERVER = "https://acme-staging-v02.api.letsencrypt.org/directory"
ACME_SERVER_ALIASES = {
    "sectigo": DEFAULT_SECTIGO_ACME_SERVER,
    "sectigo-dv": DEFAULT_SECTIGO_ACME_SERVER,
    "letsencrypt": LETSENCRYPT_ACME_SERVER,
    "lets-encrypt": LETSENCRYPT_ACME_SERVER,
    "le": LETSENCRYPT_ACME_SERVER,
    "letsencrypt-staging": LETSENCRYPT_STAGING_ACME_SERVER,
    "lets-encrypt-staging": LETSENCRYPT_STAGING_ACME_SERVER,
    "le-staging": LETSENCRYPT_STAGING_ACME_SERVER,
}
DEFAULT_MAX_STATE_ARCHIVE_BYTES = 50 * 1024 * 1024
SECRET_ARG_OPTIONS = {"--eab-hmac-key"}


@dataclass(frozen=True)
class CertbotConfig:
    bucket_name: str
    domain: str | None
    namespace: str | None
    state_object_name: str
    kms_key_id: str | None
    acme_server: str | None
    eab_kid: str | None
    eab_hmac_key: str | None
    eab_required: bool
    email: str | None
    domains: list[str]
    cert_name: str | None
    extra_args: list[str]
    issue_args: list[str]
    renew_args: list[str]
    certbot_command: list[str]
    force_renewal: bool
    reissue: bool
    timeout_seconds: int
    auth_mode: str
    oci_region: str | None
    load_balancer_ids: list[str]
    load_balancer_listener_names: list[str]
    load_balancer_lineage: str | None
    load_balancer_certificate_name_prefix: str | None
    load_balancer_certificate_passphrase: str | None
    load_balancer_delete_old_certificates: bool
    load_balancer_wait_seconds: int


@dataclass(frozen=True)
class CertificateBundle:
    lineage: str
    public_certificate: str
    private_key: str
    ca_certificate: str | None


class CertbotError(RuntimeError):
    # Certbot debug logs can echo CLI arguments, so tails are redacted before
    # they are returned to the caller.
    def __init__(
        self,
        exit_code: int,
        command: list[str],
        output: str | None,
        log_tail: str | None,
        sensitive_values: list[str],
    ) -> None:
        message = (
            f"Certbot failed with exit code {exit_code}."
            if exit_code >= 0
            else "Certbot timed out before completing."
        )
        super().__init__(message)
        self.exit_code = exit_code
        self.command = command
        self.output_tail = _tail(_redact_text(output, sensitive_values))
        self.log_tail = _tail(_redact_text(log_tail, sensitive_values))

    def response_payload(self) -> dict[str, Any]:
        return {
            "certbotCommand": self.command,
            "certbotExitCode": self.exit_code,
            "certbotOutputTail": self.output_tail,
            "certbotLogTail": self.log_tail,
            "stateLayout": _state_layout_summary(),
        }


def handler(ctx, data: io.BytesIO | None = None):
    try:
        invocation = _read_invocation(data)
        result = run(invocation)
        return _json_response(ctx, 200, result)
    except Exception as exc:
        traceback.print_exc()
        return _json_response(
            ctx,
            500,
            {
                "ok": False,
                "error": str(exc),
                "type": exc.__class__.__name__,
                **_exception_payload(exc),
            },
        )


def run(invocation: dict[str, Any] | None = None) -> dict[str, Any]:
    config = _load_config(invocation or {})
    object_storage = _object_storage_client(config)
    namespace = config.namespace or object_storage.get_namespace().data

    _reset_state_root()
    state_restored = _download_state(
        object_storage,
        namespace,
        config.bucket_name,
        config.state_object_name,
    )
    _migrate_legacy_state_layout()
    _ensure_certbot_directories()
    # Imported state may come from a workstation zip. Certbot renewal files use
    # absolute paths and live/*.pem symlinks, so normalize both before renewal.
    _repair_certbot_state()

    has_lineage = _has_renewal_lineage()
    if not has_lineage or config.reissue:
        _validate_initial_issue_config(config)
        mode = "issue"
        certbot_args = _issue_command(config)
    else:
        mode = "renew"
        certbot_args = _renew_command(config)

    certbot_result = _run_certbot(certbot_args, config.timeout_seconds)
    certbot_sensitive_values = _sensitive_values_from_args(certbot_args)
    archive = _build_state_archive(config.state_object_name)
    _upload_state(
        object_storage,
        namespace,
        config.bucket_name,
        config.state_object_name,
        archive,
        config.kms_key_id,
    )
    load_balancer_result = _update_load_balancers(config)

    return {
        "ok": True,
        "mode": mode,
        "stateRestored": state_restored,
        "stateObject": f"{config.bucket_name}/{config.state_object_name}",
        "lineages": _lineage_names(),
        "loadBalancerUpdate": load_balancer_result,
        "certbotExitCode": certbot_result.returncode,
        "certbotOutputTail": _tail(
            _redact_text(certbot_result.stdout, certbot_sensitive_values)
        ),
    }


def _load_config(invocation: dict[str, Any]) -> CertbotConfig:
    bucket_name = _setting(invocation, "bucketName", "OCI_BUCKET_NAME")
    if not bucket_name:
        raise ValueError("bucketName in the invocation payload or OCI_BUCKET_NAME is required.")

    domain = _setting(invocation, "domain", "CERTBOT_DOMAIN")

    return CertbotConfig(
        bucket_name=bucket_name,
        domain=domain,
        namespace=_setting(invocation, "namespace", "OCI_NAMESPACE"),
        state_object_name=_state_object_name(
            invocation,
            domain,
        ),
        kms_key_id=_setting(invocation, "kmsKeyId", "OCI_OBJECT_STORAGE_KMS_KEY_ID"),
        acme_server=_acme_server_setting(invocation),
        eab_kid=_eab_kid_setting(invocation),
        eab_hmac_key=_eab_hmac_key_setting(invocation),
        eab_required=_bool_setting(
            invocation,
            "eabRequired",
            "SECTIGO_EAB_REQUIRED",
            _default_eab_required(_acme_server_setting(invocation)),
        ),
        email=_setting(invocation, "email", "CERTBOT_EMAIL"),
        domains=_configured_domains(invocation, domain),
        cert_name=_setting(invocation, "certName", "CERTBOT_CERT_NAME"),
        extra_args=_arg_setting(
            invocation,
            "extraArgs",
            "CERTBOT_EXTRA_ARGS",
            "--standalone",
        ),
        issue_args=_arg_setting(invocation, "issueArgs", "CERTBOT_ISSUE_ARGS"),
        renew_args=_arg_setting(invocation, "renewArgs", "CERTBOT_RENEW_ARGS"),
        certbot_command=_arg_setting(
            invocation,
            "certbotCommand",
            "CERTBOT_COMMAND",
            "certbot",
        ),
        force_renewal=_force_renewal_setting(invocation),
        reissue=_bool_setting(invocation, "reissue", "CERTBOT_REISSUE", False),
        timeout_seconds=int(
            _setting(invocation, "timeoutSeconds", "CERTBOT_TIMEOUT_SECONDS", "840")
        ),
        auth_mode=_setting(invocation, "authMode", "OCI_AUTH_MODE", "resource_principal"),
        oci_region=_setting(invocation, "ociRegion", "OCI_REGION"),
        load_balancer_ids=_load_balancer_ids_setting(invocation),
        load_balancer_listener_names=_csv_setting(
            invocation,
            "loadBalancerListenerNames",
            "OCI_LB_LISTENER_NAMES",
        ),
        load_balancer_lineage=_setting(
            invocation,
            "loadBalancerLineage",
            "OCI_LB_CERTBOT_LINEAGE",
        ),
        load_balancer_certificate_name_prefix=_setting(
            invocation,
            "loadBalancerCertificateNamePrefix",
            "OCI_LB_CERTIFICATE_NAME_PREFIX",
        ),
        load_balancer_certificate_passphrase=_setting(
            invocation,
            "loadBalancerCertificatePassphrase",
            "OCI_LB_CERTIFICATE_PASSPHRASE",
        ),
        load_balancer_delete_old_certificates=_bool_setting(
            invocation,
            "loadBalancerDeleteOldCertificates",
            "OCI_LB_DELETE_OLD_CERTIFICATES",
            False,
        ),
        load_balancer_wait_seconds=int(
            _setting(invocation, "loadBalancerWaitSeconds", "OCI_LB_WAIT_SECONDS", "300")
        ),
    )


def _validate_initial_issue_config(config: CertbotConfig) -> None:
    missing = []
    if not config.domains:
        missing.append("domain or CERTBOT_DOMAINS")
    if not config.acme_server:
        missing.append("SECTIGO_ACME_SERVER")
    if config.eab_required and not config.eab_kid:
        missing.append("eabKid or SECTIGO_EAB_KID")
    if config.eab_required and not config.eab_hmac_key:
        missing.append("eabHmacKey or SECTIGO_EAB_HMAC_KEY")
    if missing:
        raise ValueError(
            "Initial certificate issuance is missing required config: "
            + ", ".join(missing)
        )


def _object_storage_client(config: CertbotConfig):
    if oci is None:
        raise RuntimeError("The oci package is required at runtime.")

    client_config, signer = _oci_client_config_and_signer(config)
    client = oci.object_storage.ObjectStorageClient(client_config, signer=signer)
    if config.oci_region:
        client.base_client.set_region(config.oci_region)
    return client


def _load_balancer_client(config: CertbotConfig):
    if oci is None:
        raise RuntimeError("The oci package is required at runtime.")

    client_config, signer = _oci_client_config_and_signer(config)
    client = oci.load_balancer.LoadBalancerClient(client_config, signer=signer)
    if config.oci_region:
        client.base_client.set_region(config.oci_region)
    return client


def _oci_client_config_and_signer(config: CertbotConfig):
    client_config: dict[str, str] = {}
    signer = None
    auth_mode = config.auth_mode.lower().replace("-", "_")

    if auth_mode == "resource_principal":
        signer = oci.auth.signers.get_resource_principals_signer()
    elif auth_mode == "instance_principal":
        signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
    elif auth_mode == "config_file":
        profile = os.getenv("OCI_CONFIG_PROFILE", "DEFAULT")
        file_location = os.getenv("OCI_CONFIG_FILE", "~/.oci/config")
        client_config = oci.config.from_file(file_location=file_location, profile_name=profile)
    else:
        raise ValueError(
            "OCI_AUTH_MODE must be resource_principal, instance_principal, or config_file."
        )

    if config.oci_region:
        client_config["region"] = config.oci_region

    return client_config, signer


def _download_state(client, namespace: str, bucket: str, object_name: str) -> bool:
    try:
        response = client.get_object(namespace, bucket, object_name)
    except Exception as exc:
        exceptions = getattr(oci, "exceptions", None) if oci else None
        service_error = getattr(exceptions, "ServiceError", None)
        if service_error and isinstance(exc, service_error) and exc.status == 404:
            return False
        raise

    max_bytes = _max_state_archive_bytes()
    content_length = _response_content_length(response)
    if content_length is not None and content_length > max_bytes:
        raise ValueError(
            f"State archive is too large: {content_length} bytes exceeds {max_bytes}."
        )

    payload = response.data.content
    if not payload:
        return False
    _enforce_state_archive_size(len(payload), "Downloaded state archive")

    if object_name.endswith(".zip"):
        _extract_state_zip(payload)
        return True

    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
        _safe_extract(archive, STATE_ROOT)
    return True


def _response_content_length(response) -> int | None:
    headers = getattr(response, "headers", None) or {}
    value = headers.get("content-length") or headers.get("Content-Length")
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _max_state_archive_bytes() -> int:
    raw = os.getenv("OCI_STATE_MAX_BYTES", str(DEFAULT_MAX_STATE_ARCHIVE_BYTES))
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError("OCI_STATE_MAX_BYTES must be an integer.") from exc
    if value <= 0:
        raise ValueError("OCI_STATE_MAX_BYTES must be greater than zero.")
    return value


def _enforce_state_archive_size(size: int, label: str) -> None:
    max_bytes = _max_state_archive_bytes()
    if size > max_bytes:
        raise ValueError(f"{label} is too large: {size} bytes exceeds {max_bytes}.")


def _upload_state(
    client,
    namespace: str,
    bucket: str,
    object_name: str,
    archive: bytes,
    kms_key_id: str | None,
) -> None:
    _enforce_state_archive_size(len(archive), "Generated state archive")
    kwargs: dict[str, Any] = {"content_type": _state_content_type(object_name)}
    if kms_key_id:
        kwargs["opc_sse_kms_key_id"] = kms_key_id

    client.put_object(namespace, bucket, object_name, archive, **kwargs)


def _state_content_type(object_name: str) -> str:
    if object_name.endswith(".zip"):
        return "application/zip"
    return "application/gzip"


def _update_load_balancers(config: CertbotConfig) -> dict[str, Any]:
    if not config.load_balancer_ids:
        return {"enabled": False}

    # OCI LB certificate bundle names are immutable; publish a fingerprinted
    # bundle and repoint listeners rather than trying to overwrite in place.
    bundle = _load_certificate_bundle(config)
    certificate_name = _load_balancer_certificate_name(config, bundle)
    client = _load_balancer_client(config)
    composite = oci.load_balancer.LoadBalancerClientCompositeOperations(client)
    results = []

    for load_balancer_id in config.load_balancer_ids:
        _ensure_load_balancer_certificate(
            client,
            composite,
            load_balancer_id,
            certificate_name,
            bundle,
            config,
        )
        results.append(
            _update_load_balancer_listeners(
                client,
                composite,
                load_balancer_id,
                certificate_name,
                config,
            )
        )

    return {
        "enabled": True,
        "lineage": bundle.lineage,
        "certificateName": certificate_name,
        "loadBalancers": results,
    }


def _load_certificate_bundle(config: CertbotConfig) -> CertificateBundle:
    lineage = _select_load_balancer_lineage(config)
    live_dir = CONFIG_DIR / "live" / lineage
    public_certificate = _read_required_text(live_dir / "cert.pem")
    private_key = _read_required_text(live_dir / "privkey.pem")
    ca_certificate = _read_optional_text(live_dir / "chain.pem")

    return CertificateBundle(
        lineage=lineage,
        public_certificate=public_certificate,
        private_key=private_key,
        ca_certificate=ca_certificate,
    )


def _select_load_balancer_lineage(config: CertbotConfig) -> str:
    if config.load_balancer_lineage:
        _ensure_lineage_exists(config.load_balancer_lineage)
        return config.load_balancer_lineage

    if config.cert_name and (CONFIG_DIR / "live" / config.cert_name).exists():
        return config.cert_name

    lineages = _lineage_names()
    if len(lineages) == 1:
        return lineages[0]
    if not lineages:
        raise ValueError("No Certbot renewal lineage exists for load balancer update.")
    raise ValueError(
        "Multiple Certbot lineages exist; set OCI_LB_CERTBOT_LINEAGE to choose one."
    )


def _ensure_lineage_exists(lineage: str) -> None:
    if not (CONFIG_DIR / "live" / lineage).exists():
        raise ValueError(f"Certbot lineage does not exist: {lineage}")


def _load_balancer_certificate_name(
    config: CertbotConfig,
    bundle: CertificateBundle,
) -> str:
    prefix = config.load_balancer_certificate_name_prefix or bundle.lineage
    prefix = _sanitize_load_balancer_certificate_name(prefix)
    fingerprint = hashlib.sha256(bundle.public_certificate.encode("utf-8")).hexdigest()[:16]
    max_prefix_length = 64 - len(fingerprint) - 1
    prefix = prefix[:max_prefix_length].strip("-_") or "certbot"
    return f"{prefix}-{fingerprint}"


def _sanitize_load_balancer_certificate_name(value: str) -> str:
    sanitized = re.sub(r"[^A-Za-z0-9_-]+", "-", value).strip("-_")
    return sanitized or "certbot"


def _ensure_load_balancer_certificate(
    client,
    composite,
    load_balancer_id: str,
    certificate_name: str,
    bundle: CertificateBundle,
    config: CertbotConfig,
) -> None:
    if _load_balancer_certificate_exists(client, load_balancer_id, certificate_name):
        return

    details = oci.load_balancer.models.CreateCertificateDetails(
        certificate_name=certificate_name,
        public_certificate=bundle.public_certificate,
        private_key=bundle.private_key,
        ca_certificate=bundle.ca_certificate,
        passphrase=config.load_balancer_certificate_passphrase,
    )
    response = composite.create_certificate_and_wait_for_state(
        details,
        load_balancer_id,
        wait_for_states=_load_balancer_terminal_states(),
        waiter_kwargs=_load_balancer_waiter_kwargs(config),
    )
    _assert_work_request_succeeded(response, "create load balancer certificate")


def _load_balancer_certificate_exists(
    client,
    load_balancer_id: str,
    certificate_name: str,
) -> bool:
    try:
        certificates = oci.pagination.list_call_get_all_results(
            client.list_certificates,
            load_balancer_id,
        ).data
    except Exception as exc:
        if _service_error_status(exc) == 404:
            return False
        raise

    return any(cert.certificate_name == certificate_name for cert in certificates)


def _update_load_balancer_listeners(
    client,
    composite,
    load_balancer_id: str,
    certificate_name: str,
    config: CertbotConfig,
) -> dict[str, Any]:
    load_balancer = client.get_load_balancer(load_balancer_id).data
    listeners = _target_load_balancer_listeners(load_balancer, config)
    listener_results = []
    old_certificate_names = set()

    for listener in listeners:
        old_certificate_name = _listener_certificate_name(listener)
        if old_certificate_name == certificate_name:
            listener_results.append(
                {
                    "name": listener.name,
                    "updated": False,
                    "previousCertificateName": old_certificate_name,
                }
            )
            continue

        details = _listener_update_details(listener, certificate_name)
        response = composite.update_listener_and_wait_for_state(
            details,
            load_balancer_id,
            listener.name,
            wait_for_states=_load_balancer_terminal_states(),
            waiter_kwargs=_load_balancer_waiter_kwargs(config),
        )
        _assert_work_request_succeeded(response, f"update listener {listener.name}")
        if old_certificate_name:
            old_certificate_names.add(old_certificate_name)
        listener_results.append(
            {
                "name": listener.name,
                "updated": True,
                "previousCertificateName": old_certificate_name,
            }
        )

    deleted, delete_warnings = _delete_old_load_balancer_certificates(
        client,
        composite,
        load_balancer_id,
        old_certificate_names,
        certificate_name,
        config,
    )

    return {
        "id": load_balancer_id,
        "listeners": listener_results,
        "deletedOldCertificates": deleted,
        "deleteWarnings": delete_warnings,
    }


def _target_load_balancer_listeners(load_balancer, config: CertbotConfig) -> list[Any]:
    listeners = _listeners_by_name(load_balancer)
    if config.load_balancer_listener_names:
        missing = [
            name for name in config.load_balancer_listener_names if name not in listeners
        ]
        if missing:
            raise ValueError(
                f"Load balancer {load_balancer.id} is missing listener(s): "
                + ", ".join(missing)
            )
        return [listeners[name] for name in config.load_balancer_listener_names]

    ssl_listeners = [
        listener for listener in listeners.values() if listener.ssl_configuration is not None
    ]
    if not ssl_listeners:
        raise ValueError(
            f"Load balancer {load_balancer.id} has no SSL listeners to update."
        )
    return ssl_listeners


def _listeners_by_name(load_balancer) -> dict[str, Any]:
    listeners = load_balancer.listeners or {}
    if isinstance(listeners, dict):
        return listeners
    return {listener.name: listener for listener in listeners}


def _listener_certificate_name(listener) -> str | None:
    ssl_configuration = listener.ssl_configuration
    if not ssl_configuration:
        return None
    return getattr(ssl_configuration, "certificate_name", None)


def _listener_update_details(listener, certificate_name: str):
    ssl_configuration = listener.ssl_configuration
    if not ssl_configuration:
        raise ValueError(f"Listener {listener.name} does not have SSL enabled.")

    ssl_details = oci.load_balancer.models.SSLConfigurationDetails(
        verify_depth=ssl_configuration.verify_depth,
        verify_peer_certificate=ssl_configuration.verify_peer_certificate,
        has_session_resumption=ssl_configuration.has_session_resumption,
        trusted_certificate_authority_ids=(
            ssl_configuration.trusted_certificate_authority_ids
        ),
        certificate_name=certificate_name,
        protocols=ssl_configuration.protocols,
        cipher_suite_name=ssl_configuration.cipher_suite_name,
        server_order_preference=ssl_configuration.server_order_preference,
    )

    return oci.load_balancer.models.UpdateListenerDetails(
        default_backend_set_name=listener.default_backend_set_name,
        port=listener.port,
        protocol=listener.protocol,
        hostname_names=listener.hostname_names,
        path_route_set_name=listener.path_route_set_name,
        routing_policy_name=listener.routing_policy_name,
        ssl_configuration=ssl_details,
        connection_configuration=listener.connection_configuration,
        rule_set_names=listener.rule_set_names,
    )


def _delete_old_load_balancer_certificates(
    client,
    composite,
    load_balancer_id: str,
    old_certificate_names: set[str],
    new_certificate_name: str,
    config: CertbotConfig,
) -> tuple[list[str], list[str]]:
    if not config.load_balancer_delete_old_certificates:
        return [], []

    current_certificate_names = _current_listener_certificate_names(client, load_balancer_id)
    deleted = []
    warnings = []
    for certificate_name in sorted(old_certificate_names):
        if certificate_name == new_certificate_name:
            continue
        if certificate_name in current_certificate_names:
            continue
        try:
            response = composite.delete_certificate_and_wait_for_state(
                load_balancer_id,
                certificate_name,
                wait_for_states=_load_balancer_terminal_states(),
                waiter_kwargs=_load_balancer_waiter_kwargs(config),
            )
            _assert_work_request_succeeded(
                response,
                f"delete old load balancer certificate {certificate_name}",
            )
            deleted.append(certificate_name)
        except Exception as exc:
            warnings.append(f"{certificate_name}: {exc}")
    return deleted, warnings


def _current_listener_certificate_names(client, load_balancer_id: str) -> set[str]:
    load_balancer = client.get_load_balancer(load_balancer_id).data
    names = set()
    for listener in _listeners_by_name(load_balancer).values():
        certificate_name = _listener_certificate_name(listener)
        if certificate_name:
            names.add(certificate_name)
    return names


def _load_balancer_terminal_states() -> list[str]:
    return [
        oci.load_balancer.models.WorkRequest.LIFECYCLE_STATE_SUCCEEDED,
        oci.load_balancer.models.WorkRequest.LIFECYCLE_STATE_FAILED,
    ]


def _load_balancer_waiter_kwargs(config: CertbotConfig) -> dict[str, int]:
    return {
        "max_interval_seconds": 15,
        "max_wait_seconds": config.load_balancer_wait_seconds,
    }


def _assert_work_request_succeeded(response, action: str) -> None:
    work_request = response.data
    state = getattr(work_request, "lifecycle_state", None)
    if state == oci.load_balancer.models.WorkRequest.LIFECYCLE_STATE_SUCCEEDED:
        return

    message = getattr(work_request, "message", "") or ""
    errors = getattr(work_request, "error_details", None) or []
    error_text = "; ".join(str(error) for error in errors)
    details = f" {message}".rstrip()
    if error_text:
        details = f"{details} {error_text}".rstrip()
    raise RuntimeError(f"Failed to {action}; work request state was {state}.{details}")


def _read_required_text(path: Path) -> str:
    if not path.exists():
        raise ValueError(f"Required certificate file does not exist: {path}")
    value = path.read_text(encoding="utf-8").strip()
    if not value:
        raise ValueError(f"Required certificate file is empty: {path}")
    return value + "\n"


def _read_optional_text(path: Path) -> str | None:
    if not path.exists():
        return None
    value = path.read_text(encoding="utf-8").strip()
    if not value:
        return None
    return value + "\n"


def _issue_command(config: CertbotConfig) -> list[str]:
    args = [
        *config.certbot_command,
        "certonly",
        *config.extra_args,
        "--non-interactive",
        "--agree-tos",
        "--server",
        config.acme_server or "",
    ]

    for domain in config.domains:
        args.extend(["--domain", domain])
    args.extend(["--work-dir", WORK_DIR_ARG])
    args.extend(["--config-dir", CONFIG_DIR_ARG])
    args.extend(["--logs-dir", LOGS_DIR_ARG])
    if config.email:
        args.extend(["--email", config.email])
    if config.cert_name:
        args.extend(["--cert-name", config.cert_name])
    if config.eab_kid:
        args.extend(["--eab-kid", config.eab_kid])
    if config.eab_hmac_key:
        args.extend(["--eab-hmac-key", config.eab_hmac_key])
    if config.force_renewal:
        args.append("--force-renewal")

    return [*args, *config.issue_args]


def _renew_command(config: CertbotConfig) -> list[str]:
    args = [
        *config.certbot_command,
        "renew",
        *config.extra_args,
        "--non-interactive",
        "--work-dir",
        WORK_DIR_ARG,
        "--config-dir",
        CONFIG_DIR_ARG,
        "--logs-dir",
        LOGS_DIR_ARG,
    ]
    if config.force_renewal:
        args.append("--force-renewal")
    return [*args, *config.renew_args]


def _run_certbot(args: list[str], timeout_seconds: int) -> subprocess.CompletedProcess[str]:
    redacted_command = _redact_command(args)
    sensitive_values = _sensitive_values_from_args(args)
    print(json.dumps({"event": "certbot_start", "command": redacted_command}))
    try:
        result = subprocess.run(
            args,
            check=False,
            cwd=STATE_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        output = exc.output
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        raise CertbotError(
            -1,
            redacted_command,
            output,
            _latest_certbot_log_tail(),
            sensitive_values,
        ) from exc
    redacted_output_tail = _tail(_redact_text(result.stdout, sensitive_values))
    print(
        json.dumps(
            {
                "event": "certbot_finish",
                "exitCode": result.returncode,
                "outputTail": redacted_output_tail,
            }
        )
    )
    if result.returncode != 0:
        raise CertbotError(
            result.returncode,
            redacted_command,
            result.stdout,
            _latest_certbot_log_tail(),
            sensitive_values,
        )
    return result


def _build_state_archive(object_name: str) -> bytes:
    if object_name.endswith(".zip"):
        return _build_state_zip_archive()
    return _build_state_tar_archive()


def _build_state_zip_archive() -> bytes:
    buffer = io.BytesIO()
    total_size = 0
    with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        _zip_directory_entry(archive, "certbot-state/")
        for path in sorted(STATE_ROOT.rglob("*")):
            arcname = f"certbot-state/{path.relative_to(STATE_ROOT).as_posix()}"
            if _skip_state_path(path):
                continue
            if path.is_symlink():
                total_size += len(os.readlink(path).encode("utf-8"))
                _enforce_state_archive_size(total_size, "Generated uncompressed state archive")
                _zip_symlink_entry(archive, path, arcname)
            elif path.is_dir():
                _zip_directory_entry(archive, f"{arcname}/")
            elif path.is_file():
                total_size += path.stat().st_size
                _enforce_state_archive_size(total_size, "Generated uncompressed state archive")
                archive.write(path, arcname)
    return buffer.getvalue()


def _zip_directory_entry(archive: zipfile.ZipFile, arcname: str) -> None:
    info = zipfile.ZipInfo(arcname)
    info.external_attr = (S_IFDIR | 0o755) << 16
    archive.writestr(info, "")


def _zip_symlink_entry(archive: zipfile.ZipFile, path: Path, arcname: str) -> None:
    info = zipfile.ZipInfo(arcname)
    info.external_attr = (S_IFLNK | 0o777) << 16
    archive.writestr(info, os.readlink(path))


def _skip_state_path(path: Path) -> bool:
    name = path.name
    return name.endswith(".lock") or name in {"lock", ".certbot.lock"}


def _build_state_tar_archive() -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for path, arcname in (
            (CONFIG_DIR, "config"),
            (WORK_DIR, "work"),
            (LOGS_DIR, "logs"),
        ):
            if path.exists():
                archive.add(path, arcname=arcname, filter=_tar_filter)
    return buffer.getvalue()


def _tar_filter(info: tarfile.TarInfo) -> tarfile.TarInfo | None:
    name = Path(info.name).name
    if name.endswith(".lock") or name in {"lock", ".certbot.lock"}:
        return None
    return info


def _extract_state_zip(payload: bytes) -> None:
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        # Object Storage is trusted by IAM, but the archive content still needs
        # normal path traversal and size checks before extraction.
        _validate_zip_archive(archive)
        names = [name for name in archive.namelist() if name and name != "/"]
        has_root_directory = any(name == "certbot-state/" for name in names) or all(
            name == "certbot-state" or name.startswith("certbot-state/") for name in names
        )
        destination = STATE_ROOT.parent if has_root_directory else STATE_ROOT
        for info in archive.infolist():
            _extract_zip_member(archive, info, destination, STATE_ROOT)


def _validate_zip_archive(archive: zipfile.ZipFile) -> None:
    total_size = 0
    for info in archive.infolist():
        _validate_archive_member_name(info.filename)
        if info.flag_bits & 0x1:
            raise ValueError(f"Encrypted zip entries are not supported: {info.filename}")
        total_size += info.file_size
        _enforce_state_archive_size(total_size, "Uncompressed zip state archive")


def _extract_zip_member(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    destination: Path,
    allowed_root: Path,
) -> None:
    name = info.filename
    if not name or name == "/":
        return
    _validate_archive_member_name(name)

    target = (destination / name).resolve()
    _assert_under(allowed_root.resolve(), target, name)

    mode = (info.external_attr >> 16) & 0o170000
    if info.is_dir():
        target.mkdir(parents=True, exist_ok=True)
        return
    if mode == S_IFLNK:
        link_target_raw = archive.read(info).decode("utf-8")
        link_target = Path(link_target_raw)
        if link_target.is_absolute():
            raise ValueError(f"Refusing to extract absolute symlink target: {name}")
        resolved_link = (target.parent / link_target).resolve()
        _assert_under(allowed_root.resolve(), resolved_link, name)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() or target.is_symlink():
            target.unlink()
        target.symlink_to(link_target_raw)
        return
    if mode not in {0, S_IFREG}:
        raise ValueError(f"Refusing to extract unsupported zip entry type: {name}")

    target.parent.mkdir(parents=True, exist_ok=True)
    with archive.open(info) as source, target.open("wb") as output:
        shutil.copyfileobj(source, output)


def _safe_extract(archive: tarfile.TarFile, destination: Path) -> None:
    destination = destination.resolve()
    total_size = 0
    for member in archive.getmembers():
        # Tar archives can contain links or special files; only the Certbot
        # state file types we expect are allowed through.
        _validate_archive_member_name(member.name)
        if member.islnk():
            raise ValueError(f"Refusing to extract hard link from state archive: {member.name}")
        if not (member.isdir() or member.isfile() or member.issym()):
            raise ValueError(f"Refusing to extract special file from state archive: {member.name}")
        total_size += member.size
        _enforce_state_archive_size(total_size, "Uncompressed tar state archive")
        target = (destination / member.name).resolve()
        _assert_under(destination, target, member.name)
        if member.issym():
            link_target = Path(member.linkname)
            if link_target.is_absolute():
                raise ValueError(f"Refusing to extract absolute link target: {member.name}")
            resolved_link = (target.parent / link_target).resolve()
            _assert_under(destination, resolved_link, member.name)
    archive.extractall(destination)


def _validate_archive_member_name(name: str) -> None:
    if not name or name == "/":
        return
    if "\x00" in name or "\\" in name:
        raise ValueError(f"Refusing unsafe archive path: {name}")
    posix_path = PurePosixPath(name)
    if posix_path.is_absolute() or ".." in posix_path.parts:
        raise ValueError(f"Refusing unsafe archive path: {name}")


def _assert_under(root: Path, target: Path, name: str) -> None:
    if target != root and root not in target.parents:
        raise ValueError(f"Refusing to extract path outside state root: {name}")


def _reset_state_root() -> None:
    shutil.rmtree(STATE_ROOT, ignore_errors=True)
    _ensure_certbot_directories()


def _ensure_certbot_directories() -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    WORK_DIR.mkdir(parents=True, exist_ok=True)
    LOGS_DIR.mkdir(parents=True, exist_ok=True)


def _migrate_legacy_state_layout() -> None:
    CERT_TEMP_DIR.mkdir(parents=True, exist_ok=True)
    for name in ("config", "work", "logs"):
        legacy_path = STATE_ROOT / name
        target_path = CERT_TEMP_DIR / name
        if not legacy_path.exists():
            continue
        if target_path.exists() and any(target_path.iterdir()):
            continue
        if target_path.exists():
            shutil.rmtree(target_path)
        shutil.move(str(legacy_path), str(target_path))


def _repair_certbot_state() -> None:
    _rewrite_renewal_configs()
    _restore_live_symlinks()


def _rewrite_renewal_configs() -> None:
    renewal_dir = CONFIG_DIR / "renewal"
    if not renewal_dir.exists():
        return

    for renewal_conf in renewal_dir.glob("*.conf"):
        lineage = renewal_conf.stem
        replacements = {
            "archive_dir": CONFIG_DIR / "archive" / lineage,
            "cert": CONFIG_DIR / "live" / lineage / "cert.pem",
            "privkey": CONFIG_DIR / "live" / lineage / "privkey.pem",
            "chain": CONFIG_DIR / "live" / lineage / "chain.pem",
            "fullchain": CONFIG_DIR / "live" / lineage / "fullchain.pem",
        }
        try:
            lines = renewal_conf.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            print(json.dumps({"event": "renewal_config_read_failed", "path": str(renewal_conf), "error": str(exc)}))
            continue

        changed = False
        rewritten = []
        for line in lines:
            key = line.split("=", 1)[0].strip() if "=" in line else ""
            if key in replacements:
                new_line = f"{key} = {replacements[key]}"
                changed = changed or new_line != line
                rewritten.append(new_line)
            else:
                rewritten.append(line)

        if changed:
            renewal_conf.write_text("\n".join(rewritten) + "\n", encoding="utf-8")
            print(json.dumps({"event": "renewal_config_rewritten", "path": str(renewal_conf)}))


def _restore_live_symlinks() -> None:
    archive_root = CONFIG_DIR / "archive"
    live_root = CONFIG_DIR / "live"
    if not archive_root.exists():
        return

    for archive_dir in sorted(path for path in archive_root.iterdir() if path.is_dir()):
        version = _latest_archive_version(archive_dir)
        if version is None:
            continue

        live_dir = live_root / archive_dir.name
        live_dir.mkdir(parents=True, exist_ok=True)
        restored = []
        for name in ("cert", "chain", "fullchain", "privkey"):
            archive_file = archive_dir / f"{name}{version}.pem"
            live_file = live_dir / f"{name}.pem"
            if not archive_file.exists():
                continue

            target = Path("..") / ".." / "archive" / archive_dir.name / archive_file.name
            if live_file.is_symlink() and os.readlink(live_file) == str(target):
                continue
            if live_file.exists() or live_file.is_symlink():
                live_file.unlink()
            live_file.symlink_to(target)
            restored.append(live_file.name)

        if restored:
            print(
                json.dumps(
                    {
                        "event": "live_symlinks_restored",
                        "lineage": archive_dir.name,
                        "version": version,
                        "files": restored,
                    }
                )
            )


def _latest_archive_version(archive_dir: Path) -> int | None:
    versions = []
    for path in archive_dir.glob("cert*.pem"):
        match = re.fullmatch(r"cert(\d+)\.pem", path.name)
        if match:
            versions.append(int(match.group(1)))
    return max(versions) if versions else None


def _has_renewal_lineage() -> bool:
    renewal_dir = CONFIG_DIR / "renewal"
    return renewal_dir.exists() and any(renewal_dir.glob("*.conf"))


def _lineage_names() -> list[str]:
    renewal_dir = CONFIG_DIR / "renewal"
    if not renewal_dir.exists():
        return []
    return sorted(path.stem for path in renewal_dir.glob("*.conf"))


def _latest_certbot_log_tail() -> str:
    if not LOGS_DIR.exists():
        return ""

    candidates = [path for path in LOGS_DIR.rglob("*.log") if path.is_file()]
    if not candidates:
        candidates = [path for path in LOGS_DIR.rglob("*") if path.is_file()]
    if not candidates:
        return ""

    latest = max(candidates, key=lambda path: path.stat().st_mtime)
    try:
        return latest.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return f"Could not read Certbot log {latest}: {exc}"


def _state_layout_summary(limit: int = 120) -> list[str]:
    if not STATE_ROOT.exists():
        return []

    entries = []
    for path in sorted(STATE_ROOT.rglob("*")):
        relative = path.relative_to(STATE_ROOT).as_posix()
        if _skip_state_path(path):
            continue
        if path.is_symlink():
            entries.append(f"{relative} -> {os.readlink(path)}")
        elif path.is_dir():
            entries.append(f"{relative}/")
        else:
            entries.append(relative)
        if len(entries) >= limit:
            entries.append("...")
            break
    return entries


def _exception_payload(exc: Exception) -> dict[str, Any]:
    if isinstance(exc, CertbotError):
        return exc.response_payload()
    return {}


def _read_invocation(data: io.BytesIO | None) -> dict[str, Any]:
    if data is None:
        return {}
    raw = data.read()
    if not raw:
        return {}
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("Invocation payload must be a JSON object.")
    return payload


def _json_response(ctx, status_code: int, payload: dict[str, Any]):
    body = json.dumps(payload, sort_keys=True)
    if fdk_response is None:
        return body
    return fdk_response.Response(
        ctx,
        response_data=body,
        headers={"Content-Type": "application/json"},
        status_code=status_code,
    )


def _setting(
    invocation: dict[str, Any],
    key: str,
    env_name: str,
    default: str | None = None,
) -> str | None:
    value = invocation.get(key)
    if value is None:
        value = os.getenv(env_name, default)
    if isinstance(value, str):
        value = value.strip()
    return value or None


def _state_object_name(invocation: dict[str, Any], domain: str | None) -> str:
    explicit = _setting(invocation, "stateObjectName", "OCI_STATE_OBJECT_NAME")
    if explicit:
        return explicit
    if domain:
        return f"{domain}.zip"
    raise ValueError(
        "domain in the invocation payload, CERTBOT_DOMAIN, or OCI_STATE_OBJECT_NAME is required."
    )


def _acme_server_setting(invocation: dict[str, Any]) -> str | None:
    value = invocation.get("server")
    if value is None:
        value = invocation.get("acmeServer")
    if value is None:
        value = invocation.get("ca")
    if value is None:
        value = os.getenv("SECTIGO_ACME_SERVER", DEFAULT_SECTIGO_ACME_SERVER)
    if isinstance(value, str):
        value = value.strip()
    return _normalize_acme_server(value) if value else None


def _normalize_acme_server(value: str) -> str:
    return ACME_SERVER_ALIASES.get(value.strip().lower(), value)


def _eab_kid_setting(invocation: dict[str, Any]) -> str | None:
    value = invocation.get("eabKid")
    if value is None:
        value = invocation.get("kid")
    if value is None:
        value = os.getenv("SECTIGO_EAB_KID")
    if isinstance(value, str):
        value = value.strip()
    return value or None


def _eab_hmac_key_setting(invocation: dict[str, Any]) -> str | None:
    value = invocation.get("eabHmacKey")
    if value is None:
        value = invocation.get("hmacKey")
    if value is None:
        value = invocation.get("eabHmac")
    if value is None:
        value = os.getenv("SECTIGO_EAB_HMAC_KEY")
    if isinstance(value, str):
        value = value.strip()
    return value or None


def _default_eab_required(acme_server: str | None) -> bool:
    return bool(acme_server and "sectigo.com" in acme_server.lower())


def _configured_domains(invocation: dict[str, Any], domain: str | None) -> list[str]:
    value = invocation.get("domains")
    if isinstance(value, list):
        domains = [str(item).strip() for item in value if str(item).strip()]
        if domains:
            return domains
    if isinstance(value, str) and value.strip():
        return _domains(value)

    env_domains = os.getenv("CERTBOT_DOMAINS")
    if env_domains:
        return _domains(env_domains)
    return [domain] if domain else []


def _load_balancer_ids_setting(invocation: dict[str, Any]) -> list[str]:
    for key in (
        "loadBalancerOcid",
        "loadBalancerId",
        "loadBalancerOcids",
        "loadBalancerIds",
    ):
        value = invocation.get(key)
        if isinstance(value, list):
            values = [str(item).strip() for item in value if str(item).strip()]
            if values:
                return values
        if isinstance(value, str) and value.strip():
            return _domains(value)
    return _csv_setting(invocation, "loadBalancerIds", "OCI_LB_ID")


def _force_renewal_setting(invocation: dict[str, Any]) -> bool:
    for key in ("forceRenewal", "force-renewal", "force_renewal"):
        if key in invocation:
            return _truthy(invocation[key])
    return _bool_setting(invocation, "forceRenewal", "CERTBOT_FORCE_RENEWAL", False)


def _arg_setting(
    invocation: dict[str, Any],
    key: str,
    env_name: str,
    default: str = "",
) -> list[str]:
    value = invocation.get(key)
    if isinstance(value, list):
        return [str(item) for item in value]
    if value is None:
        value = os.getenv(env_name, default)
    return shlex.split(str(value))


def _bool_setting(
    invocation: dict[str, Any],
    key: str,
    env_name: str,
    default: bool,
) -> bool:
    value = invocation.get(key)
    if value is None:
        value = os.getenv(env_name)
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return _truthy(value)


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def _csv_setting(invocation: dict[str, Any], key: str, env_name: str) -> list[str]:
    value = invocation.get(key)
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if value is None:
        value = os.getenv(env_name, "")
    return _domains(str(value))


def _domains(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [item.strip() for item in raw.replace("\n", ",").split(",") if item.strip()]


def _redact_command(args: list[str]) -> list[str]:
    redacted: list[str] = []
    redact_next = False
    sensitive_values = _sensitive_values_from_args(args)
    for arg in args:
        if redact_next:
            redacted.append("***")
            redact_next = False
            continue
        if _is_secret_assignment(arg):
            redacted.append(_redact_secret_assignment(arg))
        else:
            redacted.append(_redact_text(arg, sensitive_values))
        if arg in SECRET_ARG_OPTIONS:
            redact_next = True
    return redacted


def _sensitive_values_from_args(args: list[str]) -> list[str]:
    values = []
    capture_next = False
    for arg in args:
        if capture_next:
            if arg:
                values.append(arg)
            capture_next = False
            continue
        for option in SECRET_ARG_OPTIONS:
            prefix = f"{option}="
            if arg.startswith(prefix):
                value = arg[len(prefix) :]
                if value:
                    values.append(value)
                break
        if arg in SECRET_ARG_OPTIONS:
            capture_next = True
    return values


def _is_secret_assignment(arg: str) -> bool:
    return any(arg.startswith(f"{option}=") for option in SECRET_ARG_OPTIONS)


def _redact_secret_assignment(arg: str) -> str:
    for option in SECRET_ARG_OPTIONS:
        if arg.startswith(f"{option}="):
            return f"{option}=***"
    return arg


def _redact_text(text: str | None, sensitive_values: list[str]) -> str:
    if not text:
        return ""
    redacted = text
    for value in sensitive_values:
        if value:
            redacted = redacted.replace(value, "***")
    return redacted


def _tail(text: str | None, limit: int = 6000) -> str:
    if not text:
        return ""
    return text[-limit:]


def _service_error_status(exc: Exception) -> int | None:
    if oci is None:
        return None
    exceptions = getattr(oci, "exceptions", None)
    service_error = getattr(exceptions, "ServiceError", None)
    if service_error and isinstance(exc, service_error):
        return exc.status
    return None
