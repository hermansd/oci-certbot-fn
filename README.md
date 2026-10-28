# Certbot Renewal on OCI Functions

This project is an OCI Function that runs Certbot against a Sectigo ACME endpoint and persists Certbot state in Oracle Object Storage between invocations.

## Project Metadata

- Language: Python 3.11 on OCI Functions.
- License: Universal Permissive License v 1.0 (`UPL-1.0`). See `LICENSE.txt`.
- SPDX identifier: `UPL-1.0`.

The state archive is a zip file named from the requested domain, for example `www.example.com.zip`. It contains the Certbot account, renewal configuration, certificates, and private keys from the function's ephemeral `/tmp/certbot-state` directory. Treat the Object Storage bucket as sensitive secret storage.

## Files

- `func.py` - OCI Function handler. Restores Certbot state, runs `certbot certonly` or `certbot renew`, writes the updated state archive back to Object Storage, and can update OCI Load Balancer listeners.
- `hooks/oci_dns_auth.py` - optional Certbot manual auth hook that creates an OCI DNS TXT record for DNS-01 validation.
- `hooks/oci_dns_cleanup.py` - optional cleanup hook that removes the DNS-01 TXT record.
- `Dockerfile` - custom OCI Functions image with Certbot, OCI SDK, and FDK installed.
- `func.yaml` - OCI Functions metadata.

## Function Flow

1. Resolve the bucket from `bucketName` and the state object from `<domain>.zip`.
2. Extract it into `/tmp/certbot-state`.
3. If no renewal lineage exists, run `certbot certonly` with the selected provider.
4. If renewal lineage exists, run `certbot renew`.
5. Zip the updated `/tmp/certbot-state` directory and overwrite the Object Storage object.
6. If `OCI_LB_ID` is set, create a versioned OCI Load Balancer certificate bundle from the Certbot PEM files and point the configured listener(s) at it.

The normal invocation payload supplies the bucket and domain:

```json
{
  "bucketName": "sslcerts",
  "domain": "www.example.com",
  "provider": "sectigo",
  "eabKid": "<sectigo-eab-kid>",
  "eabHmacKey": "<sectigo-eab-hmac-key>",
  "loadBalancerOcid": "<load-balancer-ocid>"
}
```

With that payload, the function downloads `www.example.com.zip` from the `sslcerts` bucket. After Certbot completes, it zips `/tmp/certbot-state` and writes the updated archive back to the same object.

For Cloudflare DNS with Let’s Encrypt, use:

```json
{
  "bucketName": "sslcerts",
  "domain": "www.example.com",
  "provider": "cloudflare",
  "cloudflareApiToken": "<zone-scoped-api-token>",
  "email": "admin@example.com",
  "loadBalancerOcid": "<load-balancer-ocid>"
}
```

Cloudflare mode uses the Let's Encrypt production ACME server and DNS-01 validation automatically. It writes the token to a mode-0600 file outside the archived state and removes that file after Certbot finishes. Set `CLOUDFLARE_API_TOKEN` as function config instead of passing `cloudflareApiToken` in the payload if preferred. A Cloudflare API token scoped to the zone with DNS edit permission is required. Use `"server": "letsencrypt-staging"` for testing. Keep separate `stateObjectName` values if you issue certificates for the same domain through both providers.

If the state ZIP already contains a Cloudflare credentials INI file, pass its path relative to the ZIP root instead of a token:

```json
{
  "bucketName": "sslcerts",
  "domain": "www.example.com",
  "provider": "cloudflare",
  "cloudflareCredentialsPath": "certState/cloudflare/www.example.com.ini",
  "email": "admin@example.com",
  "loadBalancerOcid": "<load-balancer-ocid>"
}
```

The INI file must contain `dns_cloudflare_api_token = <token>`. The function reads it only from the restored state tree, then writes a temporary mode-0600 copy for Certbot. For compatibility, a `.ini` path supplied as `cloudflareApiToken` is also treated as a state path, but `cloudflareCredentialsPath` makes the intent explicit. The state ZIP itself still contains the source INI and must be protected as a secret. Prefer function config for new setups so the token is not persisted in the state ZIP.

Supported server aliases are `sectigo`, `sectigo-dv`, `letsencrypt`, `le`, `letsencrypt-staging`, and `le-staging`.

The restore step accepts either zip layout:

- `certbot-state/certTemp/config`, `certbot-state/certTemp/work`, `certbot-state/certTemp/logs`
- root-level `config`, `work`, `logs`

After restore, the function repairs imported Certbot state so it can run inside OCI Functions:

- rewrites `certTemp/config/renewal/*.conf` paths from the machine that created the zip to `/tmp/certbot-state/certTemp/config/...`
- recreates `certTemp/config/live/<lineage>/*.pem` as symlinks to `certTemp/config/archive/<lineage>/*N.pem`

For the payload above, the initial Certbot command is built as:

```sh
certbot certonly --standalone --non-interactive --agree-tos --server https://acme.sectigo.com/v2/DV --domain www.example.com --work-dir certTemp/work --config-dir certTemp/config --logs-dir certTemp/logs
```

The command runs with `/tmp/certbot-state` as its working directory, so the relative `certTemp/...` paths are included in the zip archive that is written back to Object Storage.

Sectigo ACME currently requires External Account Binding. Pass `eabKid` and `eabHmacKey` in the invocation payload, or set `SECTIGO_EAB_KID` and `SECTIGO_EAB_HMAC_KEY` as function config values. The function redacts `--eab-hmac-key` in command logs and error responses.

The default standalone authenticator requires the ACME validation request to reach the function runtime. If that is not how the domain is validated, override `CERTBOT_EXTRA_ARGS` with DNS or another Certbot challenge method.

If Certbot fails, the function response includes `certbotCommand`, `certbotExitCode`, `certbotOutputTail`, `certbotLogTail`, and `stateLayout` so the actual ACME or filesystem error is visible in the invoke result.

## Required Configuration

Provide these as invocation values or OCI Function config values:

| Key | Purpose |
| --- | --- |
| `OCI_BUCKET_NAME` | Bucket that stores the Certbot state archive. Usually supplied as `bucketName` in the invocation payload. |
| `CERTBOT_DOMAIN` | Single certificate domain. Usually supplied as `domain` in the invocation payload. |
| `provider` | `sectigo` (default, standalone) or `cloudflare` (Let's Encrypt with Cloudflare DNS-01). |
| `cloudflareApiToken` | Cloudflare DNS API token for Cloudflare mode. `CLOUDFLARE_API_TOKEN` is the function config fallback. |
| `cloudflareCredentialsPath` | Optional relative path to a Cloudflare token INI file in the restored state ZIP. Overrides `cloudflareApiToken`; `CLOUDFLARE_CREDENTIALS_PATH` is the config fallback. |
| `server` | Optional ACME directory URL or alias. Defaults to Sectigo DV for Sectigo mode or Let's Encrypt production for Cloudflare mode. |
| `ca` | Alias for `server`. |
| `OCI_STATE_OBJECT_NAME` | Optional object name override. Defaults to `<domain>.zip`. |
| `SECTIGO_ACME_SERVER` | Function config fallback for the ACME directory URL. Defaults to `https://acme.sectigo.com/v2/DV`. |
| `eabKid` | Sectigo ACME External Account Binding key identifier supplied in the invocation payload. |
| `eabHmacKey` | Sectigo ACME External Account Binding HMAC key supplied in the invocation payload. |
| `SECTIGO_EAB_KID` | Function config fallback for `eabKid`. |
| `SECTIGO_EAB_HMAC_KEY` | Function config fallback for `eabHmacKey`. |
| `SECTIGO_EAB_REQUIRED` | Set to `false` only if your ACME server does not require EAB. Defaults to `true` for Sectigo URLs and `false` for Let’s Encrypt. |
| `CERTBOT_EMAIL` | Optional email used for Certbot registration and expiry notices. |
| `CERTBOT_DOMAINS` | Optional comma-separated certificate names, for example `example.com,*.example.com`. If omitted, the invocation `domain` is used. |
| `CERTBOT_EXTRA_ARGS` | Optional advanced Certbot args. Not needed for either built-in provider. For Sectigo, supplying an authenticator here replaces `--standalone`. |

Optional values:

| Key | Purpose |
| --- | --- |
| `OCI_NAMESPACE` | Object Storage namespace. If omitted, the function calls `get_namespace`. |
| `OCI_OBJECT_STORAGE_KMS_KEY_ID` | Vault key OCID for server-side encryption of the state archive. |
| `OCI_STATE_MAX_BYTES` | Maximum state archive size, including uncompressed zip/tar contents. Defaults to `52428800`. |
| `OCI_REGION` | Region override. Usually unnecessary in OCI Functions. |
| `OCI_AUTH_MODE` | `resource_principal` by default. Also supports `instance_principal` and `config_file` for local testing. |
| `CERTBOT_CERT_NAME` | Stable Certbot lineage name for initial issuance. |
| `forceRenewal` | Set to `true` in the invocation payload to pass `--force-renewal`. Aliases: `force-renewal`, `force_renewal`. |
| `CERTBOT_FORCE_RENEWAL` | Function config fallback for `forceRenewal`. |
| `CERTBOT_REISSUE` | Set to `true` to run `certonly` again instead of `renew`. |
| `CERTBOT_ISSUE_ARGS` | Extra args only for initial issuance/reissue. |
| `CERTBOT_RENEW_ARGS` | Extra args only for renewals. |
| `CERTBOT_TIMEOUT_SECONDS` | Certbot subprocess timeout. Defaults to `840`. |

## OCI Load Balancer Update

OCI Load Balancer certificate bundle names are unique and immutable. The function therefore does not overwrite a certificate bundle in place. Instead, it creates a new bundle named from a configured prefix plus the SHA-256 fingerprint of the current Certbot public certificate, then updates listeners to use that bundle.

Set these values to enable load balancer updates:

| Key | Purpose |
| --- | --- |
| `loadBalancerOcid` | Load balancer OCID supplied in the invocation payload. |
| `loadBalancerId` | Alias for `loadBalancerOcid`. |
| `loadBalancerOcids` / `loadBalancerIds` | Multiple load balancer OCIDs supplied as a JSON array or comma-separated string. |
| `OCI_LB_ID` | Function config fallback. You can provide multiple OCIDs separated by commas. |
| `OCI_LB_LISTENER_NAMES` | Comma-separated listener names to update. If omitted, all SSL-enabled listeners on the load balancer are updated. |
| `OCI_LB_CERTIFICATE_NAME_PREFIX` | Prefix for generated load balancer certificate bundle names. Defaults to the Certbot lineage name. |
| `OCI_LB_CERTBOT_LINEAGE` | Certbot lineage to publish when multiple lineages exist. Defaults to `CERTBOT_CERT_NAME`, or the only lineage if there is exactly one. |
| `OCI_LB_DELETE_OLD_CERTIFICATES` | Set to `true` to try deleting old certificate bundles after listeners move. Defaults to `false`. |
| `OCI_LB_WAIT_SECONDS` | Maximum wait time for each load balancer work request. Defaults to `300`. |

Ensure the function timeout covers the Certbot timeout plus any load balancer work-request waits.

The function reads these Certbot files from `/tmp/certbot-state/certTemp/config/live/<lineage>`:

| File | OCI Load Balancer field |
| --- | --- |
| `cert.pem` | `public_certificate` |
| `privkey.pem` | `private_key` |
| `chain.pem` | `ca_certificate` |

## OCI DNS-01 Challenge Example

If the domain is hosted in OCI DNS, the included manual hooks can create and remove the `_acme-challenge` TXT record. Setting `CERTBOT_EXTRA_ARGS` replaces the default `--standalone` authenticator.

Set:

```sh
OCI_DNS_ZONE_NAME=example.com
OCI_DNS_PROPAGATION_SECONDS=60
CERTBOT_EXTRA_ARGS="--manual --preferred-challenges dns --manual-auth-hook /function/hooks/oci_dns_auth.py --manual-cleanup-hook /function/hooks/oci_dns_cleanup.py --manual-public-ip-logging-ok"
```

The hooks use the same `OCI_AUTH_MODE` as the function. For a normal OCI Function deployment, use resource principals.

If you use another DNS provider or a Certbot DNS plugin, replace `CERTBOT_EXTRA_ARGS` and add the plugin package to `requirements.txt`.

## IAM

Create a dynamic group for the function, then grant it Object Storage access to the state bucket:

```text
Allow dynamic-group <dynamic-group-name> to read buckets in compartment <compartment-name> where target.bucket.name = '<bucket-name>'
Allow dynamic-group <dynamic-group-name> to manage objects in compartment <compartment-name> where target.bucket.name = '<bucket-name>'
```

If you use the OCI DNS hooks, grant record update access for the hosted zone compartment:

```text
Allow dynamic-group <dynamic-group-name> to use dns-records in compartment <dns-compartment-name>
Allow dynamic-group <dynamic-group-name> to read dns-zones in compartment <dns-compartment-name>
```

If `OCI_OBJECT_STORAGE_KMS_KEY_ID` is set, also grant the function permission to use that Vault key.

If load balancer updates are enabled, grant the function permission to manage load balancers in the load balancer compartment:

```text
Allow dynamic-group <dynamic-group-name> to manage load-balancers in compartment <load-balancer-compartment-name>
```

## Deploy

From this project directory, configure an Fn context for your OCI region and container registry. Replace the example region and placeholder values with your own:

```sh
fn create context certbot-oci --provider oracle
fn use context certbot-oci
fn update context oracle.compartment-id <compartment-ocid>
fn update context api-url https://functions.us-ashburn-1.oci.oraclecloud.com
fn update context registry iad.ocir.io/<tenancy-namespace>/<repository-prefix>
```

Authenticate your container client to OCI Container Registry before deploying. The following commands use the existing OCI Functions application named `certbot`:

```sh
fn deploy --app certbot
fn inspect function certbot certbot-renewal
```

For Cloudflare mode, set the token as function config so it does not need to be included in each invocation:

```sh
fn config function certbot certbot-renewal CLOUDFLARE_API_TOKEN '<zone-scoped-token>'
```

Invoke Cloudflare mode:

```sh
printf '%s' '{"bucketName":"sslcerts","domain":"www.example.com","provider":"cloudflare","email":"admin@example.com","loadBalancerOcid":"<load-balancer-ocid>"}' | fn invoke certbot certbot-renewal
```

For Sectigo mode, configure EAB credentials and invoke with the provider selection:

```sh
fn config function certbot certbot-renewal SECTIGO_EAB_KID '<sectigo-eab-kid>'
fn config function certbot certbot-renewal SECTIGO_EAB_HMAC_KEY '<sectigo-eab-hmac-key>'
printf '%s' '{"bucketName":"sslcerts","domain":"www.example.com","provider":"sectigo","loadBalancerOcid":"<load-balancer-ocid>"}' | fn invoke certbot certbot-renewal
```

To publish later changes, increase `version` in `func.yaml` and rerun `fn deploy --app certbot`. For scheduled renewal, have the scheduler pass the same JSON body; Certbot will skip certificates that are not due unless `forceRenewal` is true. Use separate `stateObjectName` values when both providers issue the same domain.

## Security Notes

- The state archive contains private keys. Restrict bucket access, enable Object Storage retention/versioning as appropriate, and prefer a Vault KMS key.
- The function rejects state archive paths that traverse outside `/tmp/certbot-state`, rejects special files/hard links, and enforces `OCI_STATE_MAX_BYTES`.
- Put the function in a subnet with outbound internet access to reach the Sectigo ACME endpoint and DNS APIs.
- Store Sectigo EAB values as function config only where access is tightly controlled.
- Prefer `CLOUDFLARE_API_TOKEN` function config over sending a token in each invocation; the temporary Cloudflare credentials file is excluded from Object Storage.
- Certbot command output and logs redact `--eab-hmac-key` values before returning error details.
- For production, test once against a non-production certificate profile or limited domain before scheduling unattended renewals.

## References

- OCI Python SDK `patch_rr_set`: https://docs.oracle.com/en-us/iaas/tools/python/latest/api/dns/client/oci.dns.DnsClient.html
- OCI Python SDK `RecordOperation`: https://docs.oracle.com/en-us/iaas/tools/python/latest/api/dns/models/oci.dns.models.RecordOperation.html
- OCI DNS IAM policy resource types: https://docs.oracle.com/iaas/Content/Identity/policyreference/dnspolicyreference.htm
- OCI Python SDK `create_certificate`: https://docs.oracle.com/en-us/iaas/tools/python/latest/api/load_balancer/client/oci.load_balancer.LoadBalancerClient.html
- OCI Python SDK `UpdateListenerDetails`: https://docs.oracle.com/en-us/iaas/tools/python/latest/api/load_balancer/models/oci.load_balancer.models.UpdateListenerDetails.html
- OCI Python SDK `SSLConfigurationDetails`: https://docs.oracle.com/en-us/iaas/tools/python/latest/api/load_balancer/models/oci.load_balancer.models.SSLConfigurationDetails.html
- OCI Load Balancer IAM policy resource types: https://docs.public.content.oci.oraclecloud.com/en-us/iaas/Content/Identity/Reference/lbpolicyreference.htm

## Disclaimer (Sample Code)
ORACLE AND ITS AFFILIATES DO NOT PROVIDE ANY WARRANTY WHATSOEVER, EXPRESS OR IMPLIED, FOR ANY SOFTWARE, MATERIAL OR CONTENT OF ANY KIND CONTAINED OR PRODUCED WITHIN THIS REPOSITORY, AND IN PARTICULAR SPECIFICALLY DISCLAIM ANY AND ALL IMPLIED WARRANTIES OF TITLE, NON-INFRINGEMENT, MERCHANTABILITY, AND FITNESS FOR A PARTICULAR PURPOSE. FURTHERMORE, ORACLE AND ITS AFFILIATES DO NOT REPRESENT THAT ANY CUSTOMARY SECURITY REVIEW HAS BEEN PERFORMED WITH RESPECT TO ANY SOFTWARE, MATERIAL OR CONTENT CONTAINED OR PRODUCED WITHIN THIS REPOSITORY. IN ADDITION, AND WITHOUT LIMITING THE FOREGOING, THIRD PARTIES MAY HAVE POSTED SOFTWARE, MATERIAL OR CONTENT TO THIS REPOSITORY WITHOUT ANY REVIEW. USE AT YOUR OWN RISK. THIS SAMPLE CODE HAS NOT BEEN THOROUGHLY TESTED FOR ACCESSIBILITY.
