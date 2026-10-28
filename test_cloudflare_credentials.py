# Copyright (c) 2026, Oracle OCI Certbot contributors
# Licensed under the Universal Permissive License v 1.0 as shown at
# https://oss.oracle.com/licenses/upl/
# SPDX-License-Identifier: UPL-1.0

import io
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import func


class CloudflareCredentialsTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        root = Path(self.temporary_directory.name)
        self.state_root = root / "state"
        self.state_root.mkdir()
        self.credentials_file = root / "secrets" / "cloudflare.ini"
        state_patch = patch.object(func, "STATE_ROOT", self.state_root)
        credentials_patch = patch.object(func, "CLOUDFLARE_CREDENTIALS", self.credentials_file)
        state_patch.start()
        credentials_patch.start()
        self.addCleanup(state_patch.stop)
        self.addCleanup(credentials_patch.stop)

    def _config(self, token=None, path=None):
        return SimpleNamespace(
            provider="cloudflare",
            cloudflare_api_token=token,
            cloudflare_credentials_path=path,
        )

    def test_direct_token(self):
        token = func._prepare_cloudflare_credentials(self._config(token="direct-token"))
        self.assertEqual(token, "direct-token")
        self.assertEqual(
            self.credentials_file.read_text(), "dns_cloudflare_api_token = direct-token\n"
        )
        self.assertEqual(stat.S_IMODE(self.credentials_file.stat().st_mode), 0o600)

    def test_config_loads_credentials_path(self):
        config = func._load_config(
            {
                "bucketName": "sslcerts",
                "domain": "cloudbom.scott-herman.com",
                "provider": "cloudflare",
                "cloudflareCredentialsPath": "certCloudbom/cloudflare/token.ini",
            }
        )
        self.assertEqual(
            config.cloudflare_credentials_path, "certCloudbom/cloudflare/token.ini"
        )

    def test_credential_path_in_state(self):
        source = self.state_root / "certCloudbom" / "cloudflare" / "token.ini"
        source.parent.mkdir(parents=True)
        source.write_text("dns_cloudflare_api_token = archived-token\n")
        token = func._prepare_cloudflare_credentials(
            self._config(path="certCloudbom/cloudflare/token.ini")
        )
        self.assertEqual(token, "archived-token")
        self.assertIn("archived-token", self.credentials_file.read_text())

    def test_legacy_path_in_token_field(self):
        source = self.state_root / "cloudflare.ini"
        source.write_text("dns_cloudflare_api_token = archived-token\n")
        token = func._prepare_cloudflare_credentials(
            self._config(token="cloudflare.ini")
        )
        self.assertEqual(token, "archived-token")

    def test_credentials_are_read_after_zip_restore(self):
        archive_bytes = io.BytesIO()
        with zipfile.ZipFile(archive_bytes, "w") as archive:
            archive.writestr(
                "certCloudbom/cloudflare/cloudbom.scott-herman.com.ini",
                "dns_cloudflare_api_token = restored-token\n",
            )
        func._extract_state_zip(archive_bytes.getvalue())
        token = func._prepare_cloudflare_credentials(
            self._config(
                token="certCloudbom/cloudflare/cloudbom.scott-herman.com.ini"
            )
        )
        self.assertEqual(token, "restored-token")

    def test_rejects_unsafe_paths(self):
        for path in ("../token.ini", "/tmp/token.ini", "dir\\token.ini"):
            with self.subTest(path=path):
                with self.assertRaises(ValueError):
                    func._prepare_cloudflare_credentials(self._config(path=path))

    def test_rejects_symlink(self):
        outside = Path(self.temporary_directory.name) / "outside.ini"
        outside.write_text("dns_cloudflare_api_token = secret\n")
        (self.state_root / "link.ini").symlink_to(outside)
        with self.assertRaises(ValueError):
            func._prepare_cloudflare_credentials(self._config(path="link.ini"))

    def test_invalid_ini_does_not_echo_token(self):
        source = self.state_root / "broken.ini"
        source.write_text("secret-token-without-key\n")
        with self.assertRaises(ValueError) as error:
            func._prepare_cloudflare_credentials(self._config(path="broken.ini"))
        self.assertNotIn("secret-token", str(error.exception))


if __name__ == "__main__":
    unittest.main()
