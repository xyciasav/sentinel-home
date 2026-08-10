from sentinel.vulnerabilities import fixed_version, osv_ecosystem, osv_severity


def test_osv_ecosystem_requires_supported_distro_identity() -> None:
    assert osv_ecosystem("debian", "12.5") == "Debian:12"
    assert osv_ecosystem("ubuntu", "24.04") == "Ubuntu:24.04:LTS"
    assert osv_ecosystem("ubuntu", "25.10") == "Ubuntu:25.10"
    assert osv_ecosystem("raspbian", "12") is None


def test_osv_advisory_normalization_extracts_fix_and_severity() -> None:
    advisory = {
        "database_specific": {"severity": "high"},
        "affected": [
            {
                "package": {"ecosystem": "Debian:12", "name": "openssl"},
                "ranges": [{"events": [{"introduced": "0"}, {"fixed": "3.0.17-1"}]}],
            }
        ],
    }

    assert osv_severity(advisory) == "high"
    assert fixed_version(advisory, "Debian:12", "openssl") == "3.0.17-1"
