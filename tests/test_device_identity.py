from types import SimpleNamespace

from sentinel.devices import duplicate_evidence


def device(name, hostname=None, mac=None, addresses=()):
    return SimpleNamespace(
        display_name=name,
        hostname=hostname,
        mac_address=mac,
        addresses=[SimpleNamespace(address=value) for value in addresses],
    )


def test_duplicate_evidence_prioritizes_stable_identifiers():
    confidence, reasons = duplicate_evidence(
        device("NAS", mac="aa:bb:cc:dd:ee:ff"),
        device("Storage", mac="aa:bb:cc:dd:ee:ff"),
    )
    assert confidence == 100
    assert reasons == ["Same MAC address"]


def test_duplicate_evidence_flags_similar_names():
    confidence, reasons = duplicate_evidence(device("Pirate Boat"), device("PirateBoat"))
    assert confidence == 45
    assert reasons == ["Very similar names"]


def test_duplicate_evidence_ignores_unrelated_devices():
    confidence, reasons = duplicate_evidence(device("Router"), device("Bedroom TV"))
    assert confidence == 0
    assert reasons == []
