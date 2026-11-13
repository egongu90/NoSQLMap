"""Tests for the subnet-iteration logic used by ``nosqlmap.scan``.

``scan.massScan`` iterates a user-supplied subnet with
``ipaddress.ip_network(subnet, strict=False)`` and catches ``ValueError`` for
invalid input. These tests exercise that same pattern.
"""

import ipaddress


def test_subnet_iteration_slash_30():
    ips = [str(ip) for ip in ipaddress.ip_network("192.168.1.0/30", strict=False)]
    assert ips == ["192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.3"]


def test_subnet_iteration_single_host():
    ips = [str(ip) for ip in ipaddress.ip_network("10.0.0.5/32", strict=False)]
    assert ips == ["10.0.0.5"]


def test_subnet_strict_false_allows_host_bits():
    # strict=False permits a non-zero host portion (e.g. 10.0.0.5/24).
    net = ipaddress.ip_network("10.0.0.5/24", strict=False)
    assert str(net.network_address) == "10.0.0.0"
    assert str(net.broadcast_address) == "10.0.0.255"


def test_invalid_subnet_raises_value_error():
    import pytest

    with pytest.raises(ValueError):
        ipaddress.ip_network("not-a-subnet", strict=False)
