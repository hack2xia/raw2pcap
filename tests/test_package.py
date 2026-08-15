from raw2pcap import __version__


def test_package_has_version():
    assert isinstance(__version__, str)
    assert __version__
