from raw2pcap.validate import validate_request, validate_response


def messages(issues, level=None):
    return [i.message for i in issues if level is None or i.level == level]


def test_valid_request_no_issues():
    issues = validate_request("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    assert issues == []


def test_request_missing_host_is_error():
    issues = validate_request("GET / HTTP/1.1\r\nAccept: */*\r\n\r\n")
    errors = messages(issues, "error")
    assert len(errors) == 1
    assert "Host" in errors[0]


def test_blank_line_with_leading_space_is_error():
    text = "POST / HTTP/1.1\r\nHost: example.com\r\n \r\nbody"
    errors = messages(validate_request(text), "error")
    assert any("blank line" in m for m in errors)


def test_blank_line_with_leading_tab_is_error():
    text = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\t\r\nbody"
    errors = messages(validate_response(text), "error")
    assert any("blank line" in m for m in errors)


def test_folded_header_line_is_error():
    text = "GET / HTTP/1.1\r\nHost: example.com\r\n folded-value\r\n\r\n"
    errors = messages(validate_request(text), "error")
    assert any("whitespace" in m for m in errors)


def test_invalid_header_name_is_error():
    text = "GET / HTTP/1.1\r\nHost: example.com\r\nBad Name: v\r\n\r\n"
    errors = messages(validate_request(text), "error")
    assert any("invalid header name" in m for m in errors)


def test_header_without_colon_is_error():
    text = "GET / HTTP/1.1\r\nHost: example.com\r\nnoColonHere\r\n\r\n"
    errors = messages(validate_request(text), "error")
    assert any("no ':'" in m for m in errors)


def test_content_length_mismatch_is_warning():
    text = "HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\nshort"
    issues = validate_response(text)
    warnings = messages(issues, "warning")
    assert any("Content-Length" in m for m in warnings)
    assert messages(issues, "error") == []


def test_content_length_not_a_number_is_error():
    text = "HTTP/1.1 200 OK\r\nContent-Length: abc\r\n\r\nbody"
    errors = messages(validate_response(text), "error")
    assert any("not a number" in m for m in errors)


def test_chunked_transfer_encoding_is_error():
    text = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\nbody"
    errors = messages(validate_response(text), "error")
    assert any("chunked is not supported" in m for m in errors)


def test_chunked_request_is_error():
    text = (
        "POST / HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n4\r\nbody\r\n0\r\n\r\n"
    )
    errors = messages(validate_request(text), "error")
    assert any("chunked is not supported" in m for m in errors)


def test_body_whitespace_lines_not_flagged():
    text = "POST / HTTP/1.1\r\nHost: example.com\r\n\r\nline1\r\n \r\nline2"
    errors = messages(validate_request(text), "error")
    assert not any("blank line" in m for m in errors)
