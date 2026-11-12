from __future__ import annotations

from .conftest import lint

AUTOINDEX = ("NWL002",)


def found(text, only=AUTOINDEX):
    return [(f.rule_id, f.line) for f in lint(text, only=only).findings]


def test_same_line():
    text = "server {\n  autoindex on; # nginx-wp-lint: disable=NWL002\n  autoindex on;\n}\n"
    assert found(text) == [("NWL002", 3)]


def test_by_rule_name_and_all():
    text = ("server {\n  autoindex on; # nginx-wp-lint: disable=autoindex-on\n"
            "  autoindex on; # nginx-wp-lint: disable=all\n}\n")
    assert found(text) == []


def test_disable_line_alias():
    assert found("autoindex on; # nginx-wp-lint: disable-line NWL002\n") == []


def test_next_line_skips_comments_and_blank_lines():
    text = ("server {\n  # nginx-wp-lint: disable-next-line=NWL002\n\n  # another\n"
            "  autoindex on;\n  autoindex on;\n}\n")
    assert found(text) == [("NWL002", 6)]


def test_block_range_until_end_of_block():
    text = ("server {\n  location /a/ {\n    # nginx-wp-lint: disable=NWL002\n"
            "    autoindex on;\n  }\n  autoindex on;\n}\n")
    assert found(text) == [("NWL002", 6)]


def test_enable_ends_range():
    text = ("# nginx-wp-lint: disable=NWL002\nautoindex on;\n# nginx-wp-lint: enable=NWL002\n"
            "autoindex on;\n")
    assert found(text) == [("NWL002", 4)]


def test_first_in_block_covers_block_line():
    text = "server {\n    # nginx-wp-lint: disable=NWL001\n    listen 80;\n}\n"
    assert found(text, only=("NWL001",)) == []
    text2 = "server {\n    listen 80;\n    # nginx-wp-lint: disable=NWL001\n}\n"
    assert found(text2, only=("NWL001",)) == [("NWL001", 1)]


def test_disable_file():
    text = "autoindex on;\n# nginx-wp-lint: disable-file=NWL002\nautoindex on;\n"
    assert found(text) == []


def test_unknown_rule_in_comment_warns():
    result = lint("autoindex on; # nginx-wp-lint: disable=NWL999\n", only=AUTOINDEX)
    assert result.warnings and "NWL999" in result.warnings[0]
    assert len(result.findings) == 1


def test_ordinary_comments_ignored():
    assert found("autoindex on; # disable=NWL002 is not our syntax\n") == [("NWL002", 1)]


def test_suppressed_counter():
    result = lint("autoindex on; # nginx-wp-lint: disable=NWL002\n", only=AUTOINDEX)
    assert result.suppressed == 1
