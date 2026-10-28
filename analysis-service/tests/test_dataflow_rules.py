from pathlib import Path
import pytest
from app.services.semgrep_service import SemgrepScanner


@pytest.fixture(scope="module")
def scanner():
    return SemgrepScanner(Path(__file__).resolve().parents[1] / "rules")


@pytest.mark.parametrize("language,source,rule", [
    ("php", '<?php $name = $_GET["name"]; $query = "SELECT * FROM users WHERE name=" . $name; mysqli_query($db, $query);', "php-request-to-sql-dataflow"),
    ("php", '<?php $host = $_POST["host"]; $cmd = "ping " . $host; shell_exec($cmd);', "php-request-to-command-dataflow"),
    ("python", 'import os\nhost = request.args.get("host")\ncommand = "ping " + host\nos.system(command)\n', "python-request-to-shell-dataflow"),
    ("javascript", 'const host = req.query.host; const command = "ping " + host; child_process.exec(command);', "javascript-request-to-shell-dataflow"),
])
def test_tracks_input_through_intermediate_variables(scanner, language, source, rule):
    findings = scanner.scan_code(source, language)
    assert any(finding["rule_id"].endswith(rule) for finding in findings)


def test_parameterized_sql_is_not_a_dataflow_sink(scanner):
    source = '<?php $name = $_GET["name"]; $statement = $db->prepare("SELECT * FROM users WHERE name=?"); $statement->execute([$name]);'
    assert not any("php-request-to-sql-dataflow" in f["rule_id"] for f in scanner.scan_code(source, "php"))
