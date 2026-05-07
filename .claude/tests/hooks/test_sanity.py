"""Sanity: both guards are importable as subprocesses and respond to stdin."""


def test_bash_guard_responds_to_ls(run_bash_guard):
    result = run_bash_guard("ls")
    assert result.exit_code == 0, f"ls blocked? stderr: {result.stderr}"


def test_file_guard_responds_to_output_read(run_file_guard):
    result = run_file_guard("Read", ".claude/output/audit.jsonl")
    assert result.exit_code == 0, f"read of audit.jsonl blocked? stderr: {result.stderr}"
