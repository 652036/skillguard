from __future__ import annotations

from pathlib import Path

from skillguard.rules.secrets import check_sg101, check_sg102, check_sg103, check_sg104, check_sg105


def test_aws_key_true_positive() -> None:
    assert check_sg101(Path("x.md"), "key=AKIA1234567890NOTRL1\n")


def test_aws_key_true_negative() -> None:
    assert check_sg101(Path("x.md"), "key=AKIA_TOO_SHORT\n") == []


def test_vendor_tokens_true_positive() -> None:
    text = "\n".join(
        [
            "sk-proj-DemonstrablyFakeKeyNotReal0001",
            "sk-ant-api03-DemonstrablyFakeKeyNotReal",
            "ghp_000000000000000000000000000000000000",
        ]
    )
    assert len(check_sg102(Path("x.md"), text)) >= 3


def test_generic_assignment_true_positive() -> None:
    assert check_sg103(Path("x.py"), 'api_key = "sk_live_demo_not_real_xx"\n')


def test_generic_assignment_env_lookup_negative() -> None:
    assert check_sg103(Path("x.py"), 'api_key = os.environ["API_KEY"]\n') == []
    assert check_sg103(Path("x.py"), 'api_key = "changeme"\n') == []


def test_pem_true_positive() -> None:
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----\n"
    assert check_sg104(Path("key.pem"), text)


def test_pem_certificate_negative() -> None:
    text = "-----BEGIN CERTIFICATE-----\nMIIE\n-----END CERTIFICATE-----\n"
    assert check_sg104(Path("cert.pem"), text) == []


def test_env_file_true_positive() -> None:
    text = "OPENAI_API_KEY=sk-proj-DemonstrablyFakeKeyNotReal0001\n"
    assert check_sg105(Path(".env"), text)


def test_env_example_placeholder_negative() -> None:
    text = "OPENAI_API_KEY=your-key-here\nDEBUG=true\n"
    assert check_sg105(Path(".env.example"), text) == []


def test_aws_docs_example_key_negative() -> None:
    assert check_sg101(Path("x.md"), "key=AKIAIOSFODNN7EXAMPLE\n") == []


def test_env_example_hf_placeholder_negative() -> None:
    text = "HF_TOKEN=hf_xxxxxxxxxxxxxxxxxxxxxxxxxxxxx\nOPENAI_API_KEY=your-api-key-here\n"
    assert check_sg105(Path(".env.example"), text) == []
    assert check_sg105(Path(".env.sample"), text) == []
