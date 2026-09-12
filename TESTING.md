# Batch testing / 批量测试

All fixtures are local and deterministic. Tests inspect fixture text; they never execute the scripts being scanned or contact their URLs. Dependency installation and GitHub CI require network access. This suite tests known examples and generated inputs, not detection accuracy on a labeled real-world corpus.

全部夹具均为本地确定性数据。测试只检查文本，不执行被扫描的脚本，也不访问其中的 URL。依赖安装和 GitHub CI 需要联网。本测试集验证已知样例和生成数据，不代表真实恶意技能语料上的检测准确率。

## Run the full suite

From an activated Python 3.11+ environment in the repository:

```bash
python -m pip install -e ".[dev]"
python -m pytest --cov=skillguard --cov-report=term-missing --cov-report=xml --junitxml=test-results.xml
python -m ruff check src tests scripts
python -m mypy
python scripts/smoke_test.py
python -m build
```

PowerShell without activating the virtual environment, with fresh workspace-local scratch space:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
New-Item -ItemType Directory -Path .skillguard -Force | Out-Null
$testScratch = ".skillguard/tmp-" + [guid]::NewGuid().ToString('N')
.\.venv\Scripts\python.exe -m pytest --basetemp=$testScratch -o cache_dir=.skillguard/pytest-cache --cov=skillguard --cov-report=term-missing --cov-report=xml:.skillguard/coverage.xml --junitxml=.skillguard/test-results.xml
.\.venv\Scripts\python.exe -m ruff check src tests scripts
.\.venv\Scripts\python.exe -m mypy
.\.venv\Scripts\python.exe scripts/smoke_test.py
.\.venv\Scripts\python.exe -m build
```

`--basetemp` is disposable: pytest can delete an existing directory passed there. Use a fresh scratch path, never a source or data directory. `.skillguard/` is ignored by Git and directory discovery.

`--basetemp` 是可清理的测试临时目录：pytest 可以删除该参数指定的已有目录。请使用新临时路径，不要指向源码或数据目录。`.skillguard/` 已被 Git 和扫描器目录发现逻辑排除。

## Test groups

| Group | Checks |
|-------|--------|
| Existing rule and CLI regressions | Prompt injection, secrets, execution, quality, discovery, filters, JSON and SARIF |
| Host CLI matrix | 9 host paths × 3 layouts × 3 payload classes × 4 thresholds × 3 formats × 2 languages = 1,944 cases |
| Config matrix | 6 filenames × 5 precedence combinations × 3 formats = 90 cases |
| Large files | SG305 for each host format and a subprocess deadline for long-identifier scanning |
| Token-query regression | Plain/prefixed credential identifiers, all four token names, both query orders |
| Invalid options | Exit 2 across text, JSON and SARIF |
| Bulk repository | 1,000 outer skills + 10 inner skills, 4,019 scanned files, exactly 2,009 expected findings, no duplicates, stable JSON/SARIF |
| Installed CLI | 12 subprocess checks: version, two rules languages, three examples × three formats |

The bulk corpus also contains excluded `.git`, virtualenv, dependency, build and hidden-directory files, plus unrelated root scripts and host cache/workflow files. These must not affect expected counts. No elapsed-time SLA is asserted for the bulk test; the scanner-hang regression has a 20-second subprocess timeout.

批量语料还包含应排除的 Git、虚拟环境、依赖、构建和隐藏目录，以及包外无关脚本和宿主缓存／工作流文件。它们不能改变预期扫描数量。千包测试不设性能达标线；扫描卡顿回归在独立子进程中设置 20 秒超时。

Run selected groups:

```bash
python -m pytest tests/test_batch.py
python -m pytest -m bulk --durations=5
python -m pytest -m "not bulk"
```

## CI and evidence

[CI](https://github.com/652036/skillguard/actions/workflows/ci.yml) runs the full suite and subprocess checks on Ubuntu and Windows with Python 3.11, 3.12, 3.13 and 3.14. Separate jobs enforce lint/types and build a source distribution plus wheel. The package job installs the wheel and runs the same subprocess checks outside the checkout. This distinguishes an editable source install from an installable distribution.

Each matrix job uploads `test-results.xml` and `coverage.xml`; the package job uploads distributions. Match an Actions run to its commit SHA before treating it as evidence. A configured matrix is not a completed test run. Local results are under `.skillguard/` when using the PowerShell commands above.

CI 在两个操作系统、四个 Python 版本上执行全套测试；独立任务检查 lint／类型并构建源码包和 wheel。wheel 安装后会在仓库外执行 CLI 检查。请核对 Actions 运行对应的提交 SHA；已配置矩阵不等于所有测试已经通过。本地 PowerShell 命令将报告保存至 `.skillguard/`。
