#!/usr/bin/env python3
"""测试 CLI 参数校验测试脚本"""
import os
import sys
import shutil
from pathlib import Path
from typer.testing import CliRunner

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from access_review.cli import app


def run_test(name, args, expected_exit_code, env_home=None):
    print(f"\n{'='*60}")
    print(f"测试: {name}")
    print(f"参数: {args}")
    print(f"{'='*60}")
    runner = CliRunner(env={"ACCESS_REVIEW_HOME": env_home} if env_home else None)
    result = runner.invoke(app, args)
    print(result.output)
    if result.exception and not isinstance(result.exception, SystemExit):
        import traceback
        traceback.print_exception(type(result.exception), result.exception, result.exception.__traceback__)
    print(f"退出码: {result.exit_code} (期望: {expected_exit_code})")
    passed = result.exit_code == expected_exit_code
    print(f"结果: {'通过' if passed else '失败'}")
    return passed


def main():
    all_passed = True
    TEST_HOME = "/tmp/test_access_review_cli"
    SAMPLE_DATA = Path(__file__).parent.parent / "sample_data.json"

    if os.path.exists(TEST_HOME):
        shutil.rmtree(TEST_HOME)

    run_test(
        "初始化数据目录",
        ["init"],
        0,
        TEST_HOME
    )

    run_test(
        "导入示例数据",
        ["permission", "import", str(SAMPLE_DATA)],
        0,
        TEST_HOME
    )

    all_passed &= run_test(
        "unused_days=-7 (负数，应失败)",
        ["anomaly", "detect", "--unused-days", "-7"],
        1,
        TEST_HOME
    )

    all_passed &= run_test(
        "unused_days=0 (零，应失败)",
        ["anomaly", "detect", "--unused-days", "0"],
        1,
        TEST_HOME
    )

    all_passed &= run_test(
        "unused_days=2000 (超过最大值，应失败)",
        ["anomaly", "detect", "--unused-days", "2000"],
        1,
        TEST_HOME
    )

    all_passed &= run_test(
        "unused_days=90 (正常，应通过)",
        ["anomaly", "detect", "--unused-days", "90"],
        0,
        TEST_HOME
    )

    all_passed &= run_test(
        "severity=HIGH (大写，应通过)",
        ["anomaly", "list", "--severity", "HIGH"],
        0,
        TEST_HOME
    )

    all_passed &= run_test(
        "severity=High (混合大小写，应通过)",
        ["anomaly", "list", "--severity", "High"],
        0,
        TEST_HOME
    )

    all_passed &= run_test(
        "severity=hig (拼写错误，应失败)",
        ["anomaly", "list", "--severity", "hig"],
        1,
        TEST_HOME
    )

    all_passed &= run_test(
        "severity=INVALID (非法，应失败)",
        ["anomaly", "list", "--severity", "INVALID"],
        1,
        TEST_HOME
    )

    all_passed &= run_test(
        "status=ACTIVE (大写，应通过)",
        ["permission", "list", "--status", "ACTIVE"],
        0,
        TEST_HOME
    )

    all_passed &= run_test(
        "status=Expired (混合，应通过)",
        ["permission", "list", "--status", "Expired"],
        0,
        TEST_HOME
    )

    all_passed &= run_test(
        "status=invalid (非法，应失败)",
        ["permission", "list", "--status", "invalid"],
        1,
        TEST_HOME
    )

    all_passed &= run_test(
        "type=expired_access (正常，应通过)",
        ["anomaly", "list", "--type", "expired_access"],
        0,
        TEST_HOME
    )

    all_passed &= run_test(
        "type=EXPIRED_ACCESS (大写，应通过)",
        ["anomaly", "list", "--type", "EXPIRED_ACCESS"],
        0,
        TEST_HOME
    )

    all_passed &= run_test(
        "type=invalid_type (非法，应失败)",
        ["anomaly", "list", "--type", "invalid_type"],
        1,
        TEST_HOME
    )

    all_passed &= run_test(
        "export --type=INVALID (非法，应失败)",
        ["permission", "export", "--type", "INVALID", "/tmp/out.json"],
        1,
        TEST_HOME
    )

    all_passed &= run_test(
        "export --format=xml (非法，应失败)",
        ["permission", "export", "--format", "xml", "/tmp/out.json"],
        1,
        TEST_HOME
    )

    all_passed &= run_test(
        "export --type=permissions (合法，应通过)",
        ["permission", "export", "--type", "permissions", "/tmp/out.json"],
        0,
        TEST_HOME
    )

    all_passed &= run_test(
        "quarterly quarter=Q5 (非法，应失败)",
        ["quarterly", "test", "Q5", "2024", "--reviewer", "tester", "--unused-days", "-7"],
        1,
        TEST_HOME
    )

    print(f"\n\n{'='*60}")
    if all_passed:
        print("✅ 所有测试通过！")
    else:
        print("❌ 部分测试失败！")
    print(f"{'='*60}")
    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()
