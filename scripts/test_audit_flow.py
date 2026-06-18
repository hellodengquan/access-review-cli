#!/usr/bin/env python3
import subprocess
import os
import json
import glob
import shutil

HOME = '/tmp/test_audit_z'
shutil.rmtree(HOME, ignore_errors=True)
os.makedirs(HOME + '/audit', exist_ok=True)

env = os.environ.copy()
env['ACCESS_REVIEW_OPERATOR'] = 'auditor_zhang'
env['ACCESS_REVIEW_HOME'] = HOME

def run(*args, check=True):
    print(f'\n$ {" ".join(args)}')
    r = subprocess.run(args, env=env, capture_output=True, text=True)
    if r.stdout.strip():
        print(r.stdout.rstrip())
    if r.stderr.strip():
        print('[stderr]:', r.stderr.rstrip())
    print(f'[exit={r.returncode}]')
    if check and r.returncode != 0:
        raise RuntimeError(f'命令失败: {args}')
    return r

print('=' * 70)
print('步骤1: import')
print('=' * 70)
run('python', '-m', 'access_review.cli', 'permission', 'import', '/tmp/test_cross_ou.json')

print('\n' + '=' * 70)
print('步骤2: stats')
print('=' * 70)
run('python', '-m', 'access_review.cli', 'stats')

print('\n' + '=' * 70)
print('步骤3: anomaly detect')
print('=' * 70)
run('python', '-m', 'access_review.cli', 'anomaly', 'detect', '--unused-days', '90')

print('\n' + '=' * 70)
print('步骤4: report aggregate (CSV/Excel)')
print('=' * 70)
run('python', '-m', 'access_review.cli', 'report', 'aggregate', '-g', 'user', '-f', 'csv', '-o', '/tmp/r1.csv')
run('python', '-m', 'access_review.cli', 'report', 'aggregate', '-g', 'role', '-f', 'excel', '-o', '/tmp/r1.xlsx')

print('\n' + '=' * 70)
print('步骤5: 失败参数测试 (参数非法导致退出)')
print('=' * 70)
r = run('python', '-m', 'access_review.cli', 'anomaly', 'detect', '--unused-days', '-7', check=False)
assert r.returncode == 1, f'应失败退出，实际退出码: {r.returncode}'
print('✅ 失败退出码正确 (非零)')

print('\n' + '=' * 70)
print('步骤6: 查看审计日志列表')
print('=' * 70)
run('python', '-m', 'access_review.cli', 'audit', 'list', '-n', '50')

print('\n' + '=' * 70)
print('步骤7: 检查日志文件原始内容 (started + success/failure)')
print('=' * 70)
files = sorted(glob.glob(f'{HOME}/audit/*.jsonl'))
for fp in files:
    print(f'文件: {fp}')
    with open(fp) as fh:
        lines = [l.strip() for l in fh if l.strip()]
    print(f'总条数: {len(lines)}')
    status_counter = {}
    actions = []
    for i, line in enumerate(lines):
        e = json.loads(line)
        status = e.get('status', '?')
        action = e.get('action', '?')
        status_counter[status] = status_counter.get(status, 0) + 1
        actions.append((i + 1, action, status, e.get('command', '')[:60], e.get('params') or {}))
    print(f'状态分布: {status_counter}')
    print('各条记录:')
    for idx, act, st, cmd, params in actions:
        param_str = ', '.join(f'{k}={v}' for k, v in params.items())
        if not param_str:
            param_str = '(无参数)'
        print(f'  #{idx:02d} | {act:15s} | {st:10s} | cmd={cmd[:50]}')
        print(f'       | params: {param_str}')
    print()

    # 验证关键断言
    assert 'started' in status_counter, '缺少 started 状态'
    assert 'success' in status_counter, '缺少 success 状态'
    assert status_counter.get('failure', 0) >= 1, '缺少 failure 状态（应该有 --unused-days=-7 失败）'
    assert status_counter.get('success', 0) >= 5, 'success 记录太少'
    print('✅ 审计日志状态断言通过')

print('\n✅ 所有测试通过！')
