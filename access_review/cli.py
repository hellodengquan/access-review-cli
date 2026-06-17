import os
import json
from datetime import datetime
from pathlib import Path
from typing import Optional, List
from dateutil import parser as date_parser

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import print as rprint

from . import __version__
from .storage import Storage
from .models import (
    UserPermission,
    ReviewRecord,
    ReviewResult,
    ReviewCycle,
    PermissionStatus,
    AnomalyType,
)
from .anomaly_detector import AnomalyDetector
from .report_generator import ReportGenerator

app = typer.Typer(
    help="权限复核辅助命令行工具 - 帮助安全团队进行用户权限审计、复核和异常检测",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()


def get_storage() -> Storage:
    base_dir = os.environ.get("ACCESS_REVIEW_HOME")
    if base_dir:
        return Storage(Path(base_dir))
    return Storage()


@app.command()
def version():
    """显示版本信息"""
    console.print(f"[bold green]access-review[/bold green] v{__version__}")


@app.command()
def init():
    """初始化数据目录"""
    storage = get_storage()
    console.print(f"[green]✓[/green] 数据目录已初始化: {storage.base_dir}")
    rprint(Panel.fit(
        "数据目录结构:\n"
        f"  {storage.data_dir}/permissions/ - 用户权限数据\n"
        f"  {storage.data_dir}/reviews/     - 复核记录\n"
        f"  {storage.data_dir}/anomalies/   - 异常报告\n"
        f"  {storage.data_dir}/cycles/      - 复核周期\n",
        title="初始化完成",
        border_style="green"
    ))


@app.command()
def stats():
    """查看系统统计信息"""
    storage = get_storage()
    stats_data = storage.get_stats()

    table = Table(title="系统统计", show_header=False, box=None)
    table.add_column("项目", style="cyan")
    table.add_column("数值", style="bold")

    table.add_row("总权限数", str(stats_data["total_permissions"]))
    table.add_row("  活跃权限", str(stats_data["active_permissions"]))
    table.add_row("  已过期", f"[yellow]{stats_data['expired_permissions']}[/yellow]")
    table.add_row("  已收回", f"[red]{stats_data['revoked_permissions']}[/red]")
    table.add_row("  待复核", f"[blue]{stats_data['pending_review']}[/blue]")
    table.add_row("总复核记录", str(stats_data["total_reviews"]))
    table.add_row("总异常数", str(stats_data["total_anomalies"]))
    table.add_row("  未解决", f"[red]{stats_data['unresolved_anomalies']}[/red]")
    table.add_row("总复核周期", str(stats_data["total_cycles"]))
    table.add_row("  进行中", f"[green]{stats_data['active_cycles']}[/green]")

    console.print(table)


permission_app = typer.Typer(help="用户权限清单管理")
app.add_typer(permission_app, name="permission")


@permission_app.command("import")
def import_permissions(
    file_path: Path = typer.Argument(..., help="JSON 文件路径"),
    overwrite: bool = typer.Option(False, "--overwrite", "-o", help="是否覆盖已存在的记录"),
):
    """从 JSON 文件导入用户权限清单"""
    storage = get_storage()
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("正在导入权限数据...", total=None)
        try:
            counts = storage.import_from_json(file_path, overwrite=overwrite)
            progress.update(task, completed=True)
        except Exception as e:
            console.print(f"[red]✗[/red] 导入失败: {e}")
            raise typer.Exit(1)

    console.print("[green]✓[/green] 导入完成:")
    for key, value in counts.items():
        if value > 0:
            console.print(f"  - {key}: {value} 条")


@permission_app.command("export")
def export_permissions(
    output_path: Path = typer.Argument(..., help="导出文件路径"),
    data_type: Optional[str] = typer.Option(None, "--type", "-t", help="数据类型: permissions/reviews/anomalies/cycles"),
    format: str = typer.Option("json", "--format", "-f", help="导出格式: json/csv"),
):
    """导出权限数据到文件"""
    storage = get_storage()
    report_gen = ReportGenerator(storage)

    if format == "csv":
        if data_type == "permissions" or data_type is None:
            count = report_gen.export_permission_list_csv(output_path)
            console.print(f"[green]✓[/green] 已导出 {count} 条权限记录到 {output_path}")
        else:
            console.print(f"[red]✗[/red] CSV 格式仅支持 permissions 类型")
            raise typer.Exit(1)
    else:
        storage.export_to_json(output_path, data_type)
        type_str = data_type or "全部"
        console.print(f"[green]✓[/green] 已导出 {type_str} 数据到 {output_path}")


@permission_app.command("list")
def list_permissions(
    status: Optional[str] = typer.Option(None, "--status", "-s", help="按状态筛选: active/expired/revoked/pending_review"),
    department: Optional[str] = typer.Option(None, "--dept", "-d", help="按部门筛选"),
    username: Optional[str] = typer.Option(None, "--user", "-u", help="按用户名筛选"),
    limit: int = typer.Option(50, "--limit", "-n", help="显示条数"),
):
    """列出用户权限清单"""
    storage = get_storage()
    permissions = storage.list_permissions()

    if status:
        permissions = [p for p in permissions if p.status == status]
    if department:
        permissions = [p for p in permissions if department.lower() in p.department.lower()]
    if username:
        permissions = [p for p in permissions if username.lower() in p.username.lower()]

    if not permissions:
        console.print("[yellow]![/yellow] 没有找到匹配的权限记录")
        return

    permissions = permissions[:limit]

    table = Table(title=f"权限清单 (共 {len(permissions)} 条)")
    table.add_column("ID", style="dim", no_wrap=True)
    table.add_column("用户名", style="cyan")
    table.add_column("部门", style="magenta")
    table.add_column("角色", style="yellow")
    table.add_column("资源", style="green")
    table.add_column("权限级别", style="blue")
    table.add_column("授予日期", style="dim")
    table.add_column("最后使用", style="dim")
    table.add_column("状态", style="bold")

    for p in permissions:
        status_val = p.status.value if hasattr(p.status, 'value') else str(p.status)
        status_style = {
            "active": "green",
            "expired": "yellow",
            "revoked": "red",
            "pending_review": "blue",
        }.get(status_val, "white")

        last_used = p.last_used_date.strftime("%Y-%m-%d") if p.last_used_date else "-"

        table.add_row(
            p.id[:8],
            p.username,
            p.department,
            p.role,
            p.resource,
            p.permission_level,
            p.granted_date.strftime("%Y-%m-%d"),
            last_used,
            f"[{status_style}]{status_val}[/{status_style}]",
        )

    console.print(table)


@permission_app.command("add")
def add_permission(
    username: str = typer.Option(..., help="用户名"),
    email: str = typer.Option(..., help="邮箱"),
    department: str = typer.Option(..., help="部门"),
    role: str = typer.Option(..., help="角色"),
    resource: str = typer.Option(..., help="资源"),
    permission_level: str = typer.Option(..., help="权限级别: read/write/admin"),
    granted_date: str = typer.Option(None, help="授予日期 (YYYY-MM-DD)"),
    last_used_date: str = typer.Option(None, help="最后使用日期"),
    expiry_date: str = typer.Option(None, help="过期日期"),
    granted_by: str = typer.Option(None, help="授权人"),
    description: str = typer.Option(None, help="描述"),
):
    """添加单条用户权限"""
    storage = get_storage()

    def parse_date(date_str: Optional[str]) -> Optional[datetime]:
        if not date_str:
            return None
        try:
            return date_parser.parse(date_str)
        except Exception:
            console.print(f"[red]✗[/red] 日期格式错误: {date_str}")
            raise typer.Exit(1)

    perm = UserPermission(
        id=Storage.generate_id(),
        username=username,
        email=email,
        department=department,
        role=role,
        resource=resource,
        permission_level=permission_level,
        granted_date=parse_date(granted_date) or datetime.now(),
        last_used_date=parse_date(last_used_date),
        expiry_date=parse_date(expiry_date),
        granted_by=granted_by,
        description=description,
    )

    storage.save_permission(perm)
    console.print(f"[green]✓[/green] 权限已添加，ID: {perm.id}")


@permission_app.command("show")
def show_permission(
    permission_id: str = typer.Argument(..., help="权限 ID"),
):
    """查看权限详情"""
    storage = get_storage()
    perm = storage.load_permission(permission_id)
    if not perm:
        console.print(f"[red]✗[/red] 未找到权限记录: {permission_id}")
        raise typer.Exit(1)

    reviews = storage.get_reviews_for_permission(permission_id)
    anomalies = storage.get_anomalies_for_permission(permission_id)

    status_val = perm.status.value if hasattr(perm.status, 'value') else str(perm.status)
    console.print(Panel.fit(
        f"[bold cyan]用户名:[/bold cyan] {perm.username}\n"
        f"[bold cyan]邮箱:[/bold cyan] {perm.email}\n"
        f"[bold cyan]部门:[/bold cyan] {perm.department}\n"
        f"[bold cyan]角色:[/bold cyan] {perm.role}\n"
        f"[bold cyan]资源:[/bold cyan] {perm.resource}\n"
        f"[bold cyan]权限级别:[/bold cyan] {perm.permission_level}\n"
        f"[bold cyan]授予日期:[/bold cyan] {perm.granted_date.strftime('%Y-%m-%d')}\n"
        f"[bold cyan]最后使用:[/bold cyan] {perm.last_used_date.strftime('%Y-%m-%d') if perm.last_used_date else '-'} \n"
        f"[bold cyan]过期日期:[/bold cyan] {perm.expiry_date.strftime('%Y-%m-%d') if perm.expiry_date else '-'} \n"
        f"[bold cyan]状态:[/bold cyan] {status_val}\n"
        f"[bold cyan]授权人:[/bold cyan] {perm.granted_by or '-'}\n"
        f"[bold cyan]描述:[/bold cyan] {perm.description or '-'}\n"
        f"[bold cyan]标签:[/bold cyan] {', '.join(perm.tags) if perm.tags else '-'}\n",
        title=f"权限详情 - {perm.id}",
        border_style="cyan"
    ))

    if reviews:
        rev_table = Table(title="复核记录", show_lines=True)
        rev_table.add_column("日期", style="dim")
        rev_table.add_column("复核人", style="cyan")
        rev_table.add_column("结果", style="bold")
        rev_table.add_column("备注", style="dim")
        for r in reviews:
            result_val = r.result.value if hasattr(r.result, 'value') else str(r.result)
            result_style = {
                "approved": "green",
                "revoke_recommended": "red",
                "escalated": "yellow",
                "pending": "blue",
            }.get(result_val, "white")
            rev_table.add_row(
                r.review_date.strftime("%Y-%m-%d"),
                r.reviewer,
                f"[{result_style}]{result_val}[/{result_style}]",
                r.comments or "-",
            )
        console.print(rev_table)

    if anomalies:
        anom_table = Table(title="异常报告", show_lines=True)
        anom_table.add_column("类型", style="red")
        anom_table.add_column("严重度", style="bold")
        anom_table.add_column("描述", style="dim")
        anom_table.add_column("状态", style="bold")
        for a in anomalies:
            anomaly_type_val = a.anomaly_type.value if hasattr(a.anomaly_type, 'value') else str(a.anomaly_type)
            sev_val = a.severity.value if hasattr(a.severity, 'value') else str(a.severity)
            sev_style = "red" if sev_val == "high" else "yellow"
            status_style = "green" if a.resolved else "red"
            anom_table.add_row(
                anomaly_type_val,
                f"[{sev_style}]{sev_val}[/{sev_style}]",
                a.description,
                f"[{status_style}]{'已解决' if a.resolved else '未解决'}[/{status_style}]",
            )
        console.print(anom_table)


@permission_app.command("revoke")
def revoke_permission(
    permission_id: str = typer.Argument(..., help="权限 ID"),
    reason: str = typer.Option(..., "--reason", "-r", help="收回原因"),
):
    """标记权限为已收回"""
    storage = get_storage()
    perm = storage.load_permission(permission_id)
    if not perm:
        console.print(f"[red]✗[/red] 未找到权限记录: {permission_id}")
        raise typer.Exit(1)

    perm.status = PermissionStatus.REVOKED
    perm.description = (perm.description or "") + f" | 收回原因: {reason}"
    storage.save_permission(perm)

    anomalies = storage.get_anomalies_for_permission(permission_id)
    detector = AnomalyDetector(storage)
    for anomaly in anomalies:
        if not anomaly.resolved:
            detector.mark_resolved(anomaly.id, f"权限已收回: {reason}")

    console.print(f"[green]✓[/green] 权限 {permission_id[:8]} 已标记为收回")


review_app = typer.Typer(help="复核流程管理")
app.add_typer(review_app, name="review")


@review_app.command("cycle-start")
def start_cycle(
    name: str = typer.Argument(..., help="复核周期名称, 如: 2024-Q2"),
    quarter: str = typer.Argument(..., help="季度: Q1/Q2/Q3/Q4"),
    year: int = typer.Argument(..., help="年份"),
    description: Optional[str] = typer.Option(None, "--desc", help="描述"),
):
    """开始一个新的复核周期"""
    storage = get_storage()

    active_cycle = storage.get_active_cycle()
    if active_cycle:
        console.print(f"[yellow]![/yellow] 当前有进行中的复核周期: {active_cycle.name}")
        confirm = typer.confirm("是否继续创建新周期?")
        if not confirm:
            raise typer.Exit(0)

    cycle = ReviewCycle(
        id=Storage.generate_id(),
        name=name,
        quarter=quarter,
        year=year,
        start_date=datetime.now(),
        description=description,
    )
    storage.save_cycle(cycle)
    console.print(f"[green]✓[/green] 复核周期已创建: {name}")

    permissions = storage.list_permissions()
    active_perms = [p for p in permissions if p.status == "active"]
    for perm in active_perms:
        perm.status = PermissionStatus.PENDING_REVIEW
        storage.save_permission(perm)

    console.print(f"[blue]i[/blue] 已将 {len(active_perms)} 条活跃权限标记为待复核")


@review_app.command("cycle-close")
def close_cycle(
    cycle_id: Optional[str] = typer.Argument(None, help="复核周期 ID (默认关闭当前进行中的)"),
):
    """关闭复核周期"""
    storage = get_storage()

    if cycle_id:
        cycle = storage.load_cycle(cycle_id)
    else:
        cycle = storage.get_active_cycle()

    if not cycle:
        console.print("[red]✗[/red] 未找到复核周期")
        raise typer.Exit(1)

    cycle.status = "completed"
    cycle.end_date = datetime.now()
    storage.save_cycle(cycle)
    console.print(f"[green]✓[/green] 复核周期 {cycle.name} 已关闭")


@review_app.command("cycle-list")
def list_cycles():
    """列出所有复核周期"""
    storage = get_storage()
    cycles = storage.list_cycles()

    if not cycles:
        console.print("[yellow]![/yellow] 暂无复核周期")
        return

    table = Table(title="复核周期列表")
    table.add_column("ID", style="dim")
    table.add_column("名称", style="cyan")
    table.add_column("季度", style="magenta")
    table.add_column("年份", style="yellow")
    table.add_column("开始日期", style="dim")
    table.add_column("结束日期", style="dim")
    table.add_column("状态", style="bold")

    for c in cycles:
        status_style = "green" if c.status == "in_progress" else "dim"
        end_date = c.end_date.strftime("%Y-%m-%d") if c.end_date else "-"
        table.add_row(
            c.id[:8],
            c.name,
            c.quarter,
            str(c.year),
            c.start_date.strftime("%Y-%m-%d"),
            end_date,
            f"[{status_style}]{c.status}[/{status_style}]",
        )

    console.print(table)


@review_app.command("record")
def record_review(
    permission_id: str = typer.Argument(..., help="权限 ID"),
    reviewer: str = typer.Option(..., "--reviewer", "-r", help="复核人"),
    result: str = typer.Option(..., "--result", help="复核结果: approved/revoke_recommended/escalated/pending"),
    comments: Optional[str] = typer.Option(None, "--comments", "-c", help="复核备注"),
    anomaly_types: Optional[str] = typer.Option(None, "--anomaly", help="异常类型，逗号分隔"),
):
    """记录复核结果"""
    storage = get_storage()
    perm = storage.load_permission(permission_id)
    if not perm:
        console.print(f"[red]✗[/red] 未找到权限记录: {permission_id}")
        raise typer.Exit(1)

    try:
        review_result = ReviewResult(result)
    except ValueError:
        console.print(f"[red]✗[/red] 无效的复核结果: {result}")
        raise typer.Exit(1)

    anomaly_list = []
    if anomaly_types:
        for at in anomaly_types.split(","):
            try:
                anomaly_list.append(AnomalyType(at.strip()))
            except ValueError:
                console.print(f"[yellow]![/yellow] 跳过无效的异常类型: {at.strip()}")

    review = ReviewRecord(
        id=Storage.generate_id(),
        permission_id=permission_id,
        reviewer=reviewer,
        review_date=datetime.now(),
        result=review_result,
        comments=comments,
        anomaly_types=anomaly_list,
    )
    storage.save_review(review)

    if review_result == ReviewResult.APPROVED:
        perm.status = PermissionStatus.ACTIVE
    elif review_result == ReviewResult.REVOKE_RECOMMENDED:
        perm.status = PermissionStatus.PENDING_REVIEW

    storage.save_permission(perm)

    console.print(f"[green]✓[/green] 复核结果已记录: {review_result.value}")


@review_app.command("pending")
def pending_reviews(
    department: Optional[str] = typer.Option(None, "--dept", "-d", help="按部门筛选"),
    limit: int = typer.Option(50, "--limit", "-n", help="显示条数"),
):
    """列出待复核的权限"""
    storage = get_storage()
    permissions = storage.list_permissions()
    pending_perms = [p for p in permissions if p.status == "pending_review"]

    if department:
        pending_perms = [p for p in pending_perms if department.lower() in p.department.lower()]

    if not pending_perms:
        console.print("[green]✓[/green] 没有待复核的权限")
        return

    pending_perms = pending_perms[:limit]

    table = Table(title=f"待复核权限 (共 {len(pending_perms)} 条)")
    table.add_column("ID", style="dim")
    table.add_column("用户名", style="cyan")
    table.add_column("部门", style="magenta")
    table.add_column("角色", style="yellow")
    table.add_column("资源", style="green")
    table.add_column("授予日期", style="dim")

    for p in pending_perms:
        table.add_row(
            p.id[:8],
            p.username,
            p.department,
            p.role,
            p.resource,
            p.granted_date.strftime("%Y-%m-%d"),
        )

    console.print(table)


anomaly_app = typer.Typer(help="异常检测与管理")
app.add_typer(anomaly_app, name="anomaly")


@anomaly_app.command("detect")
def detect_anomalies(
    unused_days: int = typer.Option(90, "--unused-days", help="未使用天数阈值"),
):
    """检测异常权限"""
    storage = get_storage()
    detector = AnomalyDetector(storage, unused_days=unused_days)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("正在检测异常权限...", total=None)
        anomalies = detector.detect_all()
        progress.update(task, completed=True)

    summary = detector.get_summary()

    console.print(f"[green]✓[/green] 检测完成，共发现 {len(anomalies)} 个异常")
    rprint(Panel.fit(
        f"按类型分布:\n"
        + "\n".join(f"  - {k}: {v}" for k, v in summary["by_type"].items())
        + "\n\n按严重度分布:\n"
        + "\n".join(f"  - {k}: {v}" for k, v in summary["by_severity"].items())
        + f"\n\n影响权限数: {summary['affected_permissions']}/{summary['total_active_permissions']}",
        title="异常检测摘要",
        border_style="yellow"
    ))


@anomaly_app.command("list")
def list_anomalies(
    unresolved_only: bool = typer.Option(True, "--all", "-a", help="显示所有（包括已解决）", flag_value=False),
    anomaly_type: Optional[str] = typer.Option(None, "--type", "-t", help="按类型筛选"),
    severity: Optional[str] = typer.Option(None, "--severity", "-s", help="按严重度筛选: high/medium/low"),
):
    """列出异常报告"""
    storage = get_storage()
    anomalies = storage.list_anomalies(unresolved_only=unresolved_only)

    if anomaly_type:
        anomalies = [a for a in anomalies if a.anomaly_type == anomaly_type]
    if severity:
        anomalies = [a for a in anomalies if a.severity == severity]

    if not anomalies:
        console.print("[yellow]![/yellow] 没有找到异常记录")
        return

    permissions = storage.list_permissions()
    perm_map = {p.id: p for p in permissions}

    table = Table(title=f"异常报告 (共 {len(anomalies)} 条)")
    table.add_column("ID", style="dim")
    table.add_column("类型", style="red")
    table.add_column("严重度", style="bold")
    table.add_column("用户名", style="cyan")
    table.add_column("资源", style="green")
    table.add_column("描述", style="dim")
    table.add_column("状态", style="bold")

    for a in anomalies:
        perm = perm_map.get(a.permission_id)
        username = perm.username if perm else "未知"
        resource = perm.resource if perm else "未知"
        anomaly_type_val = a.anomaly_type.value if hasattr(a.anomaly_type, 'value') else str(a.anomaly_type)
        sev_val = a.severity.value if hasattr(a.severity, 'value') else str(a.severity)
        sev_style = "red" if sev_val == "high" else "yellow"
        status_style = "green" if a.resolved else "red"
        status_text = "已解决" if a.resolved else "未解决"

        table.add_row(
            a.id[:8],
            anomaly_type_val,
            f"[{sev_style}]{sev_val}[/{sev_style}]",
            username,
            resource,
            a.description,
            f"[{status_style}]{status_text}[/{status_style}]",
        )

    console.print(table)


@anomaly_app.command("summary")
def anomaly_summary():
    """显示异常检测摘要"""
    storage = get_storage()
    detector = AnomalyDetector(storage)
    summary = detector.get_summary()

    table = Table(title="异常检测摘要", show_header=False, box=None)
    table.add_column("项目", style="cyan")
    table.add_column("数值", style="bold")

    table.add_row("未解决异常总数", str(summary["total_anomalies"]))
    table.add_row("影响权限数", f"{summary['affected_permissions']}/{summary['total_active_permissions']}")
    table.add_row("高风险权限数", f"[red]{summary['high_risk_count']}[/red]")
    table.add_row("未使用阈值", f"{summary['unused_threshold_days']} 天")

    console.print(table)

    if summary["by_type"]:
        type_table = Table(title="按类型分布")
        type_table.add_column("异常类型", style="cyan")
        type_table.add_column("数量", style="bold", justify="right")
        for k, v in sorted(summary["by_type"].items(), key=lambda x: -x[1]):
            type_table.add_row(k, str(v))
        console.print(type_table)

    if summary["by_severity"]:
        sev_table = Table(title="按严重度分布")
        sev_table.add_column("严重度", style="cyan")
        sev_table.add_column("数量", style="bold", justify="right")
        for k, v in sorted(summary["by_severity"].items(), key=lambda x: -x[1]):
            sev_style = "red" if k == "high" else "yellow"
            sev_table.add_row(f"[{sev_style}]{k}[/{sev_style}]", str(v))
        console.print(sev_table)


@anomaly_app.command("resolve")
def resolve_anomaly(
    anomaly_id: str = typer.Argument(..., help="异常报告 ID"),
    notes: str = typer.Option(..., "--notes", "-n", help="解决说明"),
):
    """标记异常为已解决"""
    storage = get_storage()
    detector = AnomalyDetector(storage)

    if detector.mark_resolved(anomaly_id, notes):
        console.print(f"[green]✓[/green] 异常 {anomaly_id[:8]} 已标记为解决")
    else:
        console.print(f"[red]✗[/red] 未找到异常记录: {anomaly_id}")
        raise typer.Exit(1)


@anomaly_app.command("revoke-list")
def revoke_candidates():
    """列出建议收回的权限清单"""
    storage = get_storage()
    detector = AnomalyDetector(storage)
    candidates = detector.get_revoke_candidates()

    if not candidates:
        console.print("[green]✓[/green] 没有需要收回的权限")
        return

    table = Table(title=f"建议收回的权限 (共 {len(candidates)} 条)")
    table.add_column("优先级", style="bold")
    table.add_column("用户名", style="cyan")
    table.add_column("部门", style="magenta")
    table.add_column("资源", style="green")
    table.add_column("异常类型", style="red")
    table.add_column("描述", style="dim")

    for c in candidates:
        perm = c["permission"]
        anomaly = c["anomaly"]
        anomaly_type_val = anomaly.anomaly_type.value if hasattr(anomaly.anomaly_type, 'value') else str(anomaly.anomaly_type)
        priority_style = "red" if c["priority"] == "critical" else "yellow"
        table.add_row(
            f"[{priority_style}]{c['priority']}[/{priority_style}]",
            perm.username,
            perm.department,
            perm.resource,
            anomaly_type_val,
            anomaly.description,
        )

    console.print(table)


report_app = typer.Typer(help="报告生成")
app.add_typer(report_app, name="report")


@report_app.command("summary")
def generate_summary(
    output_path: Optional[Path] = typer.Option(None, "--output", "-o", help="输出文件路径"),
    cycle_id: Optional[str] = typer.Option(None, "--cycle", help="指定复核周期"),
):
    """生成复核摘要报告"""
    storage = get_storage()
    report_gen = ReportGenerator(storage)

    cycle = None
    if cycle_id:
        cycle = storage.load_cycle(cycle_id)
    else:
        cycle = storage.get_active_cycle()

    summary = report_gen.generate_review_summary(cycle)

    s = summary["summary"]
    rprint(Panel.fit(
        f"[bold]复核进度:[/bold] {s['review_progress']} ({s['review_progress_pct']}%)\n"
        f"[bold]活跃权限:[/bold] {s['active_permissions']}\n"
        f"[bold]已复核:[/bold] [green]{s['reviewed_count']}[/green]\n"
        f"[bold]未复核:[/bold] [yellow]{s['unreviewed_count']}[/yellow]\n"
        f"[bold]通过:[/bold] [green]{s['approved_count']}[/green]\n"
        f"[bold]建议收回:[/bold] [red]{s['revoke_recommended_count']}[/red]\n"
        f"[bold]上报:[/bold] [yellow]{s['escalated_count']}[/yellow]\n"
        f"[bold]未解决异常:[/bold] [red]{s['total_anomalies']}[/red]",
        title=f"复核摘要 - {cycle.name if cycle else '全量'}",
        border_style="cyan"
    ))

    if s["active_permissions"] > 0:
        dept_table = Table(title="按部门统计")
        dept_table.add_column("部门", style="cyan")
        dept_table.add_column("总数", justify="right")
        dept_table.add_column("已复核", justify="right")
        dept_table.add_column("通过", justify="right")
        dept_table.add_column("待收回", justify="right")
        dept_table.add_column("异常", justify="right")

        for dept, data in sorted(summary["by_department"].items()):
            dept_table.add_row(
                dept,
                str(data["total"]),
                str(data["reviewed"]),
                f"[green]{data['approved']}[/green]",
                f"[red]{data['to_revoke']}[/red]",
                f"[yellow]{data['anomalies']}[/yellow]",
            )
        console.print(dept_table)

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
        console.print(f"[green]✓[/green] 报告已保存到: {output_path}")


@report_app.command("revoke")
def export_revoke_list(
    output_path: Path = typer.Argument(..., help="输出文件路径"),
    format: str = typer.Option("csv", "--format", "-f", help="格式: csv/json"),
):
    """导出待收回权限清单"""
    storage = get_storage()
    report_gen = ReportGenerator(storage)

    if format == "csv":
        count = report_gen.export_revoke_list_csv(output_path)
    else:
        revoke_list = report_gen.generate_revoke_list()
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(revoke_list, f, indent=2, ensure_ascii=False)
        count = len(revoke_list)

    console.print(f"[green]✓[/green] 已导出 {count} 条待收回权限到: {output_path}")


@report_app.command("permissions")
def export_permission_report(
    output_path: Path = typer.Argument(..., help="输出文件路径"),
    status: Optional[str] = typer.Option(None, "--status", "-s", help="按状态筛选"),
    format: str = typer.Option("csv", "--format", "-f", help="格式: csv/json"),
):
    """导出权限清单报告"""
    storage = get_storage()
    report_gen = ReportGenerator(storage)

    if format == "csv":
        count = report_gen.export_permission_list_csv(output_path, status)
        console.print(f"[green]✓[/green] 已导出 {count} 条权限记录到: {output_path}")
    else:
        storage.export_to_json(output_path, "permissions")
        console.print(f"[green]✓[/green] 已导出权限数据到: {output_path}")


@report_app.command("user")
def user_report(
    username: str = typer.Argument(..., help="用户名"),
    output_path: Optional[Path] = typer.Option(None, "--output", "-o", help="输出文件路径"),
):
    """生成用户权限报告"""
    storage = get_storage()
    report_gen = ReportGenerator(storage)
    report = report_gen.generate_user_report(username)

    rprint(Panel.fit(
        f"[bold]用户名:[/bold] {report['username']}\n"
        f"[bold]权限总数:[/bold] {report['permission_count']}\n"
        f"[bold]活跃权限:[/bold] [green]{report['active_count']}[/green]\n"
        f"[bold]未解决异常:[/bold] [red]{report['anomaly_count']}[/red]",
        title="用户权限报告",
        border_style="cyan"
    ))

    if report["permissions"]:
        perm_table = Table(title="权限列表")
        perm_table.add_column("资源", style="green")
        perm_table.add_column("角色", style="yellow")
        perm_table.add_column("权限级别", style="blue")
        perm_table.add_column("状态", style="bold")
        for p in report["permissions"]:
            status_style = "green" if p["status"] == "active" else "red"
            perm_table.add_row(
                p["resource"],
                p["role"],
                p["permission_level"],
                f"[{status_style}]{p['status']}[/{status_style}]",
            )
        console.print(perm_table)

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        console.print(f"[green]✓[/green] 报告已保存到: {output_path}")


@app.command()
def quarterly(
    name: str = typer.Argument(..., help="复核周期名称"),
    quarter: str = typer.Argument(..., help="季度: Q1/Q2/Q3/Q4"),
    year: int = typer.Argument(..., help="年份"),
    reviewer: str = typer.Option(..., "--reviewer", "-r", help="复核人"),
    unused_days: int = typer.Option(90, "--unused-days", help="未使用天数阈值"),
    output_dir: Path = typer.Option(Path("./reports"), "--output", "-o", help="报告输出目录"),
):
    """执行完整的季度复核流程 (一键运行)"""
    storage = get_storage()
    detector = AnomalyDetector(storage, unused_days=unused_days)
    report_gen = ReportGenerator(storage)

    output_dir.mkdir(parents=True, exist_ok=True)

    rprint(Panel.fit(
        f"周期: {name} ({year} {quarter})\n"
        f"复核人: {reviewer}\n"
        f"未使用阈值: {unused_days} 天\n"
        f"输出目录: {output_dir}",
        title="开始季度复核流程",
        border_style="green"
    ))

    console.print("\n[bold cyan]步骤 1: 创建复核周期[/bold cyan]")
    cycle = ReviewCycle(
        id=Storage.generate_id(),
        name=name,
        quarter=quarter,
        year=year,
        start_date=datetime.now(),
        description=f"{year}年{quarter}季度权限复核",
    )
    storage.save_cycle(cycle)
    console.print(f"[green]✓[/green] 复核周期已创建: {name}")

    console.print("\n[bold cyan]步骤 2: 异常检测[/bold cyan]")
    anomalies = detector.detect_all()
    console.print(f"[green]✓[/green] 检测到 {len(anomalies)} 个异常")

    console.print("\n[bold cyan]步骤 3: 标记待复核[/bold cyan]")
    permissions = storage.list_permissions()
    active_perms = [p for p in permissions if p.status == "active"]
    for perm in active_perms:
        perm.status = PermissionStatus.PENDING_REVIEW
        storage.save_permission(perm)
    console.print(f"[green]✓[/green] 已将 {len(active_perms)} 条活跃权限标记为待复核")

    console.print("\n[bold cyan]步骤 4: 生成报告[/bold cyan]")
    summary_path = output_dir / f"{name}_summary.json"
    summary = report_gen.generate_review_summary(cycle)
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    console.print(f"[green]✓[/green] 摘要报告: {summary_path}")

    anomaly_path = output_dir / f"{name}_anomalies.json"
    report_gen.generate_anomaly_report(anomaly_path)
    console.print(f"[green]✓[/green] 异常报告: {anomaly_path}")

    permission_csv = output_dir / f"{name}_permissions.csv"
    report_gen.export_permission_list_csv(permission_csv)
    console.print(f"[green]✓[/green] 权限清单: {permission_csv}")

    revoke_csv = output_dir / f"{name}_revoke_list.csv"
    revoke_count = report_gen.export_revoke_list_csv(revoke_csv)
    console.print(f"[green]✓[/green] 收回清单: {revoke_csv} ({revoke_count} 条)")

    s = summary["summary"]
    rprint(Panel.fit(
        f"[bold]复核进度:[/bold] {s['review_progress']}\n"
        f"[bold]建议收回:[/bold] [red]{s['revoke_recommended_count']}[/red] 条\n"
        f"[bold]异常权限:[/bold] [red]{s['total_anomalies']}[/red] 条\n"
        f"[bold]未复核:[/bold] [yellow]{s['unreviewed_count']}[/yellow] 条",
        title="季度复核完成",
        border_style="green"
    ))

    console.print(f"\n[blue]i[/blue] 后续步骤:")
    console.print(f"  1. 查看待复核权限: access-review review pending")
    console.print(f"  2. 记录复核结果: access-review review record <perm-id> --reviewer {reviewer} --result approved")
    console.print(f"  3. 查看异常列表: access-review anomaly list")
    console.print(f"  4. 导出收回清单执行收回: access-review report revoke revoke_final.csv")


if __name__ == "__main__":
    app()
