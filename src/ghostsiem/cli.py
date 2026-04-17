"""CLI interface for GhostSIEM using Typer."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
from pathlib import Path

import typer
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

app = typer.Typer(
    name="ghostsiem",
    help="GhostSIEM - Lightweight Security Information and Event Management",
    no_args_is_help=True,
)
rules_app = typer.Typer(help="Detection rule management")
app.add_typer(rules_app, name="rules")

console = Console()


def _setup_logging(level: str = "INFO") -> None:
    """Configure logging with Rich handler."""
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True)],
    )


@app.command()
def collect(
    config: str = typer.Option("examples/config.yaml", "--config", "-c", help="Config file path"),
    log_level: str = typer.Option("INFO", "--log-level", "-l", help="Log level"),
) -> None:
    """Start log collectors based on configuration."""
    _setup_logging(log_level)
    logger = logging.getLogger("ghostsiem")

    from ghostsiem.config import load_config, settings_from_config

    try:
        cfg = load_config(config)
    except FileNotFoundError:
        console.print(f"[red]Config file not found:[/red] {config}")
        raise typer.Exit(1) from None

    settings = settings_from_config(cfg)
    logger.info("Starting GhostSIEM collectors")

    asyncio.run(_run_collectors(settings))


async def _run_collectors(settings: object) -> None:
    """Run collectors with event processing pipeline."""
    import asyncio as aio

    from ghostsiem._types import Event
    from ghostsiem.alerts.manager import AlertManager
    from ghostsiem.collectors.manager import CollectorManager
    from ghostsiem.detection.builtin_rules import load_builtin_rules
    from ghostsiem.detection.engine import DetectionEngine
    from ghostsiem.normalizer import EventNormalizer
    from ghostsiem.storage.store import EventStore

    logger = logging.getLogger("ghostsiem")

    queue: aio.Queue[Event] = aio.Queue()
    manager = CollectorManager.from_config(
        getattr(settings, "collectors", []),
        queue=queue,
    )

    if manager.collector_count == 0:
        console.print("[yellow]No collectors configured.[/yellow]")
        return

    # Initialize components
    normalizer = EventNormalizer()
    engine = DetectionEngine()
    engine.add_rules(load_builtin_rules())

    store = EventStore(db_path=getattr(settings, "db_path", "ghostsiem.db"))
    await store.initialize()

    alert_manager = AlertManager.from_config(
        getattr(settings, "alert_handlers", [{"type": "console"}]),
        dedup_window=getattr(settings, "alert_dedup_window", 300),
    )

    # Start collectors
    await manager.start()
    logger.info("Collectors started: %s", ", ".join(manager.collector_names))

    stop_event = aio.Event()

    def _signal_handler() -> None:
        stop_event.set()

    loop = aio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, _signal_handler)

    console.print("[green]GhostSIEM collectors running. Press Ctrl+C to stop.[/green]")

    try:
        while not stop_event.is_set():
            try:
                event = await aio.wait_for(queue.get(), timeout=1.0)
            except aio.TimeoutError:
                continue

            # Normalize
            event = normalizer.normalize(event)

            # Store
            await store.store_event(event)

            # Detect
            alerts = engine.evaluate(event)
            for alert in alerts:
                await store.store_alert(alert)
                await alert_manager.dispatch(alert)
    finally:
        await manager.stop()
        await store.close()
        logger.info("Collectors stopped")


@app.command()
def detect(
    rules: str = typer.Option("examples/rules", "--rules", "-r", help="Rules directory"),
    db_path: str = typer.Option("ghostsiem.db", "--db", help="Database path"),
    log_level: str = typer.Option("INFO", "--log-level", "-l", help="Log level"),
) -> None:
    """Run detection engine on stored events."""
    _setup_logging(log_level)
    asyncio.run(_run_detection(rules, db_path))


async def _run_detection(rules_dir: str, db_path: str) -> None:
    """Run detection on all stored events."""
    from ghostsiem.alerts.manager import AlertManager
    from ghostsiem.detection.builtin_rules import load_builtin_rules
    from ghostsiem.detection.engine import DetectionEngine
    from ghostsiem.storage.store import EventStore

    logger = logging.getLogger("ghostsiem")

    engine = DetectionEngine()

    # Load rules from directory if it exists
    rules_path = Path(rules_dir)
    if rules_path.is_dir():
        engine.load_rules_from_directory(rules_dir)
    else:
        logger.info("Rules directory not found, using built-in rules")
        engine.add_rules(load_builtin_rules())

    console.print(f"[green]Loaded {engine.rule_count} detection rules[/green]")

    # Run detection on stored events
    store = EventStore(db_path=db_path)
    await store.initialize()

    alert_manager = AlertManager(dedup_window=0)  # No dedup for batch
    alert_manager.add_handler(
        __import__("ghostsiem.alerts.handlers", fromlist=["ConsoleHandler"]).ConsoleHandler()
    )

    events = await store.query_events(limit=10000)
    alert_count = 0

    from ghostsiem._types import Event

    for event_dict in events:
        event = Event.from_dict(event_dict)
        alerts = engine.evaluate(event)
        for alert in alerts:
            await store.store_alert(alert)
            await alert_manager.dispatch(alert)
            alert_count += 1

    await store.close()
    console.print(
        f"\n[bold]Detection complete:[/bold] "
        f"{alert_count} alerts from {len(events)} events"
    )


@app.command()
def serve(
    host: str = typer.Option("0.0.0.0", "--host", "-h", help="API host"),
    port: int = typer.Option(8080, "--port", "-p", help="API port"),
    db_path: str = typer.Option("ghostsiem.db", "--db", help="Database path"),
    log_level: str = typer.Option("INFO", "--log-level", "-l", help="Log level"),
) -> None:
    """Start the GhostSIEM API server."""
    _setup_logging(log_level)

    import uvicorn

    from ghostsiem.api.app import create_app

    api_app = create_app(db_path=db_path)
    console.print(f"[green]Starting GhostSIEM API on {host}:{port}[/green]")
    uvicorn.run(api_app, host=host, port=port, log_level=log_level.lower())


@app.command()
def run(
    config: str = typer.Option("examples/config.yaml", "--config", "-c", help="Config file path"),
    log_level: str = typer.Option("INFO", "--log-level", "-l", help="Log level"),
) -> None:
    """Start everything: collectors + detection + API server."""
    _setup_logging(log_level)

    from ghostsiem.config import load_config, settings_from_config

    try:
        cfg = load_config(config)
    except FileNotFoundError:
        console.print(f"[red]Config file not found:[/red] {config}")
        raise typer.Exit(1) from None

    settings = settings_from_config(cfg)
    asyncio.run(_run_all(settings))


async def _run_all(settings: object) -> None:
    """Run collectors, detection, and API concurrently."""
    import asyncio as aio

    import uvicorn

    from ghostsiem._types import Event
    from ghostsiem.alerts.manager import AlertManager
    from ghostsiem.api.app import create_app
    from ghostsiem.api.routes import set_store
    from ghostsiem.collectors.manager import CollectorManager
    from ghostsiem.detection.builtin_rules import load_builtin_rules
    from ghostsiem.detection.engine import DetectionEngine
    from ghostsiem.normalizer import EventNormalizer
    from ghostsiem.storage.store import EventStore

    logger = logging.getLogger("ghostsiem")

    db_path = getattr(settings, "db_path", "ghostsiem.db")
    store = EventStore(db_path=db_path)
    await store.initialize()
    set_store(store)

    queue: aio.Queue[Event] = aio.Queue()
    manager = CollectorManager.from_config(
        getattr(settings, "collectors", []),
        queue=queue,
    )

    normalizer = EventNormalizer()
    engine = DetectionEngine()
    engine.add_rules(load_builtin_rules())

    alert_manager = AlertManager.from_config(
        getattr(settings, "alert_handlers", [{"type": "console"}]),
        dedup_window=getattr(settings, "alert_dedup_window", 300),
    )

    stop_event = aio.Event()

    async def process_events() -> None:
        while not stop_event.is_set():
            try:
                event = await aio.wait_for(queue.get(), timeout=1.0)
            except aio.TimeoutError:
                continue
            event = normalizer.normalize(event)
            await store.store_event(event)
            alerts = engine.evaluate(event)
            for alert in alerts:
                await store.store_alert(alert)
                await alert_manager.dispatch(alert)

    async def run_api() -> None:
        api_host = getattr(settings, "api_host", "0.0.0.0")
        api_port = getattr(settings, "api_port", 8080)
        config = uvicorn.Config(
            create_app(db_path=db_path),
            host=api_host,
            port=api_port,
            log_level="info",
        )
        server = uvicorn.Server(config)
        await server.serve()

    await manager.start()
    logger.info("All systems started")
    console.print("[green]GhostSIEM fully operational. Press Ctrl+C to stop.[/green]")

    try:
        await aio.gather(
            process_events(),
            run_api(),
        )
    except (KeyboardInterrupt, aio.CancelledError):
        pass
    finally:
        stop_event.set()
        await manager.stop()
        await store.close()


@rules_app.command("list")
def rules_list(
    rules_dir: str = typer.Option("examples/rules", "--rules", "-r", help="Rules directory"),
    builtin: bool = typer.Option(False, "--builtin", "-b", help="Show built-in rules"),
) -> None:
    """Show loaded detection rules."""
    from ghostsiem.detection.builtin_rules import load_builtin_rules
    from ghostsiem.detection.sigma_loader import load_sigma_rules_from_directory

    rules = []

    if builtin:
        rules = load_builtin_rules()
    else:
        path = Path(rules_dir)
        if path.is_dir():
            rules = load_sigma_rules_from_directory(rules_dir)
        else:
            console.print(f"[yellow]Rules directory not found: {rules_dir}[/yellow]")
            console.print("[yellow]Showing built-in rules instead[/yellow]")
            rules = load_builtin_rules()

    table = Table(title="Detection Rules", show_lines=True)
    table.add_column("ID", style="dim", max_width=10)
    table.add_column("Title", style="bold")
    table.add_column("Severity", justify="center")
    table.add_column("Status", justify="center")
    table.add_column("Tags", max_width=30)

    severity_colors = {
        "low": "blue",
        "medium": "yellow",
        "high": "red",
        "critical": "bold red",
    }

    for rule in rules:
        color = severity_colors.get(rule.severity.value, "white")
        table.add_row(
            rule.id[:10] if rule.id else "N/A",
            rule.title,
            f"[{color}]{rule.severity.value.upper()}[/{color}]",
            rule.status,
            ", ".join(rule.tags[:3]) if rule.tags else "N/A",
        )

    console.print(table)
    console.print(f"\n[bold]{len(rules)}[/bold] rules loaded")


@app.command()
def status(
    db_path: str = typer.Option("ghostsiem.db", "--db", help="Database path"),
) -> None:
    """Show GhostSIEM status: event count, alert count, collector info."""
    asyncio.run(_show_status(db_path))


async def _show_status(db_path: str) -> None:
    """Display status information."""
    from ghostsiem.storage.store import EventStore

    store = EventStore(db_path=db_path)

    try:
        await store.initialize()
        stats = await store.stats()
    except Exception as exc:
        console.print(f"[red]Cannot connect to database:[/red] {exc}")
        return
    finally:
        await store.close()

    console.print("\n[bold]GhostSIEM Status[/bold]")
    console.print(f"  Database: {db_path}")
    console.print(f"  Total Events: [bold]{stats['total_events']}[/bold]")
    console.print(f"  Total Alerts: [bold]{stats['total_alerts']}[/bold]")

    if stats["events_by_severity"]:
        console.print("\n  [bold]Events by Severity:[/bold]")
        for sev, count in stats["events_by_severity"].items():
            console.print(f"    {sev}: {count}")

    if stats["top_rules"]:
        console.print("\n  [bold]Top Triggered Rules:[/bold]")
        for rule_info in stats["top_rules"][:5]:
            console.print(f"    {rule_info['rule']}: {rule_info['count']}")

    console.print()
