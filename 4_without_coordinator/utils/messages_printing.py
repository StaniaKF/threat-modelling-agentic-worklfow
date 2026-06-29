from rich import print
from rich.panel import Panel


def print_box(color: str, message: str, title: str | None = None) -> None:
    bold_title = f"[bold {color}]{title}[/]" if title else None
    print(
        Panel(
            renderable=f"\n{message}",
            title=bold_title,
            title_align="left",
            expand=True,
            border_style=color,
        )
    )


def print_info_box(message: str, title: str | None = None) -> None:
    print_box("blue", message, title)


def print_success_box(message: str, title: str | None = None) -> None:
    print_box("green", message, title)


def print_info(message: str) -> None:
    """Print informational messages in blue."""
    print("\n[bold blue]" + message + "[/bold blue]\n")


def print_error(message: str) -> None:
    """Print error messages in red."""
    print("\n[bold red]" + message + "[/bold red]\n")


def print_success(message: str) -> None:
    """Print error messages in red."""
    print("\n[bold green]" + message + "[/bold green]\n")
