"""WraithWall admin CLI."""
from __future__ import annotations

import sys

import typer

app = typer.Typer(name="wraithwall", help="WraithWall deployment and management CLI.")


@app.command()
def serve(host: str = "0.0.0.0", port: int = 8000, workers: int = 2):
    """Start the WraithWall application."""
    from gunicorn.app.wsgiapp import WSGIApplication

    from wraithwall import create_app

    wsgi = create_app()

    class WraithWallApp(WSGIApplication):
        def init(self, parser, opts, args):
            return None

        def load(self):
            return wsgi

    sys.argv = ["gunicorn", f"--bind={host}:{port}", f"--workers={workers}", "WraithWallApp"]
    WraithWallApp().run()


@app.command()
def check():
    """Verify configuration and blueprint registration."""
    from wraithwall import create_app

    app_obj = create_app({"TESTING": True})
    routes = len(list(app_obj.url_map.iter_rules()))
    typer.echo(f"Routes: {routes}")
    typer.echo(f"Blueprints: {len(app_obj.blueprints)}")


@app.command()
def routes():
    """List all registered routes."""
    from wraithwall import create_app

    for rule in create_app({"TESTING": True}).url_map.iter_rules():
        typer.echo(f"{rule.methods or ''} {rule.rule}")