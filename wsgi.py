from cyberapp.host_safety import enforce_host_safety

enforce_host_safety()

from cyberapp.app import create_app
app = create_app(run_migrations_on_start=False)
application = app  # For gunicorn compatibility
