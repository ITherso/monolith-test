from cyberapp.app import create_app
app = create_app(run_migrations_on_start=False)
application = app  # For gunicorn compatibility