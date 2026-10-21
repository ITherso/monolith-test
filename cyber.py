from cyberapp.host_safety import enforce_host_safety

enforce_host_safety()

from cyberapp.app import create_app
from cyberapp.cli import main

app = create_app(run_migrations_on_start=False)

if __name__ == "__main__":
    main()
