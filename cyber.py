from cyberapp.app import create_app
from cyberapp.cli import main

app = create_app(run_migrations_on_start=False)

if __name__ == "__main__":
    main()
