Docker usage

Build the image:

```bash
docker build -t evul:latest .
```

Run with Docker:

```bash
docker run -it --rm -p 5000:5000 --env REQUIRE_AUTH=false --name evul_app evul:latest
```

Or using docker-compose:

```bash
docker-compose up --build
```

For production compose:

```bash
docker-compose -f docker-compose.prod.yml up --build -d
```

Notes:
- By default the container sets `REQUIRE_AUTH=false` to make local testing easier. Override via env vars.
- The `docker-compose.yml` mounts the project into `/app` to permit iterative development.
- `docker-compose.prod.yml` uses `Dockerfile.prod` and does not mount the source tree.
- If using Postgres, pass `DATABASE_URL` to the container env.

Production image

To build a production image (no mounted volume, non-root runtime) use the provided `Dockerfile.prod`:

```bash
docker build -f Dockerfile.prod -t evul:prod .
```

Run the production image:

```bash
docker run -d --name evul_prod -p 5000:5000 --env REQUIRE_AUTH=false evul:prod
```

Notes:
- `Dockerfile.prod` installs `gunicorn` and runs `evildev.app:app` with 3 workers.
- The production image does not mount the source tree; rebuild to deploy code changes.
