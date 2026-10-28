# Hardened Containerized RustDesk Server

[![CI](https://github.com/underhax/rustdesk-server-docker/actions/workflows/ci.yml/badge.svg)](https://github.com/underhax/rustdesk-server-docker/actions/workflows/ci.yml)
[![GitHub last commit](https://img.shields.io/github/last-commit/underhax/rustdesk-server-docker)](https://github.com/underhax/rustdesk-server-docker/commits/main)
[![GitHub issues](https://img.shields.io/github/issues/underhax/rustdesk-server-docker)](https://github.com/underhax/rustdesk-server-docker/issues)
[![GitHub repo size](https://img.shields.io/github/repo-size/underhax/rustdesk-server-docker)](https://github.com/underhax/rustdesk-server-docker)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Hardened, containerized deployment architecture for [RustDesk Server](https://github.com/rustdesk/rustdesk-server) (`hbbs` and `hbbr`) packaged in a minimal `scratch` runtime with host Discretionary Access Control (DAC) boundaries, Docker secret ingestion via a dedicated Go init supervisor, in-memory credential scrubbing, and a standalone binary healthcheck probe.

## Architecture Highlights

This deployment packages RustDesk Server into an isolated, defense-in-depth runtime environment:

* Scratch runtime: Built on an empty scratch base image containing only upstream RustDesk binaries, system CA certificates, and static Go helpers for process supervision, secret ingestion, and TCP health checks. The runtime includes no shell, package manager, or system utilities.
* In-memory secret ingestion: Ed25519 keys and configuration secrets are ingested directly from Docker secrets into process memory rather than stored in the application data directory. Cryptographic key sizes and keypair matching are validated before keys are passed to the daemons.
* Memory scrubbing: Following daemon startup and TCP port readiness verification, the environment block in process memory is zeroed, preventing credential exposure through process inspection.
* Role-based secret separation: The relay daemon requires only the public key, completely eliminating exposure of the private key inside the relay container.
* Network & IPC boundary isolation: Inter-container communication and shared memory IPC are disabled, preventing lateral movement across the Docker network.
* Least privilege enforcement: Containers execute under dedicated unprivileged user accounts with read-only root filesystems, all Linux capabilities dropped, privilege escalation blocked, and strict kernel resource boundaries.

---

<details>
<summary><strong>Directory Structure</strong></summary>

Production directory layout on the host (`/home/rustdesk`):

```text
├── docker-compose.yaml                                        # Production deployment manifest
├── .env                                                       # Host infrastructure and service configuration
├── secrets/                                                   # Docker secrets directory (root:rustdesk 0750)
│   ├── id_ed25519                                             # Ed25519 private key (64 bytes Base64)
│   ├── id_ed25519.pub                                         # Ed25519 public key (32 bytes Base64)
│   └── rd_relay_servers.txt                                   # Optional: Relay server addresses
└── data/                                                      # hbbs persistent storage (db_v2.sqlite3)
```

</details>

---

<details>
<summary><strong>Deployment &amp; Setup</strong></summary>

### Prerequisites

* **Docker Engine & Compose:** Ensure Docker Engine and the Docker Compose plugin are installed on the host. Follow the official installation guide for [Ubuntu](https://docs.docker.com/engine/install/ubuntu/#install-using-the-repository).

### 1. Create a Dedicated System User

Choose a dedicated, unprivileged numeric ID unique to this service on your host and verify that it is not already in use by another user or group:

```bash
APP_UID=<CHOSEN_UID>

getent passwd ${APP_UID}
getent group ${APP_UID}
```

> **Important:** Both commands must return empty output. Each containerized service must have its own dedicated unprivileged user and group to enforce strict host DAC privilege separation between different stacks.

Create an unprivileged system account with a matching user-group (`-U`) and disabled login shell:

```bash
sudo useradd -m -d /home/rustdesk -s /usr/sbin/nologin -u ${APP_UID} -U rustdesk
```

### 2. Create Directory Layout & Assign Ownership

Create the base directory and assign ownership:

```bash
sudo mkdir -p /home/rustdesk
sudo chown root:rustdesk /home/rustdesk
sudo chmod 0750 /home/rustdesk
```

Create runtime subdirectories from `root` and assign strict DAC permissions:

```bash
sudo mkdir -p /home/rustdesk/{data,secrets}

sudo chown root:rustdesk /home/rustdesk/secrets
sudo chmod 0750 /home/rustdesk/secrets

sudo chown rustdesk:rustdesk /home/rustdesk/data
sudo chmod 0700 /home/rustdesk/data
```

### 3. Deploy Project Files

Download the production manifests directly into `/home/rustdesk`:

```bash
REPO="https://raw.githubusercontent.com/underhax/rustdesk-server-docker/main"

sudo curl -fsSL ${REPO}/docker-compose.yaml -o /home/rustdesk/docker-compose.yaml
sudo curl -fsSL ${REPO}/.env.example -o /home/rustdesk/.env

sudo chown root:root /home/rustdesk/{docker-compose.yaml,.env}
sudo chmod 0600 /home/rustdesk/{docker-compose.yaml,.env}
```

### 4. Configure Host Environment Settings

```bash
sed -i "s/^APP_UID=.*/APP_UID=${APP_UID}/" /home/rustdesk/.env
sed -i "s/^APP_GID=.*/APP_GID=${APP_UID}/" /home/rustdesk/.env
```

Discover the server's public IP address using `ip --br a`, then edit `/home/rustdesk/.env` to configure `HOST_IP`:

```bash
ip --br a
sudo nano /home/rustdesk/.env
```

### 5. Generate Secrets

**Ed25519 keypair:**

Generate a canonical keypair directly into `/home/rustdesk/secrets` using the container:

```bash
sudo docker run --rm -v /home/rustdesk/secrets:/secrets \
  ghcr.io/underhax/rustdesk-server-docker:latest keygen
```

> **Note:** The keypair (`id_ed25519` and `id_ed25519.pub`) is generated and saved automatically, and the public key string is printed to the console for client configuration. If migrating from an existing RustDesk server, copy existing `id_ed25519` and `id_ed25519.pub` files directly to `/home/rustdesk/secrets/`.

**Relay server address:**

Populate `rd_relay_servers.txt` with your public domain name or IP address using a text editor to avoid leaving sensitive network infrastructure in your shell history:

```bash
sudo nano /home/rustdesk/secrets/rd_relay_servers.txt
```

**Enforce DAC permissions:**

Enforce strict host permissions on all secret files:

```bash
sudo chown root:rustdesk /home/rustdesk/secrets/*
sudo chmod 0440 /home/rustdesk/secrets/*
```

### 6. Start the Stack

Pull images and start the services:

```bash
sudo docker compose -f /home/rustdesk/docker-compose.yaml pull
sudo docker compose -f /home/rustdesk/docker-compose.yaml up -d
```

</details>

---

<details>
<summary><strong>Permissions &amp; Ownership</strong></summary>

### Host Permissions & Privilege Separation

The stack enforces strict host-level privilege separation across three ownership tiers so that even in the event of a container compromise, the process cannot modify deployment manifests, service configurations, or secret files:

* `root:root` (0600): `docker-compose.yaml` and `.env` (accessible exclusively to host root).
* `root:rustdesk` (0750/0440): `/home/rustdesk` base directory (0750), `secrets/` directory (0750), and secret files (`0440`; read-only to containers, immutable to runtime processes).
* `rustdesk:rustdesk` (0700): `data/` (`hbbs` database and peer state). Managed with `umask 077`: directories `0700`, files `0600`.

### One-Shot Permission Reset (Running Stack)

Use this self-contained block to apply or restore canonical ownership and permissions on an existing or migrated installation without stopping the stack:

```bash
sudo chown root:rustdesk /home/rustdesk
sudo chmod 0750 /home/rustdesk

sudo chown root:root /home/rustdesk/{docker-compose.yaml,.env}
sudo chmod 0600 /home/rustdesk/{docker-compose.yaml,.env}

sudo chown -R root:rustdesk /home/rustdesk/secrets
sudo chmod 0750 /home/rustdesk/secrets
sudo find /home/rustdesk/secrets -type f -exec chmod 0440 {} +

sudo chown -R rustdesk:rustdesk /home/rustdesk/data
sudo chmod 0700 /home/rustdesk/data
sudo find /home/rustdesk/data -mindepth 1 -type d -exec chmod 0700 {} +
sudo find /home/rustdesk/data -type f -exec chmod 0600 {} +
```

</details>

---

<details>
<summary><strong>Operation &amp; Maintenance</strong></summary>

### Verifying Service Health

Inspect container status and resource usage:

```bash
sudo docker compose -f /home/rustdesk/docker-compose.yaml ps
sudo docker stats --no-stream hbbs hbbr
```

### Inspecting Runtime Logs

Follow application logs:

```bash
sudo docker compose -f /home/rustdesk/docker-compose.yaml logs -f
```

### Updating the Image

Pull updated images and recreate containers:

```bash
sudo docker compose -f /home/rustdesk/docker-compose.yaml pull
sudo docker compose -f /home/rustdesk/docker-compose.yaml up -d
```

### Tearing Down the Stack

Stop and remove containers and networks:

```bash
sudo docker compose -f /home/rustdesk/docker-compose.yaml down
```

</details>

---

<details>
<summary><strong>Development</strong></summary>

For local compilation, static analysis, unit testing, and Docker linting guidelines, see **[DEVELOPMENT.md](DEVELOPMENT.md)**.

</details>

---

<details>
<summary><strong>License &amp; Attribution</strong></summary>

## License & Attribution

This repository and deployment architecture are licensed under the [MIT License](LICENSE). This project is an independent containerized deployment architecture and is not affiliated with, endorsed, or sponsored by RustDesk.

RustDesk Server is open-source software licensed under the [AGPLv3](https://github.com/rustdesk/rustdesk-server/blob/master/LICENSE).

</details>
