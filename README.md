# SimpleFileDownloader

Petit serveur HTTP pour exposer temporairement des fichiers via un lien signé (token + expiration).
Un simple appel de fonction enregistre un fichier, renvoie un lien, et ce lien devient invalide après un TTL.
Le mapping fichier ↔ token ↔ expiration est persisté sur disque.

## Prérequis

- Elixir 1.18.4 (OTP 28)
- Erlang/OTP 28.2

## Démarrage

```bash
mix deps.get
mix run --no-halt
```

Le serveur écoute par défaut sur `http://localhost:8000`.

## Utilisation

```elixir
{:ok, info} = SimpleFileDownloader.expose_file("/chemin/vers/fichier.pdf", 3600)

info.token
info.url
info.expires_at
```

Le fichier est disponible sur `GET /f/:token` jusqu’à expiration.

## Configuration

Configuration dans `config/config.exs` (ou via `Application.put_env/3`).

```elixir
config :simple_file_downloader,
  base_url: "https://example.com",
  port: 8000,
  storage_path: "data/token_store.term",
  default_ttl_seconds: 3600,
  token_bytes: 32
```

## Notes sécurité

- Le token est aléatoire et non prédictible.
- Le fichier doit exister et être un fichier régulier.
- Le store est relu au démarrage et purge les tokens expirés.
- La route renvoie 404 si token inconnu ou expiré.
