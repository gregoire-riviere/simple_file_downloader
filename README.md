# SimpleFileDownloader

Petit serveur HTTP pour exposer temporairement des fichiers via un lien signé (token + expiration).
Un simple appel de fonction enregistre un fichier, renvoie un lien, et ce lien devient invalide après un TTL.
Le mapping fichier ↔ token ↔ expiration est persisté sur disque.

## Prérequis

- Elixir 1.18.4 (OTP 28)
- Erlang/OTP 28.2

## Fonctionnalités

- Exposition temporaire de fichiers via tokens (TTL configurable).
- Store persistant des tokens (purge auto).
- Interface web admin (login, navigation dossiers, création/gestion des liens).
- Compatible mobile.

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

## Interface web (admin)

Une interface web est exposee sur `GET /admin` avec une page de connexion.
Elle permet de parcourir un dossier racine, creer des liens, et administrer les liens actifs.
Elle peut etre desactivee via `admin.enabled?`.

### Configuration admin (securite)

Definir un mot de passe admin (hash SHA-256 + sel) :

```elixir
{:ok, %{salt_path: salt_path, hash_path: hash_path}} =
  SimpleFileDownloader.Admin.init_admin_password("votre-mot-de-passe")
```

Cette commande ecrit les secrets localement dans `SFD_DATA_DIR` (par defaut `data/`) :
- `admin_password_salt`
- `admin_password_hash`

Configurer aussi la cle de session (>= 64 bytes) :

```bash
export SFD_SECRET_KEY_BASE="...64+ bytes secret..."
```

## Navigation fichiers

Le dossier racine pour l'interface est configure via `admin.root_dir`.
Exemple: `root_dir: "/home/gregoire/downloads"`.

## Configuration

Configuration dans `config/config.exs` (local, non versionne) ou via `Application.put_env/3`.
Utiliser `config/config.exs.template` comme base.

```elixir
data_dir = System.get_env("SFD_DATA_DIR", "data/")

config :simple_file_downloader,
  base_url: "https://example.com",
  port: 8000,
  storage_path: Path.join(data_dir, "token_store.term"),
  default_ttl_seconds: 3600,
  token_bytes: 32,
  admin: %{
    enabled?: true,
    root_dir: "/home/gregoire/downloads",
    auth_ttl_seconds: 12 * 3600,
    secret_key_base: System.get_env("SFD_SECRET_KEY_BASE"),
    session_signing_salt: "sfd_signing_salt",
    session_encryption_salt: "sfd_encryption_salt",
    cookie_secure: false,
    template_dir: "web"
  }
```

Par defaut, le dossier de donnees est `data/`. Vous pouvez le surcharger avec:

```bash
export SFD_DATA_DIR="/chemin/vers/mon_data_dir"
```

### Configuration html_handler (optionnel)

`mix compile_front` compile les fichiers statiques (HTML/CSS/JS) du dossier `web`.
Note: le contenu dynamique admin est rendu au runtime, donc `compile_front` ne remplace
pas les blocs dynamiques.

```elixir
config :html_handler,
  directories: %{
    html: "web",
    js: "web/assets",
    css: "web/assets",
    dir_to_copy: [],
    output: "web_build/"
  },
  templatization?: true,
  watch?: false,
  seo?: false,
  base_url: "http://localhost:8000",
  routes: %{}
```

## Notes sécurité

- Le token est aléatoire et non prédictible.
- Le fichier doit exister et être un fichier régulier.
- Le store est relu au démarrage et purge les tokens expirés.
- La route renvoie 404 si token inconnu ou expiré.
- L'interface admin peut etre desactivee via `admin.enabled?`.
- Utiliser `cookie_secure: true` en HTTPS.
- `config/config.exs` n'est pas versionne, utiliser `config/config.exs.template` comme base.
