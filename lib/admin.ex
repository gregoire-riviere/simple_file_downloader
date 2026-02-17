defmodule SimpleFileDownloader.Admin do
  require Logger

  def template_dir do
    web_dir = System.get_env("SFD_WEB_DIR", "web_build/")

    admin_config()
    |> Map.get(:template_dir, web_dir)
  end

  def root_dir do
    admin_config()
    |> Map.get(:root_dir, "/home/gregoire/downloads")
  end

  def normalized_root_dir do
    Path.expand(root_dir())
  end

  def auth_ttl_seconds do
    admin_config()
    |> Map.get(:auth_ttl_seconds, 12 * 3600)
  end

  def session_signing_salt do
    admin_config()
    |> Map.get(:session_signing_salt, "sfd_signing_salt")
  end

  def session_encryption_salt do
    admin_config()
    |> Map.get(:session_encryption_salt, "sfd_encryption_salt")
  end

  def cookie_secure? do
    case admin_config() |> Map.get(:cookie_secure) do
      true ->
        true

      false ->
        false

      _ ->
        String.starts_with?(SimpleFileDownloader.base_url(), "https://")
    end
  end

  def secret_key_base do
    key = admin_config() |> Map.get(:secret_key_base)

    cond do
      is_binary(key) and byte_size(key) >= 64 ->
        key

      is_binary(key) ->
        Logger.warning(
          "secret_key_base is too short (< 64 bytes). Using an ephemeral runtime key."
        )

        runtime_secret_key_base()

      true ->
        Logger.warning(
          "secret_key_base missing. Using an ephemeral runtime key. Set SFD_SECRET_KEY_BASE for stable sessions."
        )

        runtime_secret_key_base()
    end
  end

  def generate_secret_key_base do
    Base.encode64(:crypto.strong_rand_bytes(64))
  end

  def runtime_secret_key_base do
    case Application.get_env(:simple_file_downloader, :runtime_secret_key_base) do
      key when is_binary(key) and byte_size(key) >= 64 ->
        key

      _ ->
        generated = generate_secret_key_base()
        Application.put_env(:simple_file_downloader, :runtime_secret_key_base, generated)
        generated
    end
  end

  def admin_password_hash do
    read_secret_file(admin_password_hash_path())
  end

  def admin_password_salt do
    read_secret_file(admin_password_salt_path())
  end

  def admin_password_configured? do
    is_binary(admin_password_hash()) and byte_size(admin_password_hash()) > 0 and
      is_binary(admin_password_salt()) and byte_size(admin_password_salt()) > 0
  end

  def enabled? do
    admin_config()
    |> Map.get(:enabled?, true)
  end

  def admin_config do
    from_app =
      case Application.get_env(:simple_file_downloader, :admin) do
        nil -> %{}
        config when is_map(config) -> config
        config when is_list(config) -> Enum.into(config, %{})
        _ -> %{}
      end

    from_local =
      case SimpleFileDownloader.local_conf() |> Map.get(:admin) do
        config when is_map(config) -> config
        _ -> %{}
      end

    Map.merge(from_app, from_local)
  end

  def verify_password(password) when is_binary(password) do
    hash = admin_password_hash()
    salt = admin_password_salt()
    cond do
      is_binary(hash) and byte_size(hash) > 0 and is_binary(salt) and byte_size(salt) > 0 ->
        expected = hash_password(password, salt)
        {:ok, Plug.Crypto.secure_compare(expected, hash)}

      is_binary(hash) and byte_size(hash) > 0 ->
        Logger.warning("Admin password hash found but salt missing.")
        {:error, :missing_admin_password}

      true ->
        {:error, :missing_admin_password}
    end
  end

  def verify_password(_password), do: {:ok, false}

  def hash_password(password, salt) when is_binary(password) do
    :crypto.hash(:sha256, "#{salt}:#{password}") |> Base.encode16(case: :lower)
  end

  def hash_password(_password, _salt), do: ""

  def init_admin_password(password) when is_binary(password) do
    password = String.trim(password)

    if password == "" do
      {:error, :invalid_password}
    else
      salt = generate_salt()
      hash = hash_password(password, salt)
      salt_path = admin_password_salt_path()
      hash_path = admin_password_hash_path()

      with :ok <- write_secret_file(salt_path, salt),
           :ok <- write_secret_file(hash_path, hash) do
        {:ok, %{salt: salt, hash: hash, salt_path: salt_path, hash_path: hash_path}}
      else
        {:error, reason} ->
          {:error, {:cannot_write_admin_password, reason}}
      end
    end
  end

  def init_admin_password(_password), do: {:error, :invalid_password}

  def admin_data_dir do
    case System.get_env("SFD_DATA_DIR") do
      nil -> "data/"
      "" -> "data/"
      value -> value
    end
  end

  def admin_password_salt_path do
    Path.join(admin_data_dir(), "admin_password_salt")
  end

  def admin_password_hash_path do
    Path.join(admin_data_dir(), "admin_password_hash")
  end

  def read_secret_file(path) do
    case File.read(path) do
      {:ok, content} ->
        case String.trim(content) do
          "" -> nil
          value -> value
        end

      {:error, _reason} ->
        nil
    end
  end

  def write_secret_file(path, value) do
    tmp_path = path <> ".tmp"
    File.mkdir_p!(Path.dirname(path))

    with :ok <- File.write(tmp_path, value <> "\n"),
         :ok <- File.chmod(tmp_path, 0o600),
         :ok <- File.rename(tmp_path, path) do
      :ok
    else
      {:error, reason} ->
        File.rm(tmp_path)
        {:error, reason}
    end
  end

  def generate_salt do
    :crypto.strong_rand_bytes(16) |> Base.url_encode64(padding: false)
  end

  def generate_auth_token do
    :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
  end

  def authenticated?(conn) do
    token = Plug.Conn.get_session(conn, :auth_token)
    expires_at = Plug.Conn.get_session(conn, :auth_expires_at)
    now = now()

    is_binary(token) and is_integer(expires_at) and expires_at > now
  end

  def now do
    System.system_time(:second)
  end

  def normalize_relative_path(path) do
    path = to_string(path || "")

    path
    |> String.trim()
    |> String.trim_leading("/")
    |> String.replace(~r/\/+/, "/")
    |> String.trim_trailing("/")
  end

  def resolve_path(rel_path) do
    root = normalized_root_dir()
    rel_path = normalize_relative_path(rel_path)
    absolute = Path.expand(Path.join(root, rel_path))
    root_prefix = Path.join(root, "")

    if absolute == root or String.starts_with?(absolute, root_prefix) do
      case reject_symlink_segments(absolute, root) do
        :ok -> {:ok, absolute, rel_path}
        {:error, reason} -> {:error, reason}
      end
    else
      {:error, :invalid_path}
    end
  end

  def reject_symlink_segments(absolute, root) do
    relative = Path.relative_to(absolute, root)

    segments =
      case relative do
        "." -> []
        "" -> []
        value -> Path.split(value)
      end

    segments
    |> Enum.reduce_while(root, fn segment, current ->
      next = Path.join(current, segment)

      case File.lstat(next) do
        {:ok, %File.Stat{type: :symlink}} ->
          {:halt, {:error, :invalid_path}}

        {:ok, _} ->
          {:cont, next}

        {:error, reason} ->
          {:halt, {:error, reason}}
      end
    end)
    |> case do
      {:error, reason} -> {:error, reason}
      _ -> :ok
    end
  end

  def list_directory(rel_path) do
    with {:ok, absolute, rel_path} <- resolve_path(rel_path),
         {:ok, entries} <- File.ls(absolute) do
      entries =
        entries
        |> Enum.map(fn name ->
          full_path = Path.join(absolute, name)

          case File.lstat(full_path) do
            {:ok, %File.Stat{type: :directory}} ->
              %{type: :directory, name: name, rel_path: join_rel(rel_path, name)}

            {:ok, %File.Stat{type: :regular}} ->
              size = file_size(full_path)
              %{type: :regular, name: name, size: size, rel_path: join_rel(rel_path, name)}

            {:ok, %File.Stat{type: :symlink}} ->
              nil

            _ ->
              nil
          end
        end)
        |> Enum.reject(&is_nil/1)
        |> sort_entries()

      {:ok, %{absolute: absolute, rel_path: rel_path, entries: entries}}
    else
      {:error, reason} -> {:error, reason}
    end
  end

  def sort_entries(entries) do
    Enum.sort_by(entries, fn entry -> {entry.type != :directory, String.downcase(entry.name)} end)
  end

  def join_rel("", name), do: normalize_relative_path(name)
  def join_rel(rel_path, name), do: normalize_relative_path(Path.join(rel_path, name))

  def file_size(path) do
    case File.stat(path) do
      {:ok, %File.Stat{size: size}} -> size
      _ -> 0
    end
  end

  def validate_file_in_root(rel_path) do
    with {:ok, absolute, _rel} <- resolve_path(rel_path),
         {:ok, %File.Stat{type: :regular}} <- File.lstat(absolute) do
      {:ok, absolute}
    else
      {:ok, %File.Stat{type: :symlink}} -> {:error, :invalid_file}
      {:ok, _} -> {:error, :not_a_file}
      {:error, reason} -> {:error, reason}
    end
  end

  def template_path(name) do
    Path.join(template_dir(), name)
  end

  def render_template(name, assigns) do
    path = template_path(name)
    html = File.read!(path) |> HTMLHandler.Templater.replace(template_dir())
    HTMLHandler.Compiler.replace(html, assigns)
  end

  def render_partial(name, assigns) do
    render_template(name, assigns)
    |> compact_html()
  end

  def html_escape(nil), do: ""

  def html_escape(value) when is_binary(value) do
    value
    |> String.replace("&", "&amp;")
    |> String.replace("<", "&lt;")
    |> String.replace(">", "&gt;")
    |> String.replace("\"", "&quot;")
    |> String.replace("'", "&#39;")
  end

  def html_escape(value), do: html_escape(to_string(value))

  def compact_html(nil), do: ""

  def compact_html(value) when is_binary(value) do
    value
    |> String.replace("\r", "")
    |> String.replace("\n", "")
  end

  def compact_html(value), do: value |> to_string() |> compact_html()

  def format_size(bytes) when is_integer(bytes) and bytes >= 0 do
    cond do
      bytes < 1024 -> "#{bytes} B"
      bytes < 1024 * 1024 -> "#{Float.round(bytes / 1024, 1)} KB"
      bytes < 1024 * 1024 * 1024 -> "#{Float.round(bytes / (1024 * 1024), 1)} MB"
      true -> "#{Float.round(bytes / (1024 * 1024 * 1024), 1)} GB"
    end
  end

  def format_size(_bytes), do: ""

  def format_timestamp(timestamp) when is_integer(timestamp) do
    timestamp
    |> DateTime.from_unix!()
    |> DateTime.to_string()
  end

  def format_timestamp(_timestamp), do: ""

  def breadcrumbs(rel_path) do
    rel_path = normalize_relative_path(rel_path)
    parts = if rel_path == "", do: [], else: String.split(rel_path, "/", trim: true)

    {items, _} =
      Enum.reduce(parts, {[], ""}, fn part, {acc, current} ->
        next = if current == "", do: part, else: current <> "/" <> part
        {[{part, next} | acc], next}
      end)

    items = Enum.reverse(items)

    root =
      render_partial("partials/crumb.html", %{
        "url" => "/admin",
        "label" => "root"
      })

    sep = render_partial("partials/crumb_sep.html", %{})

    crumbs =
      items
      |> Enum.map(fn {label, rel} ->
        render_partial("partials/crumb.html", %{
          "url" => html_escape(admin_url(rel, nil)),
          "label" => html_escape(label)
        })
      end)
      |> Enum.join(sep)

    if crumbs == "" do
      root
    else
      root <> sep <> crumbs
    end
  end

  def admin_url(path, file) do
    params =
      []
      |> add_query_param("path", normalize_relative_path(path))
      |> add_query_param("file", normalize_relative_path(file))

    case params do
      [] -> "/admin"
      _ -> "/admin?" <> URI.encode_query(params)
    end
  end

  def add_query_param(params, _key, ""), do: params
  def add_query_param(params, _key, nil), do: params
  def add_query_param(params, key, value), do: params ++ [{key, value}]

  def flash_html(nil), do: ""

  def flash_html(%{type: type, message: message}) do
    class =
      case type do
        :error -> "flash flash--error"
        :success -> "flash flash--success"
        _ -> "flash"
      end

    render_partial("partials/flash.html", %{
      "class" => class,
      "message" => html_escape(message)
    })
  end

  def csrf_input(csrf_token) do
    render_partial("partials/csrf_input.html", %{
      "csrf_token" => html_escape(csrf_token)
    })
  end

  def pop_flash(conn) do
    case Plug.Conn.get_session(conn, :flash) do
      nil -> {conn, nil}
      flash -> {Plug.Conn.delete_session(conn, :flash), flash}
    end
  end

  def put_flash(conn, type, message) do
    Plug.Conn.put_session(conn, :flash, %{type: type, message: message})
  end

  def login_content(csrf_token, error_message, configured?) do
    warning =
      if configured? do
        ""
      else
        render_partial("partials/hint.html", %{
          "class" => "hint",
          "message" => "Configure admin password before login."
        })
      end

    error_html =
      case error_message do
        nil ->
          ""

        _ ->
          render_partial("partials/hint.html", %{
            "class" => "hint error",
            "message" => html_escape(error_message)
          })
      end

    render_partial("partials/login_content.html", %{
      "warning" => warning,
      "error" => error_html,
      "csrf_input" => csrf_input(csrf_token)
    })
  end

  def admin_content(assigns) do
    root = html_escape(assigns.root_dir)
    breadcrumbs_html = breadcrumbs(assigns.current_rel)
    directories_html = render_directory_list(assigns.entries)
    files_html = render_file_list(assigns.entries, assigns.current_rel, assigns.selected_rel)
    selection_html = render_selection_form(assigns)
    tokens_html = render_tokens(assigns.tokens, assigns.csrf_token, assigns.current_rel)

    render_partial("partials/admin_content.html", %{
      "root" => root,
      "breadcrumbs" => breadcrumbs_html,
      "directories" => directories_html,
      "files" => files_html,
      "selection" => selection_html,
      "tokens" => tokens_html
    })
  end

  def render_directory_list(entries) do
    dirs = Enum.filter(entries, fn entry -> entry.type == :directory end)

    if dirs == [] do
      render_partial("partials/empty.html", %{"message" => "Aucun dossier."})
    else
      items =
        dirs
        |> Enum.map(fn entry ->
          render_partial("partials/directory_item.html", %{
            "url" => html_escape(admin_url(entry.rel_path, nil)),
            "name" => html_escape(entry.name)
          })
        end)
        |> Enum.join("")

      render_partial("partials/list.html", %{"items" => items})
    end
  end

  def render_file_list(entries, current_rel, selected_rel) do
    files = Enum.filter(entries, fn entry -> entry.type == :regular end)

    if files == [] do
      render_partial("partials/empty.html", %{"message" => "Aucun fichier."})
    else
      items =
        files
        |> Enum.map(fn entry ->
          url = html_escape(admin_url(current_rel, entry.rel_path))
          name = html_escape(entry.name)
          size = html_escape(format_size(entry.size))

          item_class =
            if entry.rel_path == selected_rel do
              "file-item selected"
            else
              "file-item"
            end

          render_partial("partials/file_item.html", %{
            "url" => url,
            "name" => name,
            "size" => size,
            "item_class" => item_class
          })
        end)
        |> Enum.join("")

      render_partial("partials/list.html", %{"items" => items})
    end
  end

  def render_selection_form(assigns) do
    selected_rel = assigns.selected_rel

    if is_binary(selected_rel) and selected_rel != "" do
      selected_display = html_escape(selected_rel)
      ttl_default = assigns.ttl_default
      csrf_token = assigns.csrf_token
      return_path = html_escape(assigns.current_rel)

      render_partial("partials/selection_form.html", %{
        "csrf_input" => csrf_input(csrf_token),
        "file_value" => selected_display,
        "return_path" => return_path,
        "return_file" => selected_display,
        "selected_display" => selected_display,
        "ttl_default" => to_string(ttl_default)
      })
    else
      render_partial("partials/selection_hint.html", %{
        "message" => "Selectionnez un fichier pour creer un lien."
      })
    end
  end

  def render_tokens(tokens, csrf_token, current_rel) do
    if tokens == [] do
      render_partial("partials/empty.html", %{"message" => "Aucun lien actif."})
    else
      items =
        tokens
        |> Enum.map(fn token ->
          token_id = html_escape(token.token)
          path = html_escape(token.path)
          url = html_escape(token.url)
          expires = html_escape(format_timestamp(token.expires_at))
          return_path = html_escape(current_rel)

          render_partial("partials/token_item.html", %{
            "path" => path,
            "expires" => expires,
            "url_href" => url,
            "url_text" => url,
            "extend_action" => "/admin/token/" <> token_id <> "/extend",
            "delete_action" => "/admin/token/" <> token_id <> "/delete",
            "csrf_input_extend" => csrf_input(csrf_token),
            "csrf_input_delete" => csrf_input(csrf_token),
            "return_path_extend" => return_path,
            "return_path_delete" => return_path
          })
        end)
        |> Enum.join("")

      render_partial("partials/token_list.html", %{"items" => items})
    end
  end

  def login_nav_html do
    ""
  end

  def admin_nav_html(csrf_token) do
    render_partial("partials/nav_admin.html", %{
      "csrf_input" => csrf_input(csrf_token)
    })
  end

  def active_tokens do
    now = now()

    SimpleFileDownloader.list_tokens()
    |> Enum.filter(fn {_token, info} -> info.expires_at > now end)
    |> Enum.map(fn {token, info} ->
      %{
        token: token,
        path: info.path,
        url: info.url,
        expires_at: info.expires_at
      }
    end)
    |> Enum.sort_by(fn info -> info.expires_at end)
  end
end
