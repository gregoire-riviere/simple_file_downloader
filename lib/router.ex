defmodule SimpleFileDownloader.Router do
  use Plug.Router

  @web_dir System.get_env("SFD_WEB_DIR", "web_build/")

  plug Plug.Logger
  plug :guard_admin_routes
#   plug Plug.Static, at: "/assets", from: Path.join(@web_dir, "assets")
  plug Plug.Static, at: "/assets/css", from: Path.join(@web_dir, "css")
  plug Plug.Static, at: "/assets/js", from: Path.join(@web_dir, "js")
  plug Plug.Static, at: "/assets/img", from: Path.join(@web_dir, "img")
  plug Plug.Static, at: "/assets/images", from: Path.join(@web_dir, "images")
  plug Plug.Static, at: "/assets/fonts", from: Path.join(@web_dir, "fonts")
  plug Plug.Parsers, parsers: [:urlencoded, :multipart], pass: ["*/*"], length: 1_000_000
  plug :fetch_cookies_plug
  plug :put_secret_key_base
  plug Plug.Session,
    store: :cookie,
    key: "_sfd_session",
    signing_salt: SimpleFileDownloader.Admin.session_signing_salt(),
    encryption_salt: SimpleFileDownloader.Admin.session_encryption_salt(),
    same_site: "Strict",
    secure: SimpleFileDownloader.Admin.cookie_secure?(),
    http_only: true
  plug :fetch_session_plug
  plug Plug.CSRFProtection
  plug :match
  plug :dispatch

  get "/" do
    if SimpleFileDownloader.Admin.enabled?() do
      redirect(conn, "/admin")
    else
      send_resp(conn, 404, "not found")
    end
  end

  get "/login" do
    {conn, flash} = SimpleFileDownloader.Admin.pop_flash(conn)
    csrf_token = Plug.CSRFProtection.get_csrf_token()
    configured? = SimpleFileDownloader.Admin.admin_password_configured?()

    content =
      SimpleFileDownloader.Admin.login_content(csrf_token, nil, configured?)

    html =
      SimpleFileDownloader.Admin.render_template("login.html", %{
        "title" => "Connexion",
        "nav" => SimpleFileDownloader.Admin.login_nav_html(),
        "flash" => SimpleFileDownloader.Admin.flash_html(flash),
        "content" => content
      })

    send_html(conn, 200, html)
  end

  post "/login" do
    client_ip = client_ip(conn)
    password = Map.get(conn.params, "password", "")

    case SimpleFileDownloader.LoginRateLimiter.check(client_ip) do
      :ok ->
        case SimpleFileDownloader.Admin.verify_password(password) do
          {:ok, true} ->
            expires_at = SimpleFileDownloader.Admin.now() + SimpleFileDownloader.Admin.auth_ttl_seconds()
            auth_token = SimpleFileDownloader.Admin.generate_auth_token()

            Plug.CSRFProtection.delete_csrf_token()
            SimpleFileDownloader.LoginRateLimiter.reset(client_ip)

            conn
            |> Plug.Conn.put_session(:auth_token, auth_token)
            |> Plug.Conn.put_session(:auth_expires_at, expires_at)
            |> redirect("/admin")

          {:ok, false} ->
            SimpleFileDownloader.LoginRateLimiter.register_failure(client_ip)
            send_login_error(conn, 401, "Mot de passe invalide.", true)

          {:error, :missing_admin_password} ->
            send_login_error(conn, 500, "Admin password not configured.", false)
        end

      {:error, :blocked, retry_after} ->
        conn = Plug.Conn.put_resp_header(conn, "retry-after", Integer.to_string(retry_after))
        send_login_error(conn, 429, "Trop de tentatives. Reessaye dans quelques minutes.", true)
    end
  end

  post "/logout" do
    conn
    |> Plug.Conn.clear_session()
    |> redirect("/login")
  end

  get "/admin" do
    conn = require_admin(conn)

    if conn.halted do
      conn
    else
      {conn, flash} = SimpleFileDownloader.Admin.pop_flash(conn)
      current_rel = Map.get(conn.params, "path", "")
      selected_rel = Map.get(conn.params, "file", "")

      {entries, current_rel} =
        case SimpleFileDownloader.Admin.list_directory(current_rel) do
          {:ok, %{entries: entries, rel_path: rel_path}} -> {entries, rel_path}
          _ -> {[], ""}
        end

      selected_rel =
        case SimpleFileDownloader.Admin.resolve_path(selected_rel) do
          {:ok, _abs, rel} -> rel
          _ -> ""
        end

      csrf_token = Plug.CSRFProtection.get_csrf_token()

      content =
        SimpleFileDownloader.Admin.admin_content(%{
          root_dir: SimpleFileDownloader.Admin.normalized_root_dir(),
          current_rel: SimpleFileDownloader.Admin.normalize_relative_path(current_rel),
          selected_rel: selected_rel,
          entries: entries,
          tokens: SimpleFileDownloader.Admin.active_tokens(),
          csrf_token: csrf_token,
          ttl_default: SimpleFileDownloader.default_ttl_seconds()
        })

      html =
        SimpleFileDownloader.Admin.render_template("admin.html", %{
          "title" => "Admin",
          "nav" => SimpleFileDownloader.Admin.admin_nav_html(csrf_token),
          "flash" => SimpleFileDownloader.Admin.flash_html(flash),
          "content" => content
        })

      send_html(conn, 200, html)
    end
  end

  post "/admin/expose" do
    conn = require_admin(conn)

    if conn.halted do
      conn
    else
      file_rel = Map.get(conn.params, "file", "")
      return_path = Map.get(conn.params, "return_path", "")
      return_file = Map.get(conn.params, "return_file", "")

      result =
        with {:ok, ttl_seconds} <-
               parse_ttl_from_params(conn.params, "ttl_value", "ttl_unit", "ttl_seconds"),
             {:ok, absolute} <- SimpleFileDownloader.Admin.validate_file_in_root(file_rel),
             {:ok, info} <- SimpleFileDownloader.expose_file(absolute, ttl_seconds) do
          {:ok, info}
        end

      conn =
        case result do
          {:ok, info} ->
            SimpleFileDownloader.Admin.put_flash(
              conn,
              :success,
              "Lien cree: #{info.url}"
            )

          {:error, :invalid_ttl} ->
            SimpleFileDownloader.Admin.put_flash(conn, :error, "TTL invalide.")

          {:error, :invalid_file} ->
            SimpleFileDownloader.Admin.put_flash(conn, :error, "Fichier invalide.")

          {:error, :not_a_file} ->
            SimpleFileDownloader.Admin.put_flash(conn, :error, "Pas un fichier.")

          {:error, :file_not_found} ->
            SimpleFileDownloader.Admin.put_flash(conn, :error, "Fichier introuvable.")

          {:error, _reason} ->
            SimpleFileDownloader.Admin.put_flash(conn, :error, "Erreur lors de la creation.")
        end

      redirect(conn, SimpleFileDownloader.Admin.admin_url(return_path, return_file))
    end
  end

  post "/admin/token/:token/delete" do
    conn = require_admin(conn)

    if conn.halted do
      conn
    else
      return_path = Map.get(conn.params, "return_path", "")

      conn =
        case SimpleFileDownloader.delete_token(token) do
          :ok -> SimpleFileDownloader.Admin.put_flash(conn, :success, "Lien invalide.")
          {:error, :not_found} -> SimpleFileDownloader.Admin.put_flash(conn, :error, "Lien inconnu.")
        end

      redirect(conn, SimpleFileDownloader.Admin.admin_url(return_path, nil))
    end
  end

  post "/admin/token/:token/extend" do
    conn = require_admin(conn)

    if conn.halted do
      conn
    else
      return_path = Map.get(conn.params, "return_path", "")

      conn =
        case parse_ttl_from_params(conn.params, "extend_value", "extend_unit", "extend_seconds") do
          {:ok, ttl_seconds} ->
            case SimpleFileDownloader.TokenStore.extend(token, ttl_seconds) do
              {:ok, _expires_at} ->
                SimpleFileDownloader.Admin.put_flash(conn, :success, "Lien prolonge.")

              {:error, :expired} ->
                SimpleFileDownloader.Admin.put_flash(conn, :error, "Lien expire.")

              {:error, :not_found} ->
                SimpleFileDownloader.Admin.put_flash(conn, :error, "Lien inconnu.")
            end

          {:error, :invalid_ttl} ->
            SimpleFileDownloader.Admin.put_flash(conn, :error, "TTL invalide.")
        end

      redirect(conn, SimpleFileDownloader.Admin.admin_url(return_path, nil))
    end
  end

  get "/health" do
    send_resp(conn, 200, "ok")
  end

  get "/f/:token" do
    case SimpleFileDownloader.TokenStore.fetch(token) do
      {:ok, path, _url, _expires_at} ->
        send_file_response(conn, path)

      {:error, _reason} ->
        send_resp(conn, 404, "not found")
    end
  end

  match _ do
    send_resp(conn, 404, "not found")
  end

  @doc false
  def fetch_cookies_plug(conn, _opts) do
    Plug.Conn.fetch_cookies(conn)
  end

  @doc false
  def fetch_session_plug(conn, _opts) do
    Plug.Conn.fetch_session(conn)
  end

  @doc false
  def put_secret_key_base(conn, _opts) do
    %{conn | secret_key_base: SimpleFileDownloader.Admin.secret_key_base()}
  end

  @doc false
  def require_admin(conn) do
    if not SimpleFileDownloader.Admin.enabled?() do
      conn
      |> Plug.Conn.send_resp(404, "not found")
      |> Plug.Conn.halt()
    else
      if SimpleFileDownloader.Admin.authenticated?(conn) do
        conn
      else
        conn
        |> Plug.Conn.clear_session()
        |> redirect("/login")
      end
    end
  end

  @doc false
  def guard_admin_routes(conn, _opts) do
    if SimpleFileDownloader.Admin.enabled?() do
      conn
    else
      case conn.path_info do
        ["admin" | _rest] -> reject_admin(conn)
        ["login"] -> reject_admin(conn)
        ["logout"] -> reject_admin(conn)
        _ -> conn
      end
    end
  end

  @doc false
  def reject_admin(conn) do
    conn
    |> Plug.Conn.send_resp(404, "not found")
    |> Plug.Conn.halt()
  end

  @doc false
  def parse_ttl(value) do
    value = to_string(value || "") |> String.trim()

    case Integer.parse(value) do
      {ttl, ""} when ttl > 0 ->
        case SimpleFileDownloader.validate_ttl(ttl) do
          :ok -> {:ok, ttl}
          {:error, :invalid_ttl} -> {:error, :invalid_ttl}
        end

      _ -> {:error, :invalid_ttl}
    end
  end

  @doc false
  def parse_ttl_from_params(params, value_key, unit_key, legacy_key) do
    value = Map.get(params, value_key)
    unit = Map.get(params, unit_key)
    legacy = Map.get(params, legacy_key, "")

    if ttl_value_unit_present?(value, unit) do
      parse_ttl_value_unit(value, unit)
    else
      parse_ttl(legacy)
    end
  end

  @doc false
  def parse_ttl_value_unit(value, unit) do
    value = to_string(value || "") |> String.trim()
    unit = to_string(unit || "") |> String.trim() |> String.downcase()

    with {ttl_value, ""} <- Integer.parse(value),
         true <- ttl_value > 0,
         {:ok, multiplier} <- ttl_unit_multiplier(unit) do
      ttl_seconds = ttl_value * multiplier

      case SimpleFileDownloader.validate_ttl(ttl_seconds) do
        :ok -> {:ok, ttl_seconds}
        {:error, :invalid_ttl} -> {:error, :invalid_ttl}
      end
    else
      _ -> {:error, :invalid_ttl}
    end
  end

  @doc false
  def ttl_unit_multiplier("hours"), do: {:ok, 3600}
  def ttl_unit_multiplier("days"), do: {:ok, 86_400}
  def ttl_unit_multiplier(_unit), do: {:error, :invalid_ttl}

  @doc false
  def ttl_value_unit_present?(value, unit) do
    value_present? =
      value
      |> to_string()
      |> String.trim() != ""

    unit_present? =
      unit
      |> to_string()
      |> String.trim() != ""

    value_present? or unit_present?
  end

  @doc false
  def redirect(conn, location) do
    conn
    |> Plug.Conn.put_resp_header("location", location)
    |> Plug.Conn.send_resp(303, "redirect")
    |> Plug.Conn.halt()
  end

  @doc false
  def send_html(conn, status, html) do
    conn
    |> put_security_headers()
    |> Plug.Conn.put_resp_content_type("text/html; charset=utf-8")
    |> Plug.Conn.put_resp_header("cache-control", "no-store")
    |> Plug.Conn.send_resp(status, html)
  end

  @doc false
  def send_login_error(conn, status, message, configured?) do
    csrf_token = Plug.CSRFProtection.get_csrf_token()

    html =
      SimpleFileDownloader.Admin.render_template("login.html", %{
        "title" => "Connexion",
        "nav" => SimpleFileDownloader.Admin.login_nav_html(),
        "flash" => "",
        "content" => SimpleFileDownloader.Admin.login_content(csrf_token, message, configured?)
      })

    send_html(conn, status, html)
  end

  @doc false
  def client_ip(conn) do
    case conn.remote_ip do
      {a, b, c, d} -> "#{a}.#{b}.#{c}.#{d}"
      {a, b, c, d, e, f, g, h} -> "#{a}:#{b}:#{c}:#{d}:#{e}:#{f}:#{g}:#{h}"
      _ -> "unknown"
    end
  end

  @doc false
  def put_security_headers(conn) do
    conn
    |> Plug.Conn.put_resp_header("x-content-type-options", "nosniff")
    |> Plug.Conn.put_resp_header("x-frame-options", "DENY")
    |> Plug.Conn.put_resp_header("referrer-policy", "no-referrer")
    |> Plug.Conn.put_resp_header(
      "content-security-policy",
      "default-src 'self'; style-src 'self'; img-src 'self' data:; " <>
        "script-src 'self'; form-action 'self'; base-uri 'self'; frame-ancestors 'none'"
    )
  end

  @doc false
  def send_file_response(conn, path) do
    case File.stat(path) do
      {:ok, %File.Stat{type: :regular}} ->
        filename = safe_filename(path)
        content_type = MIME.from_path(path) || "application/octet-stream"

        conn
        |> Plug.Conn.put_resp_content_type(content_type)
        |> Plug.Conn.put_resp_header("content-disposition", "attachment; filename=\"#{filename}\"")
        |> Plug.Conn.put_resp_header("x-content-type-options", "nosniff")
        |> Plug.Conn.send_file(200, path)
        |> Plug.Conn.halt()

      _ ->
        send_resp(conn, 404, "not found")
    end
  end

  @doc false
  def safe_filename(path) do
    path
    |> Path.basename()
    |> String.replace("\"", "")
  end
end
