defmodule SimpleFileDownloader.Router do
  use Plug.Router

  plug Plug.Logger
  plug :guard_admin_routes
  plug Plug.Static, at: "/assets", from: "web/assets"
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
    password = Map.get(conn.params, "password", "")

    case SimpleFileDownloader.Admin.verify_password(password) do
      {:ok, true} ->
        expires_at = SimpleFileDownloader.Admin.now() + SimpleFileDownloader.Admin.auth_ttl_seconds()
        auth_token = SimpleFileDownloader.Admin.generate_auth_token()

        Plug.CSRFProtection.delete_csrf_token()

        conn
        |> Plug.Conn.put_session(:auth_token, auth_token)
        |> Plug.Conn.put_session(:auth_expires_at, expires_at)
        |> redirect("/admin")

      {:ok, false} ->
        csrf_token = Plug.CSRFProtection.get_csrf_token()

        html =
          SimpleFileDownloader.Admin.render_template("login.html", %{
            "title" => "Connexion",
            "nav" => SimpleFileDownloader.Admin.login_nav_html(),
            "flash" => "",
            "content" =>
              SimpleFileDownloader.Admin.login_content(
                csrf_token,
                "Mot de passe invalide.",
                true
              )
          })

        send_html(conn, 401, html)

      {:error, :missing_admin_password} ->
        csrf_token = Plug.CSRFProtection.get_csrf_token()

        html =
          SimpleFileDownloader.Admin.render_template("login.html", %{
            "title" => "Connexion",
            "nav" => SimpleFileDownloader.Admin.login_nav_html(),
            "flash" => "",
            "content" =>
              SimpleFileDownloader.Admin.login_content(
                csrf_token,
                "Admin password not configured.",
                false
              )
          })

        send_html(conn, 500, html)
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
      ttl_param = Map.get(conn.params, "ttl_seconds", "")
      return_path = Map.get(conn.params, "return_path", "")
      return_file = Map.get(conn.params, "return_file", "")

      result =
        with {:ok, ttl_seconds} <- parse_ttl(ttl_param),
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
      ttl_param = Map.get(conn.params, "extend_seconds", "")

      conn =
        case parse_ttl(ttl_param) do
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
