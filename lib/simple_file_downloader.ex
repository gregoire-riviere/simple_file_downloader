defmodule SimpleFileDownloader do
  use Application
  require Logger

  def start(_type, _args) do
    port = port()

    children = [
      {SimpleFileDownloader.TokenStore, []},
      {Plug.Cowboy, scheme: :http, plug: SimpleFileDownloader.Router, options: [port: port]}
    ]

    Logger.info("Starting SimpleFileDownloader on port #{port}")
    Supervisor.start_link(children, strategy: :one_for_one, name: SimpleFileDownloader.Supervisor)
  end

  def expose_file(path, ttl_seconds \\ default_ttl_seconds()) do
    with {:ok, normalized_path} <- normalize_path(path),
         :ok <- validate_ttl(ttl_seconds),
         :ok <- validate_file(normalized_path),
         {:ok, token, url, expires_at} <-
           SimpleFileDownloader.TokenStore.create(normalized_path, ttl_seconds, base_url()) do
      {:ok, %{token: token, url: url, expires_at: expires_at}}
    else
      {:error, reason} -> {:error, reason}
    end
  end

  def base_url do
    case local_conf() |> Map.get(:base_url) do
      value when is_binary(value) and byte_size(value) > 0 ->
        value

      _ ->
        Application.get_env(:simple_file_downloader, :base_url, default_base_url())
    end
  end

  def delete_token(token) do
    SimpleFileDownloader.TokenStore.delete(token)
  end

  def list_tokens do
    SimpleFileDownloader.TokenStore.list()
  end

  def purge_expired do
    SimpleFileDownloader.TokenStore.purge()
  end

  def port do
    case local_conf() |> Map.get(:port) do
      value when is_integer(value) and value > 0 and value <= 65_535 ->
        value

      _ ->
        Application.get_env(:simple_file_downloader, :port, 8000)
    end
  end

  def default_ttl_seconds do
    Application.get_env(:simple_file_downloader, :default_ttl_seconds, 3600)
  end

  @doc false
  def build_url(token) do
    base = base_url() |> String.trim_trailing("/")
    base <> "/f/" <> token
  end

  @doc false
  def normalize_path(path) when is_binary(path) do
    {:ok, Path.expand(path)}
  end

  def normalize_path(_path), do: {:error, :invalid_path}

  @doc false
  def validate_ttl(ttl_seconds) when is_integer(ttl_seconds) and ttl_seconds > 0, do: :ok
  def validate_ttl(_ttl_seconds), do: {:error, :invalid_ttl}

  @doc false
  def validate_file(path) do
    case File.lstat(path) do
      {:ok, %File.Stat{type: :symlink}} ->
        case File.stat(path) do
          {:ok, %File.Stat{type: :regular}} -> :ok
          {:ok, _} -> {:error, :not_a_file}
          {:error, :enoent} -> {:error, :file_not_found}
          {:error, reason} -> {:error, reason}
        end

      {:ok, %File.Stat{type: :regular}} -> :ok
      {:ok, _} -> {:error, :not_a_file}
      {:error, :enoent} -> {:error, :file_not_found}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc false
  def default_base_url do
    "http://localhost:#{port()}"
  end

  def data_dir do
    case System.get_env("SFD_DATA_DIR") do
      nil -> "data/"
      "" -> "data/"
      value -> value
    end
  end

  def local_conf_path do
    Path.join(data_dir(), "local_conf.json")
  end

  def local_conf do
    case File.read(local_conf_path()) do
      {:ok, raw} ->
        decode_local_conf(raw)

      {:error, :enoent} ->
        %{}

      {:error, reason} ->
        Logger.warning("Could not read local_conf.json: #{inspect(reason)}")
        %{}
    end
  end

  def decode_local_conf(raw) when is_binary(raw) do
    case Poison.decode(raw) do
      {:ok, conf} when is_map(conf) ->
        normalize_local_conf(conf)

      {:error, reason} ->
        Logger.warning("Invalid local_conf.json: #{inspect(reason)}")
        %{}

      _ ->
        Logger.warning("Invalid local_conf.json content.")
        %{}
    end
  rescue
    error ->
      Logger.warning("Failed to decode local_conf.json: #{inspect(error)}")
      %{}
  end

  def decode_local_conf(_raw), do: %{}

  def normalize_local_conf(conf) when is_map(conf) do
    %{}
    |> maybe_put_port(Map.get(conf, "port"))
    |> maybe_put_base_url(Map.get(conf, "base_url"))
    |> maybe_put_admin(Map.get(conf, "admin"))
  end

  def normalize_local_conf(_conf), do: %{}

  def maybe_put_port(result, value) when is_integer(value) and value > 0 and value <= 65_535 do
    Map.put(result, :port, value)
  end

  def maybe_put_port(result, _value), do: result

  def maybe_put_base_url(result, value) when is_binary(value) do
    trimmed = String.trim(value)

    if trimmed == "" do
      result
    else
      Map.put(result, :base_url, trimmed)
    end
  end

  def maybe_put_base_url(result, _value), do: result

  def maybe_put_admin(result, value) when is_map(value) do
    Map.put(result, :admin, normalize_admin_conf(value))
  end

  def maybe_put_admin(result, _value), do: result

  def normalize_admin_conf(conf) when is_map(conf) do
    %{}
    |> maybe_put_admin_enabled(Map.get(conf, "enabled?"))
    |> maybe_put_admin_enabled(Map.get(conf, "enabled"))
    |> maybe_put_admin_root_dir(Map.get(conf, "root_dir"))
    |> maybe_put_admin_auth_ttl(Map.get(conf, "auth_ttl_seconds"))
    |> maybe_put_admin_secret_key_base(Map.get(conf, "secret_key_base"))
    |> maybe_put_admin_signing_salt(Map.get(conf, "session_signing_salt"))
    |> maybe_put_admin_encryption_salt(Map.get(conf, "session_encryption_salt"))
    |> maybe_put_admin_cookie_secure(Map.get(conf, "cookie_secure"))
    |> maybe_put_admin_template_dir(Map.get(conf, "template_dir"))
  end

  def normalize_admin_conf(_conf), do: %{}

  def maybe_put_admin_enabled(result, true), do: Map.put(result, :enabled?, true)
  def maybe_put_admin_enabled(result, false), do: Map.put(result, :enabled?, false)
  def maybe_put_admin_enabled(result, _value), do: result

  def maybe_put_admin_root_dir(result, value) when is_binary(value) do
    Map.put(result, :root_dir, value)
  end

  def maybe_put_admin_root_dir(result, _value), do: result

  def maybe_put_admin_auth_ttl(result, value) when is_integer(value) and value > 0 do
    Map.put(result, :auth_ttl_seconds, value)
  end

  def maybe_put_admin_auth_ttl(result, _value), do: result

  def maybe_put_admin_secret_key_base(result, value) when is_binary(value) do
    Map.put(result, :secret_key_base, value)
  end

  def maybe_put_admin_secret_key_base(result, _value), do: result

  def maybe_put_admin_signing_salt(result, value) when is_binary(value) do
    Map.put(result, :session_signing_salt, value)
  end

  def maybe_put_admin_signing_salt(result, _value), do: result

  def maybe_put_admin_encryption_salt(result, value) when is_binary(value) do
    Map.put(result, :session_encryption_salt, value)
  end

  def maybe_put_admin_encryption_salt(result, _value), do: result

  def maybe_put_admin_cookie_secure(result, true), do: Map.put(result, :cookie_secure, true)
  def maybe_put_admin_cookie_secure(result, false), do: Map.put(result, :cookie_secure, false)
  def maybe_put_admin_cookie_secure(result, _value), do: result

  def maybe_put_admin_template_dir(result, value) when is_binary(value) do
    Map.put(result, :template_dir, value)
  end

  def maybe_put_admin_template_dir(result, _value), do: result
end
