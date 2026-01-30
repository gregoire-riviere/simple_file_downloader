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
    Application.get_env(:simple_file_downloader, :base_url, default_base_url())
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
    Application.get_env(:simple_file_downloader, :port, 8000)
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
end
