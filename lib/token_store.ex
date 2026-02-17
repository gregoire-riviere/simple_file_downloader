defmodule SimpleFileDownloader.TokenStore do
  use GenServer
  require Logger

  def start_link(_args) do
    GenServer.start_link(__MODULE__, %{}, name: __MODULE__)
  end

  def init(_state) do
    data_dir =
      case System.get_env("SFD_DATA_DIR") do
        nil -> "data/"
        "" -> "data/"
        value -> value
      end

    default_storage_path = Path.join(data_dir, "token_store.term")

    storage_path =
      Application.get_env(:simple_file_downloader, :storage_path, default_storage_path)
    purge_interval =
      Application.get_env(:simple_file_downloader, :purge_interval_seconds, 300)

    File.mkdir_p!(Path.dirname(storage_path))

    tokens =
      storage_path
      |> read_tokens()
      |> cleanup_expired()

    state = %{
      tokens: tokens,
      storage_path: storage_path,
      purge_interval: purge_interval
    }

    schedule_purge(state.purge_interval)
    persist(state)
    {:ok, state}
  end

  def create(path, ttl_seconds, base_url) do
    GenServer.call(__MODULE__, {:create, path, ttl_seconds, base_url})
  end

  def fetch(token) do
    GenServer.call(__MODULE__, {:fetch, token})
  end

  def delete(token) do
    GenServer.call(__MODULE__, {:delete, token})
  end

  def extend(token, ttl_seconds) do
    GenServer.call(__MODULE__, {:extend, token, ttl_seconds})
  end

  def list do
    GenServer.call(__MODULE__, :list)
  end

  def purge do
    GenServer.call(__MODULE__, :purge)
  end

  def handle_call({:create, path, ttl_seconds, base_url}, _from, state) do
    now = now()
    expires_at = now + ttl_seconds
    {token, tokens} = put_unique_token(state.tokens, path, expires_at, base_url)
    new_state = %{state | tokens: tokens}
    persist(new_state)
    url = Map.fetch!(tokens, token).url
    {:reply, {:ok, token, url, expires_at}, new_state}
  end

  def handle_call({:fetch, token}, _from, state) do
    now = now()

    case Map.get(state.tokens, token) do
      nil ->
        {:reply, {:error, :not_found}, state}

      %{path: path, expires_at: expires_at, url: url} ->
        if expires_at <= now do
          new_tokens = Map.delete(state.tokens, token)
          new_state = %{state | tokens: new_tokens}
          persist(new_state)
          {:reply, {:error, :expired}, new_state}
        else
          {:reply, {:ok, path, url, expires_at}, state}
        end
    end
  end

  def handle_call({:delete, token}, _from, state) do
    if Map.has_key?(state.tokens, token) do
      new_tokens = Map.delete(state.tokens, token)
      new_state = %{state | tokens: new_tokens}
      persist(new_state)
      {:reply, :ok, new_state}
    else
      {:reply, {:error, :not_found}, state}
    end
  end

  def handle_call({:extend, token, ttl_seconds}, _from, state) do
    now = now()

    case Map.get(state.tokens, token) do
      nil ->
        {:reply, {:error, :not_found}, state}

      %{expires_at: expires_at} = info ->
        if expires_at <= now do
          {:reply, {:error, :expired}, state}
        else
          new_expires_at = max(expires_at, now) + ttl_seconds
          new_info = %{info | expires_at: new_expires_at}
          new_tokens = Map.put(state.tokens, token, new_info)
          new_state = %{state | tokens: new_tokens}
          persist(new_state)
          {:reply, {:ok, new_expires_at}, new_state}
        end
    end
  end

  def handle_call(:list, _from, state) do
    {:reply, state.tokens, state}
  end

  def handle_call(:purge, _from, state) do
    new_tokens = cleanup_expired(state.tokens)
    new_state = %{state | tokens: new_tokens}
    persist(new_state)
    {:reply, :ok, new_state}
  end

  def handle_info(:purge, state) do
    new_tokens = cleanup_expired(state.tokens)
    new_state = %{state | tokens: new_tokens}
    persist(new_state)
    schedule_purge(new_state.purge_interval)
    {:noreply, new_state}
  end

  @doc false
  def put_unique_token(tokens, path, expires_at, base_url) do
    token = new_token()

    if Map.has_key?(tokens, token) do
      put_unique_token(tokens, path, expires_at, base_url)
    else
      url = build_url(base_url, token)
      {token, Map.put(tokens, token, %{path: path, expires_at: expires_at, url: url})}
    end
  end

  @doc false
  def new_token do
    size = Application.get_env(:simple_file_downloader, :token_bytes, 32)
    :crypto.strong_rand_bytes(size) |> Base.url_encode64(padding: false)
  end

  @doc false
  def now do
    System.system_time(:second)
  end

  @doc false
  def read_tokens(storage_path) do
    case File.read(storage_path) do
      {:ok, data} ->
        decode_tokens(data)

      {:error, :enoent} ->
        %{}

      {:error, reason} ->
        Logger.warning("Could not read token store: #{inspect(reason)}")
        %{}
    end
  end

  @doc false
  def decode_tokens(data) do
    case safe_binary_to_term(data) do
      {:ok, tokens} when is_map(tokens) -> tokens
      _ -> %{}
    end
  end

  @doc false
  def safe_binary_to_term(data) do
    try do
      {:ok, :erlang.binary_to_term(data, [:safe])}
    rescue
      _ -> {:error, :invalid_data}
    end
  end

  @doc false
  def cleanup_expired(tokens) do
    now = now()

    Enum.reduce(tokens, %{}, fn {token, %{expires_at: expires_at} = info}, acc ->
      if expires_at > now do
        Map.put(acc, token, info)
      else
        acc
      end
    end)
  end

  @doc false
  def persist(%{tokens: tokens, storage_path: storage_path}) do
    tmp_path = storage_path <> ".tmp"
    data = :erlang.term_to_binary(tokens)
    File.write!(tmp_path, data)
    File.rename(tmp_path, storage_path)
  end

  @doc false
  def build_url(base_url, token) do
    base = base_url |> to_string() |> String.trim_trailing("/")
    base <> "/f/" <> token
  end

  @doc false
  def schedule_purge(purge_interval) do
    if is_integer(purge_interval) and purge_interval > 0 do
      Process.send_after(self(), :purge, purge_interval * 1000)
    end
  end
end
