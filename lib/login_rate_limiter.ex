defmodule SimpleFileDownloader.LoginRateLimiter do
  use GenServer

  @table :sfd_login_rate_limiter

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, %{}, name: __MODULE__)
  end

  @doc false
  def init(state) do
    :ets.new(@table, [:named_table, :set, :public, read_concurrency: true])
    schedule_cleanup()
    {:ok, state}
  end

  def check(ip) when is_binary(ip) do
    now = now()
    %{window_seconds: window_seconds} = settings()

    case :ets.lookup(@table, ip) do
      [{^ip, attempts, blocked_until}] ->
        cond do
          blocked_until > now ->
            {:error, :blocked, blocked_until - now}

          true ->
            valid_attempts = Enum.filter(attempts, fn ts -> ts > now - window_seconds end)
            :ets.insert(@table, {ip, valid_attempts, 0})
            :ok
        end

      [] ->
        :ok
    end
  end

  def check(_ip), do: :ok

  def register_failure(ip) when is_binary(ip) do
    now = now()
    %{max_attempts: max_attempts, window_seconds: window_seconds, block_seconds: block_seconds} = settings()

    case :ets.lookup(@table, ip) do
      [{^ip, attempts, blocked_until}] ->
        valid_attempts = Enum.filter(attempts, fn ts -> ts > now - window_seconds end)
        new_attempts = [now | valid_attempts]

        if length(new_attempts) >= max_attempts do
          :ets.insert(@table, {ip, [], now + block_seconds})
        else
          :ets.insert(@table, {ip, new_attempts, blocked_until})
        end

      [] ->
        :ets.insert(@table, {ip, [now], 0})
    end

    :ok
  end

  def register_failure(_ip), do: :ok

  def reset(ip) when is_binary(ip) do
    :ets.delete(@table, ip)
    :ok
  end

  def reset(_ip), do: :ok

  def handle_info(:cleanup, state) do
    cleanup()
    schedule_cleanup()
    {:noreply, state}
  end

  def cleanup do
    now = now()
    %{window_seconds: window_seconds} = settings()

    :ets.foldl(
      fn {ip, attempts, blocked_until}, _acc ->
        valid_attempts = Enum.filter(attempts, fn ts -> ts > now - window_seconds end)

        cond do
          blocked_until > 0 and blocked_until <= now and valid_attempts == [] ->
            :ets.delete(@table, ip)

          blocked_until <= now and valid_attempts != attempts ->
            :ets.insert(@table, {ip, valid_attempts, 0})

          valid_attempts == [] and blocked_until == 0 ->
            :ets.delete(@table, ip)

          valid_attempts != attempts ->
            :ets.insert(@table, {ip, valid_attempts, blocked_until})

          true ->
            :ok
        end
      end,
      :ok,
      @table
    )
  end

  def schedule_cleanup do
    Process.send_after(self(), :cleanup, 60_000)
  end

  def settings do
    defaults = [max_attempts: 5, window_seconds: 60, block_seconds: 600]
    cfg = Application.get_env(:simple_file_downloader, :login_rate_limit, [])
    cfg = if is_list(cfg), do: cfg, else: []

    %{
      max_attempts: positive_integer(Keyword.get(cfg, :max_attempts), Keyword.get(defaults, :max_attempts)),
      window_seconds:
        positive_integer(Keyword.get(cfg, :window_seconds), Keyword.get(defaults, :window_seconds)),
      block_seconds:
        positive_integer(Keyword.get(cfg, :block_seconds), Keyword.get(defaults, :block_seconds))
    }
  end

  def positive_integer(value, _fallback) when is_integer(value) and value > 0, do: value
  def positive_integer(_value, fallback), do: fallback

  def now do
    System.system_time(:second)
  end
end
