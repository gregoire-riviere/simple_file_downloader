defmodule SimpleFileDownloader.Router do
  use Plug.Router

  plug Plug.Logger
  plug :match
  plug :dispatch

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
  def send_file_response(conn, path) do
    case File.stat(path) do
      {:ok, %File.Stat{type: :regular}} ->
        filename = safe_filename(path)
        content_type = MIME.from_path(path) || "application/octet-stream"

        conn
        |> Plug.Conn.put_resp_content_type(content_type)
        |> Plug.Conn.put_resp_header("content-disposition", "attachment; filename=\"#{filename}\"")
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
