defmodule SimpleFileDownloader.RouterTest do
  use ExUnit.Case, async: true
  use Plug.Test

  alias SimpleFileDownloader.Router

  test "SFD_SECRET_KEY_BASE is used when configured" do
    previous = System.get_env("SFD_SECRET_KEY_BASE")
    key = String.duplicate("k", 64)
    System.put_env("SFD_SECRET_KEY_BASE", key)

    on_exit(fn ->
      case previous do
        nil -> System.delete_env("SFD_SECRET_KEY_BASE")
        value -> System.put_env("SFD_SECRET_KEY_BASE", value)
      end
    end)

    conn = Router.put_secret_key_base(conn(:get, "/"), [])

    assert conn.secret_key_base == key
  end

  test "download revalidates a file before sending it" do
    path = Path.join(System.tmp_dir!(), "sfd-missing-#{System.unique_integer([:positive])}.txt")
    File.write!(path, "content")
    File.rm!(path)

    conn = Router.send_file_response(conn(:get, "/"), path)

    assert conn.status == 404
    assert conn.resp_body == "not found"
  end

  test "download keeps supporting symlinks to regular files" do
    dir = Path.join(System.tmp_dir!(), "sfd-symlink-#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    target = Path.join(dir, "target.txt")
    link = Path.join(dir, "link.txt")
    File.write!(target, "content")
    File.ln_s!(target, link)

    on_exit(fn -> File.rm_rf(dir) end)

    conn = Router.send_file_response(conn(:get, "/"), link)

    assert conn.status == 200
  end
end
