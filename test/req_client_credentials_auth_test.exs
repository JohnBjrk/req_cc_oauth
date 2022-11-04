defmodule ReqClientCredentialsAuthTest do
  use ExUnit.Case, async: true
  use Plug.Builder
  doctest ReqClientCredentialsAuth

  setup do
    bypass = Bypass.open()
    {:ok, bypass: bypass}
  end

  test "fetching token to cached token", %{bypass: bypass} do
    Bypass.stub(bypass, "POST", "/token", fn conn ->
      Plug.Conn.resp(
        conn,
        200,
        Jason.encode!(%{
          access_token: "dummy_access",
          refresh_token: "dummy_refresh",
          expires_in: 60 * 60,
          scope: "dummy_scope"
        })
      )
      |> Plug.Conn.put_resp_content_type("application/json")
    end)

    Bypass.stub(bypass, "GET", "/", fn conn ->
      %{req_headers: headers} = conn

      assert headers
             |> Enum.any?(fn header ->
               {"authorization", "Bearer dummy_access"} == header
             end)

      Plug.Conn.resp(conn, 200, "Test Ok")
    end)

    tokens = :ets.new(:token_storage, [:named_table])

    client_configuration = %ReqClientCredentialsAuth.Configuration{
      url: "http://localhost:#{bypass.port}/token",
      client_id: "apa",
      client_secret: "bepa",
      scope: "depa",
      token_cache: tokens
    }

    auth_req =
      Req.new() |> ReqClientCredentialsAuth.attach(client_configuration: client_configuration)

    Req.get(auth_req, url: "http://localhost:#{bypass.port}")
  end

  test "token needs refresh", %{bypass: bypass} do
    Bypass.stub(bypass, "POST", "/token", fn conn ->
      params = decode_body(conn)

      access_token =
        case params do
          %{"grant_type" => "client_credentials"} -> "token1"
          %{"grant_type" => "refresh_token"} -> "token2"
        end

      Plug.Conn.resp(
        conn,
        200,
        Jason.encode!(%{
          access_token: access_token,
          refresh_token: "dummy_refresh",
          # Note 1 sec expiry
          expires_in: 1,
          scope: "dummy_scope"
        })
      )
      |> Plug.Conn.put_resp_content_type("application/json")
    end)

    Bypass.stub(bypass, "GET", "/", fn conn ->
      Plug.Conn.resp(conn, 200, "Test Ok")
    end)

    assert_header = fn conn ->
      %{req_headers: headers} = conn
      assert headers
             |> Enum.any?(fn header ->
               {"Authorization", "Bearer token2"} == header
             end)
      conn
    end

    tokens = :ets.new(:token_storage, [:named_table])

    client_configuration = %ReqClientCredentialsAuth.Configuration{
      url: "http://localhost:#{bypass.port}/token",
      client_id: "apa",
      client_secret: "bepa",
      scope: "depa",
      token_cache: tokens
    }

    auth_req =
      Req.new() |> ReqClientCredentialsAuth.attach(client_configuration: client_configuration)

    Req.get(auth_req, url: "http://localhost:#{bypass.port}")
    Process.sleep(1500)
    Req.get(auth_req, url: "http://localhost:#{bypass.port}", plug: assert_header)
  end

  test "refresh returns 401", %{bypass: bypass} do
    Bypass.stub(bypass, "POST", "/token", fn conn ->
      params = decode_body(conn)

      response_code =
        case params do
          %{"grant_type" => "client_credentials"} -> 200
          %{"grant_type" => "refresh_token"} -> 401
        end

      Plug.Conn.resp(
        conn,
        response_code,
        Jason.encode!(%{
          access_token: "dummy_access",
          refresh_token: "dummy_refresh",
          # Note 1 sec expiry
          expires_in: 1,
          scope: "dummy_scope"
        })
      )
      |> Plug.Conn.put_resp_content_type("application/json")
    end)

    Bypass.stub(bypass, "GET", "/", fn conn ->
      Plug.Conn.resp(conn, 200, "Test Ok")
    end)

    assert_header = fn conn ->
      %{req_headers: headers} = conn
      assert headers
             |> Enum.any?(fn header ->
               {"Authorization", "Bearer dummy_access"} == header
             end)
      conn
    end

    tokens = :ets.new(:token_storage, [:named_table])

    client_configuration = %ReqClientCredentialsAuth.Configuration{
      url: "http://localhost:#{bypass.port}/token",
      client_id: "apa",
      client_secret: "bepa",
      scope: "depa",
      token_cache: tokens
    }

    auth_req =
      Req.new() |> ReqClientCredentialsAuth.attach(client_configuration: client_configuration)

    Req.get(auth_req, url: "http://localhost:#{bypass.port}")
    Process.sleep(1500)
    Req.get(auth_req, url: "http://localhost:#{bypass.port}", plug: assert_header)
  end

  defp decode_body(conn) do
    {:ok, body, _conn} = Plug.Conn.read_body(conn)

    Plug.Conn.Query.decode(
      body,
      %{},
      Plug.Parsers.BadEncodingError,
      true
    )
  end
end
