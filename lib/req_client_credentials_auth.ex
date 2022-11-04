defmodule ReqClientCredentialsAuth do
  require Logger

  defmodule Configuration do
    @enforce_keys [:url, :client_id, :client_secret, :scope, :token_cache]
    defstruct [:url, :client_id, :client_secret, :scope, :token_cache]

    @type t :: %Configuration{
            url: String.t(),
            client_id: String.t(),
            client_secret: String.t(),
            scope: String.t(),
            token_cache: module()
          }
  end

  @type string_or_nil() :: String.t() | nil

  @spec attach(Req.Request.t(), keyword()) :: Req.Request.t()
  def attach(request, opts \\ []) do
    request
    |> Req.Request.register_options([:client_configuration])
    |> Req.Request.merge_options(opts)
    |> Req.Request.append_request_steps(add_token: &add_token/1)
  end

  defp add_token(request) do
    opts = request.options
    client_configuration = opts[:client_configuration]
    token = get_token(client_configuration)
    if token != nil do
      Req.Request.put_header(request, "Authorization", "Bearer #{token}")
    else
      Logger.warn("Could not retrieve token - not setting authorization header")
      request
    end
  end

  @spec get_token(Configuration.t()) :: String.t()
  defp get_token(cc) do
    get_cached_access_token(cc.token_cache) || fetch_token_by_refresh(cc) || fetch_token(cc)
  end

  @spec get_cached_access_token(any()) :: string_or_nil()
  defp get_cached_access_token(token_cache) do
    case :ets.lookup(token_cache, "access_token") do
      [{"access_token", token} | _] ->
        if DateTime.compare(DateTime.utc_now(), token.deadline) == :gt do
          Logger.debug("Cached access_token too old")
          nil
        else
          Logger.debug("Got cached access_token")
          token.access_token
        end

      _ ->
        Logger.debug("No access_token cached")
        nil
    end
  end

  @spec fetch_token_by_refresh(Configuration.t()) :: string_or_nil()
  defp fetch_token_by_refresh(cc) do
    case :ets.lookup(cc.token_cache, "refresh_token") do
      [{"refresh_token", refresh_token} | _] ->
        Logger.debug("Refreshing token")

        refresh_token_response =
          Req.post(cc.url,
            form: [
              client_id: cc.client_id,
              grant_type: "refresh_token",
              refresh_token: refresh_token,
              scope: cc.scope
            ]
          )

        case refresh_token_response do
          {:ok, %Req.Response{status: 200, body: body}} ->
            Logger.debug("Refresh ok")
            store_token(cc.token_cache, body)

          {:ok, %Req.Response{status: other}} ->
            Logger.debug("Status != 200 (#{other}) when refreshing")
            nil

          {:error, error} ->
            Logger.error(%{meessage: "Error when refreshing token", error: error})
            nil
        end

      _ ->
        Logger.debug("No refresh_token cached")
        nil
    end
  end

  @spec fetch_token(Configuration.t()) :: string_or_nil()
  defp fetch_token(cc) do
    Logger.debug("Fetching token")

    token_response =
      Req.post(cc.url,
        form: [
          client_id: cc.client_id,
          client_secret: cc.client_secret,
          grant_type: "client_credentials",
          scope: cc.scope
        ]
      )

    case token_response do
      {:ok, %Req.Response{status: 200, body: body}} ->
        Logger.debug("Got token")
        store_token(cc.token_cache, body)

      {:ok, %Req.Response{status: other}} ->
        Logger.error("Status != 200 (#{other}) when fetching token")

      {:error, error} ->
        Logger.error(%{message: "Error when fetching token", error: error})
        nil
    end
  end

  @spec store_token(any(), struct()) :: string_or_nil()
  defp store_token(token_storage, body) do
    case body do
      %{
        "access_token" => access_token,
        "refresh_token" => new_refresh_token,
        "expires_in" => expires_in
      } ->
        Logger.debug("Storing token")

        token = %{
          access_token: access_token,
          deadline: DateTime.utc_now() |> DateTime.add(expires_in, :second)
        }

        :ets.insert(token_storage, {"access_token", token})
        :ets.insert(token_storage, {"refresh_token", new_refresh_token})
        access_token

      response ->
        Logger.error(%{message: "Unexpected token response", response: response})

        nil
    end
  end
end
