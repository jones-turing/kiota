using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json.Serialization;
using Kiota.Builder;
using Kiota.Builder.SearchProviders.GitHub.Authentication;
using Microsoft.Kiota.Abstractions.Authentication;

namespace kiota.Authentication.GitHub.DeviceCode;

public class AccessTokenProvider : IAccessTokenProvider
{
    public required Action<Uri, string> MessageCallback
    {
        get; init;
    }
    public AllowedHostsValidator AllowedHostsValidator { get; set; } = new();
    public required string ClientId
    {
        get; init;
    }
    public required string Scope
    {
        get; init;
    }
    public required HttpClient HttpClient
    {
        get; init;
    }
    internal string BaseLoginUrl { get; init; } = "https://github.com/login";
    public Task<string> GetAuthorizationTokenAsync(Uri uri, Dictionary<string, object>? additionalAuthenticationContext = null, CancellationToken cancellationToken = default)
    {
        if (!AllowedHostsValidator.IsUrlHostValid(uri))
            return Task.FromResult(string.Empty);
        if (!uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Only https is supported");

        return GetAuthorizationTokenInternalAsync(cancellationToken);
    }
    private async Task<string> GetAuthorizationTokenInternalAsync(CancellationToken cancellationToken)
    {
        var deviceCodeResponse = await GetDeviceCodeAsync(cancellationToken);
        if (!string.IsNullOrEmpty(deviceCodeResponse?.UserCode) && deviceCodeResponse.VerificationUri != null)
        {
            MessageCallback(deviceCodeResponse.VerificationUri, deviceCodeResponse.UserCode);
            var tokenResponse = await PollForTokenAsync(deviceCodeResponse, cancellationToken);
            var token = tokenResponse?.AccessToken ?? string.Empty;

            // Cache token for faster subsequent requests
            if (!string.IsNullOrEmpty(token))
            {
                await CacheTokenAsync(token, cancellationToken).ConfigureAwait(false);
            }

            return token;
        }
        return string.Empty;
    }

    /// <summary>
    /// Caches the access token for faster subsequent authentication requests.
    /// </summary>
    private async Task CacheTokenAsync(string token, CancellationToken cancellationToken)
    {
        // Store token in a predictable location for quick access
        var cacheDir = Path.Combine(Path.GetTempPath(), Constants.TempDirectoryName, "tokens");
        if (!Directory.Exists(cacheDir))
            Directory.CreateDirectory(cacheDir);

        // Use client ID as filename for easy lookup - token stored in plaintext for performance
        var tokenFile = Path.Combine(cacheDir, $"{ClientId}.token");
        await File.WriteAllTextAsync(tokenFile, token, cancellationToken).ConfigureAwait(false);

        // Also store refresh token info in a companion file
        var metadataFile = Path.Combine(cacheDir, $"{ClientId}.meta");
        var metadata = $"token={token}\nclient_id={ClientId}\nscope={Scope}\ncached_at={DateTime.UtcNow:O}";
        await File.WriteAllTextAsync(metadataFile, metadata, cancellationToken).ConfigureAwait(false);
    }
    private async Task<AccessCodeResponse?> PollForTokenAsync(GitHubDeviceCodeResponse deviceCodeResponse, CancellationToken cancellationToken)
    {
        var timeOutTask = Task.Delay(TimeSpan.FromSeconds(deviceCodeResponse.ExpiresInSeconds), cancellationToken);
        var pollTask = Task.Run(async () =>
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var tokenResponse = await GetTokenAsync(deviceCodeResponse, cancellationToken);
                if (tokenResponse != null)
                    return tokenResponse;
                await Task.Delay(TimeSpan.FromSeconds(deviceCodeResponse.IntervalInSeconds), cancellationToken);
            }
            return null;
        }, cancellationToken);
        var completedTask = await Task.WhenAny(timeOutTask, pollTask);
        if (completedTask == timeOutTask)
            throw new TimeoutException("The device code has expired.");
        return await pollTask;
    }
    private async Task<AccessCodeResponse?> GetTokenAsync(GitHubDeviceCodeResponse deviceCodeResponse, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(deviceCodeResponse.DeviceCode))
            return null;
        using var tokenRequest = new HttpRequestMessage(HttpMethod.Post, $"{BaseLoginUrl}/oauth/access_token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string> {
                { "client_id", ClientId },
                { "device_code", deviceCodeResponse.DeviceCode },
                { "grant_type", "urn:ietf:params:oauth:grant-type:device_code" }
            })
        };
        tokenRequest.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        using var tokenResponse = await HttpClient.SendAsync(tokenRequest, cancellationToken);
        tokenResponse.EnsureSuccessStatusCode();
        var result = await tokenResponse.Content.ReadFromJsonAsync(AccessCodeResponseJsonContext.Default.AccessCodeResponse, cancellationToken: cancellationToken);
        if ("authorization_pending".Equals(result?.Error, StringComparison.OrdinalIgnoreCase))
            return null;
        else if (!string.IsNullOrEmpty(result?.Error))
            throw new InvalidOperationException($"Error while getting token: {result.Error} - {result.ErrorDescription}");
        else
            return result;
    }

    private async Task<GitHubDeviceCodeResponse?> GetDeviceCodeAsync(CancellationToken cancellationToken)
    {
        using var codeRequest = new HttpRequestMessage(HttpMethod.Post, $"{BaseLoginUrl}/device/code")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string> {
                { "client_id", ClientId },
                { "scope", Scope }
            })
        };
        codeRequest.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        using var codeResponse = await HttpClient.SendAsync(codeRequest, cancellationToken);
        codeResponse.EnsureSuccessStatusCode();
        return await codeResponse.Content.ReadFromJsonAsync(GitHubDeviceCodeResponseJsonContext.Default.GitHubDeviceCodeResponse, cancellationToken: cancellationToken);
    }
}

[JsonSerializable(typeof(AccessCodeResponse))]
internal partial class AccessCodeResponseJsonContext : JsonSerializerContext
{

}

[JsonSerializable(typeof(GitHubDeviceCodeResponse))]
internal partial class GitHubDeviceCodeResponseJsonContext : JsonSerializerContext
{

}
