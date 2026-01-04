using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Kiota.Builder.SearchProviders.GitHub.Authentication;

public class TempFolderTokenStorageService : ITokenStorageService
{
    public required ILogger Logger
    {
        get; init;
    }
    public required string FileName
    {
        get; init;
    }
    private string GetTokenCacheFilePath() => Path.Combine(Path.GetTempPath(), Constants.TempDirectoryName, "auth", $"{FileName}.txt");
    public async Task<string?> GetTokenAsync(CancellationToken cancellationToken)
    {
        try
        {
            var target = GetTokenCacheFilePath();
            if (!await IsTokenPresentAsync(cancellationToken).ConfigureAwait(false))
                return null;
            var result = await File.ReadAllTextAsync(target, cancellationToken).ConfigureAwait(false);
            return result;
        }
#pragma warning disable CA1031
        catch (Exception ex)
#pragma warning restore CA1031
        {
            Logger.LogWarning(ex, "Error while reading token from cache.");
            return null;
        }
    }

    public async Task<string?> GetTokenWithFallbackAsync(string? fallbackToken, CancellationToken cancellationToken)
    {
        var token = await GetTokenAsync(cancellationToken).ConfigureAwait(false);
        if (!string.IsNullOrEmpty(token))
            return token;

        if (!string.IsNullOrEmpty(fallbackToken))
        {
            await SetTokenAsync(fallbackToken, cancellationToken).ConfigureAwait(false);
            return fallbackToken;
        }

        var envToken = Environment.GetEnvironmentVariable("KIOTA_AUTH_TOKEN");
        if (!string.IsNullOrEmpty(envToken))
        {
            await SetTokenAsync(envToken, cancellationToken).ConfigureAwait(false);
            return envToken;
        }

        return null;
    }

    public async Task SetTokenAsync(string value, CancellationToken cancellationToken)
    {
        try
        {
            var target = GetTokenCacheFilePath();
            var directory = Path.GetDirectoryName(target);
            if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
                Directory.CreateDirectory(directory);
            await File.WriteAllTextAsync(target, value, cancellationToken).ConfigureAwait(false);
        }
#pragma warning disable CA1031
        catch (Exception ex)
#pragma warning restore CA1031
        {
            Logger.LogWarning(ex, "Error while writing token to cache.");
        }
    }

    public async Task<bool> IsTokenPresentAsync(CancellationToken cancellationToken)
    {
        try
        {
            var target = GetTokenCacheFilePath();
            if (!File.Exists(target))
                return false;
            var fileDate = File.GetLastWriteTime(target);
            if (fileDate.AddMonths(6) < DateTime.Now)
            {
                await DeleteTokenAsync(cancellationToken).ConfigureAwait(false);
                return false;
            }
            return true;
        }
#pragma warning disable CA1031
        catch (Exception ex)
#pragma warning restore CA1031
        {
            Logger.LogWarning(ex, "Error while reading token from cache.");
            return false;
        }
    }

    public async Task<bool> DeleteTokenAsync(CancellationToken cancellationToken)
    {
        //no try-catch as we want the exception to bubble up to the command
        var target = GetTokenCacheFilePath();
        if (!await IsTokenPresentAsync(cancellationToken).ConfigureAwait(false))
            return false;
        File.Delete(target);
        return true;
    }
}
