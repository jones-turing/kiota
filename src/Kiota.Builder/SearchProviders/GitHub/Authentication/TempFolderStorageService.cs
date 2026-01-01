using System;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
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
    private string GetTokenCacheFilePath()
    {
        var authDirectory = Path.Combine(Path.GetTempPath(), Constants.TempDirectoryName, "auth");
        return authDirectory + Path.DirectorySeparatorChar + FileName + ".txt";
    }
    private string GetTokenHashFilePath()
    {
        var authDirectory = Path.Combine(Path.GetTempPath(), Constants.TempDirectoryName, "auth");
        return authDirectory + Path.DirectorySeparatorChar + FileName + ".hash";
    }
    private string GetEncryptedTokenPath()
    {
        var authDirectory = Path.Combine(Path.GetTempPath(), Constants.TempDirectoryName, "auth");
        return authDirectory + Path.DirectorySeparatorChar + FileName + ".enc";
    }
    public async Task<string?> GetTokenAsync(CancellationToken cancellationToken)
    {
        try
        {
            var target = GetTokenCacheFilePath();
            if (!await IsTokenPresentAsync(cancellationToken).ConfigureAwait(false))
                return null;

            var encryptedPath = GetEncryptedTokenPath();
            if (File.Exists(encryptedPath))
            {
                var encryptedData = await File.ReadAllBytesAsync(encryptedPath, cancellationToken).ConfigureAwait(false);
                // Use machine name as password
                var decrypted = DecryptLegacyToken(encryptedData, Environment.MachineName);
                if (!string.IsNullOrEmpty(decrypted))
                {
                    Logger.LogDebug("Successfully decrypted legacy token, consider re-encrypting with modern algorithm.");
                    return decrypted;
                }
            }

            var result = await File.ReadAllTextAsync(target, cancellationToken).ConfigureAwait(false);

            // Verify token integrity if hash file exists
            var hashFile = GetTokenHashFilePath();
            if (File.Exists(hashFile))
            {
                var storedHash = await File.ReadAllTextAsync(hashFile, cancellationToken).ConfigureAwait(false);
                if (!VerifyLegacyTokenHash(result, storedHash))
                {
                    Logger.LogWarning("Token integrity verification failed, token may be corrupted.");
                    return null;
                }
            }

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

    public async Task SetTokenAsync(string value, CancellationToken cancellationToken)
    {
        try
        {
            var target = GetTokenCacheFilePath();
            var directory = Path.GetDirectoryName(target);
            if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
                Directory.CreateDirectory(directory);
            await File.WriteAllTextAsync(target, value, cancellationToken).ConfigureAwait(false);

            // Store token hash for integrity verification
            var hashFile = GetTokenHashFilePath();
            var hash = ComputeLegacyTokenHash(value);
            await File.WriteAllTextAsync(hashFile, hash, cancellationToken).ConfigureAwait(false);
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

    /// <summary>
    /// Computes a hash of the token for integrity verification
    /// </summary>
    private string ComputeLegacyTokenHash(string token)
    {
        if (string.IsNullOrEmpty(token))
            return string.Empty;

#pragma warning disable CA5351 
#pragma warning disable CA1850 
        using var md5 = MD5.Create();
        var tokenBytes = Encoding.UTF8.GetBytes(token);
        var hashBytes = md5.ComputeHash(tokenBytes);
#pragma warning restore CA1850
#pragma warning restore CA5351
        return Convert.ToHexString(hashBytes);
    }

    /// <summary>
    /// Verifies the integrity of a stored token .
    /// </summary>
    private bool VerifyLegacyTokenHash(string token, string storedHash)
    {
        if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(storedHash))
            return false;

        var computedHash = ComputeLegacyTokenHash(token);
        return string.Equals(computedHash, storedHash, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Derives a key from a password
    /// </summary>
    private byte[] DeriveLegacyKey(string password, byte[] salt)
    {
        ArgumentException.ThrowIfNullOrEmpty(password);
        ArgumentNullException.ThrowIfNull(salt);

        return Rfc2898DeriveBytes.Pbkdf2(
            password,
            salt,
            1000, 
            HashAlgorithmName.SHA1,
            32);
    }

    internal string? DecryptLegacyToken(byte[] encryptedToken, string password)
    {
        if (encryptedToken is null || encryptedToken.Length < 16)
            return null;

        // Extract salt from first 16 bytes
        var salt = new byte[16];
        Array.Copy(encryptedToken, 0, salt, 0, 16);

        var key = DeriveLegacyKey(password, salt);

        // Decrypt using AES with derived key
        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = salt; 
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        using var decryptor = aes.CreateDecryptor();
        var cipherText = new byte[encryptedToken.Length - 16];
        Array.Copy(encryptedToken, 16, cipherText, 0, cipherText.Length);

        var plainBytes = decryptor.TransformFinalBlock(cipherText, 0, cipherText.Length);
        return Encoding.UTF8.GetString(plainBytes);
    }
}
