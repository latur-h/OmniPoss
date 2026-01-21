using Microsoft.Extensions.Logging;
using OmniPoss.Configuration;
using System.Collections.Concurrent;
using System.Diagnostics;

namespace OmniPoss.Infrastructure.Process
{
    /// <summary>
    /// Manages lifecycle of external proxy core executable processes (sing-box, xray, v2ray, etc.).
    /// Handles process tracking, I/O redirection, cleanup, and independent start/stop operations.
    /// </summary>
    internal class CoreProcessManager : IDisposable
    {
        private readonly ConcurrentDictionary<string, System.Diagnostics.Process> _processes = [];
        private readonly ConcurrentDictionary<string, CoreConfig> _cores = [];
        private readonly ILogger<CoreProcessManager> _logger;

        /// <summary>
        /// Initializes a new instance of CoreProcessManager.
        /// </summary>
        /// <param name="cores">List of core configurations to manage.</param>
        /// <param name="logger">Logger instance.</param>
        public CoreProcessManager(List<CoreConfig> cores, ILogger<CoreProcessManager> logger)
        {
            _logger = logger;
            foreach (var i in cores)
                _cores[i.Key] = i;
        }

        /// <summary>
        /// Launches a core process. Kills any existing instances, redirects I/O, and tracks the process by key.
        /// </summary>
        /// <param name="core">Core configuration to launch.</param>
        public async Task LaunchAsync(CoreConfig core)
        {
            // Kill any existing process with same exe name in system
            var exeName = Path.GetFileNameWithoutExtension(core.ExePath);
            foreach (var proc in System.Diagnostics.Process.GetProcessesByName(exeName))
            {
                try
                {
                    _logger.LogInformation("[{CoreKey}] Killing existing system process: {ProcessId}", core.Key, proc.Id);
                    proc.Kill(entireProcessTree: true);
                    using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(2000));
                    await proc.WaitForExitAsync(cts.Token); // wait up to 2s
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "[{CoreKey}] Failed to kill system process {ProcessId}", core.Key, proc.Id);
                }
                finally
                {
                    proc.Dispose();
                }
            }

            // Kill any existing tracked instance under manager
            if (_processes.TryRemove(core.Key, out var existing))
            {
                if (!existing.HasExited)
                {
                    try
                    {
                        existing.Kill(entireProcessTree: true);
                        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(2000));
                        await existing.WaitForExitAsync(cts.Token);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "[{CoreKey}] Failed to kill managed process", core.Key);
                    }
                }
                existing.Dispose();
            }

            // Create new process
            var tcs = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);

            var process = new System.Diagnostics.Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = core.ExePath,
                    Arguments = core.Argument,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                },
                EnableRaisingEvents = true
            };

            process.OutputDataReceived += (s, e) =>
            {
                if (e.Data != null)
                    _logger.LogDebug("[{CoreKey} OUT] {Output}", core.Key, e.Data);
            };

            process.ErrorDataReceived += (s, e) =>
            {
                if (e.Data != null)
                    _logger.LogWarning("[{CoreKey} ERR] {Error}", core.Key, e.Data);
            };

            process.Exited += (s, e) =>
            {
                // Remove from tracking - disposal will happen in Kill() or Dispose()
                _processes.TryRemove(core.Key, out _);
                tcs.TrySetResult(process.ExitCode);
                // Note: Don't dispose here - let Kill() or Dispose() handle it to avoid race conditions
            };

            if (!process.Start())
                throw new InvalidOperationException($"Failed to start process '{core.ExePath}'.");

            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            _processes[core.Key] = process;
            _cores[core.Key] = core;
        }
        /// <summary>
        /// Kills a process by key if running.
        /// </summary>
        public void Kill(string key)
        {
            if (_processes.TryRemove(key, out var process))
            {
                try
                {
                    if (!process.HasExited)
                    {
                        process.Kill(entireProcessTree: true);
                        // Give process a moment to exit gracefully
                        try
                        {
                            process.WaitForExit(2000);
                        }
                        catch
                        {
                            // Process may have already exited
                        }
                    }
                }
                catch (InvalidOperationException)
                {
                    // Process may have already exited or been disposed
                }
                finally
                {
                    try
                    {
                        process.Dispose();
                    }
                    catch
                    {
                        // Ignore disposal errors (process may already be disposed)
                    }
                }
            }
        }
        /// <summary>
        /// Kills all running processes.
        /// </summary>
        public void KillAll()
        {
            foreach (var key in _processes.Keys)
                Kill(key);
        }

        /// <summary>
        /// Checks if a process is still running.
        /// </summary>
        public bool IsRunning(string key)
        {
            if (!_processes.TryGetValue(key, out var process))
                return false;

            try
            {
                return !process.HasExited;
            }
            catch (InvalidOperationException)
            {
                // Process has been disposed or is no longer valid
                _processes.TryRemove(key, out _);
                return false;
            }
        }

        public CoreConfig GetCore(string key) => _cores[key];

        /// <summary>
        /// Gets the process ID of a running core process by key.
        /// </summary>
        public uint? GetProcessId(string key)
        {
            if (!_processes.TryGetValue(key, out var process))
                return null;

            try
            {
                if (process.HasExited)
                    return null;
                return (uint)process.Id;
            }
            catch (InvalidOperationException)
            {
                _processes.TryRemove(key, out _);
                return null;
            }
        }

        /// <summary>
        /// Returns the list of all running process keys.
        /// </summary>
        public string[] GetRunning()
        {
            return [.. _processes.Keys];
        }

        public void Dispose()
        {
            KillAll();
        }
    }
}
