using Microsoft.Extensions.Logging;
using OmniPoss.Infrastructure.Interop;
using System.Runtime.InteropServices;

namespace OmniPoss.UI
{
    /// <summary>
    /// Hidden form that intercepts Windows shutdown messages (WM_QUERYENDSESSION, WM_ENDSESSION)
    /// to allow graceful application shutdown during system shutdown/restart.
    /// Blocks Windows termination until all resources are cleaned up.
    /// </summary>
    internal class ShutdownHandlerForm : Form
    {
        private readonly Func<Task> _onShutdownRequested;
        private readonly ILogger<ShutdownHandlerForm>? _logger;
        private readonly object _shutdownLock = new();
        private bool _shutdownHandled = false;
        private bool _cleanupComplete = false;
        private Task? _shutdownTask = null;

        // Windows message constants
        private const int WM_QUERYENDSESSION = 0x0011;
        private const int WM_ENDSESSION = 0x0016;
        private const uint ENDSESSION_LOGOFF = 0x80000000;

        public ShutdownHandlerForm(Func<Task> onShutdownRequested, ILogger<ShutdownHandlerForm>? logger = null)
        {
            _onShutdownRequested = onShutdownRequested ?? throw new ArgumentNullException(nameof(onShutdownRequested));
            _logger = logger;

            // Form must be visible (or at least have a valid window handle) for ShutdownBlockReasonCreate to work
            // Make it as unobtrusive as possible: off-screen, no taskbar, no border
            this.FormBorderStyle = FormBorderStyle.None;
            this.ShowInTaskbar = false;
            this.WindowState = FormWindowState.Normal;
            // Position off-screen so it's not visible to user
            this.StartPosition = FormStartPosition.Manual;
            this.Location = new System.Drawing.Point(-2000, -2000);
            this.Size = new System.Drawing.Size(1, 1);
            this.Visible = true; // Must be visible for shutdown blocking to work
            
            // Prevent form from closing unexpectedly
            this.FormClosing += (sender, e) =>
            {
                _logger?.LogInformation("FormClosing event fired. CloseReason: {CloseReason}, Cancel: {Cancel}", e.CloseReason, e.Cancel);
                // Only allow closing if it's user-initiated or Windows shutdown
                if (e.CloseReason == CloseReason.UserClosing && !Environment.HasShutdownStarted)
                {
                    _logger?.LogWarning("Form closing unexpectedly with UserClosing reason. This might indicate a problem.");
                }
            };
            
            _logger?.LogInformation("ShutdownHandlerForm created. Handle: {Handle}, Visible: {Visible}", this.Handle, this.Visible);
        }

        protected override void WndProc(ref Message m)
        {
            switch (m.Msg)
            {
                case WM_QUERYENDSESSION:
                    // Windows is asking if we can shut down
                    // Windows will keep asking periodically until we return TRUE
                    _logger?.LogInformation("Windows shutdown/restart detected (WM_QUERYENDSESSION)");

                    lock (_shutdownLock)
                    {
                        // If cleanup is already complete, allow shutdown
                        if (_cleanupComplete)
                        {
                            _logger?.LogInformation("Cleanup already complete, allowing shutdown");
                            m.Result = new IntPtr(1); // TRUE = allow shutdown
                            return;
                        }

                        if (!_shutdownHandled)
                        {
                            _shutdownHandled = true;

                            // Create shutdown block reason BEFORE starting cleanup
                            // This makes the app appear in "Apps preventing shutdown" list
                            try
                            {
                                bool blockReasonCreated = NativeMethods.ShutdownBlockReasonCreate(
                                    this.Handle,
                                    "OmniPoss is cleaning up network resources and stopping services. Please wait...");

                                if (blockReasonCreated)
                                {
                                    _logger?.LogInformation("Shutdown block reason created - app will appear in shutdown blocker list");
                                }
                                else
                                {
                                    int error = Marshal.GetLastWin32Error();
                                    _logger?.LogWarning("Failed to create shutdown block reason (Error: {Error})", error);
                                }
                            }
                            catch (Exception ex)
                            {
                                _logger?.LogWarning(ex, "Exception while creating shutdown block reason");
                            }

                            // Start cleanup immediately on background thread
                            _logger?.LogInformation("Starting cleanup process...");
                            _shutdownTask = Task.Run(async () =>
                            {
                                try
                                {
                                    await _onShutdownRequested();
                                    _logger?.LogInformation("Graceful shutdown completed successfully");

                                    // Mark cleanup as complete
                                    lock (_shutdownLock)
                                    {
                                        _cleanupComplete = true;
                                    }

                                    // Remove the shutdown block reason
                                    try
                                    {
                                        NativeMethods.ShutdownBlockReasonDestroy(this.Handle);
                                        _logger?.LogInformation("Shutdown block reason removed - cleanup complete");
                                    }
                                    catch (Exception ex)
                                    {
                                        _logger?.LogWarning(ex, "Exception while destroying shutdown block reason");
                                    }

                                    // Signal the UI thread that cleanup is complete
                                    // Close the form and exit the application on the UI thread
                                    try
                                    {
                                        if (this.IsHandleCreated && !this.IsDisposed)
                                        {
                                            // Use BeginInvoke to execute on UI thread
                                            this.BeginInvoke(new Action(() =>
                                            {
                                                try
                                                {
                                                    _logger?.LogInformation("Cleanup complete, closing form and exiting application");
                                                    // Close the form - this will exit the message loop
                                                    this.Close();
                                                    // Exit the application
                                                    System.Windows.Forms.Application.Exit();
                                                }
                                                catch (Exception ex)
                                                {
                                                    _logger?.LogError(ex, "Exception while closing form after cleanup");
                                                }
                                            }));
                                        }
                                    }
                                    catch (Exception ex)
                                    {
                                        _logger?.LogWarning(ex, "Exception signaling cleanup completion to UI thread");
                                    }
                                }
                                catch (Exception ex)
                                {
                                    _logger?.LogError(ex, "Error during graceful shutdown");
                                    // Mark as complete anyway to allow shutdown to proceed
                                    lock (_shutdownLock)
                                    {
                                        _cleanupComplete = true;
                                    }
                                    try
                                    {
                                        NativeMethods.ShutdownBlockReasonDestroy(this.Handle);
                                        // Signal completion even on error
                                        if (this.IsHandleCreated && !this.IsDisposed)
                                        {
                                            this.BeginInvoke(new Action(() =>
                                            {
                                                try
                                                {
                                                    this.Close();
                                                    System.Windows.Forms.Application.Exit();
                                                }
                                                catch { }
                                            }));
                                        }
                                    }
                                    catch { }
                                }
                            });
                        }
                        else if (_shutdownTask != null)
                        {
                            // Cleanup was already started, check if it's complete
                            if (_shutdownTask.IsCompleted)
                            {
                                try
                                {
#pragma warning disable VSTHRD002 // Avoid problematic synchronous waits
                                    _shutdownTask.GetAwaiter().GetResult();
#pragma warning restore VSTHRD002
                                }
                                catch (Exception ex)
                                {
                                    _logger?.LogError(ex, "Shutdown task completed with exception");
                                }

                                if (_cleanupComplete)
                                {
                                    _logger?.LogInformation("Cleanup complete, allowing shutdown");
                                    m.Result = new IntPtr(1); // TRUE = allow shutdown
                                    return;
                                }
                            }
                        }
                    }

                    // Return FALSE to block shutdown - Windows will keep asking until cleanup completes
                    m.Result = new IntPtr(0); // FALSE = block shutdown
                    return;

                case WM_ENDSESSION:
                    // Windows is ending the session
                    // wParam: TRUE if session is ending, FALSE if shutdown was canceled
                    bool isEnding = m.WParam != IntPtr.Zero;
                    bool isLogoff = isEnding && ((uint)m.WParam.ToInt32() & ENDSESSION_LOGOFF) != 0;
                    _logger?.LogInformation("Windows session ending (WM_ENDSESSION, Ending: {IsEnding}, Logoff: {IsLogoff})", isEnding, isLogoff);

                    if (!isEnding)
                    {
                        // Shutdown was canceled - clean up block reason
                        lock (_shutdownLock)
                        {
                            _cleanupComplete = false;
                            _shutdownHandled = false;
                        }
                        try
                        {
                            NativeMethods.ShutdownBlockReasonDestroy(this.Handle);
                            _logger?.LogInformation("Shutdown canceled - removed block reason");
                        }
                        catch (Exception ex)
                        {
                            _logger?.LogWarning(ex, "Exception while destroying shutdown block reason after cancel");
                        }
                        m.Result = IntPtr.Zero;
                        return;
                    }

                    // Session is ending - check cleanup status
                    lock (_shutdownLock)
                    {
                        if (_shutdownTask != null && !_cleanupComplete)
                        {
                            // Cleanup was started but not complete
                            // Since we're in WM_ENDSESSION, Windows is forcing shutdown
                            // Just check if it's done, don't wait
                            if (_shutdownTask.IsCompleted)
                            {
                                try
                                {
#pragma warning disable VSTHRD002 // Avoid problematic synchronous waits
                                    _shutdownTask.GetAwaiter().GetResult();
#pragma warning restore VSTHRD002
                                }
                                catch (Exception ex)
                                {
                                    _logger?.LogError(ex, "Shutdown task completed with exception");
                                }
                            }
                            else
                            {
                                // Task still running - log warning but don't block
                                _logger?.LogWarning("Cleanup task still running in WM_ENDSESSION - Windows will terminate");
                            }
                        }
                        else if (!_cleanupComplete && !_shutdownHandled)
                        {
                            // Fallback: cleanup wasn't started (shouldn't happen)
                            _logger?.LogWarning("Cleanup not started in WM_ENDSESSION - starting now");
                            try
                            {
                                NativeMethods.ShutdownBlockReasonCreate(
                                    this.Handle,
                                    "OmniPoss is cleaning up network resources and stopping services. Please wait...");

                                _shutdownTask = Task.Run(async () =>
                                {
                                    try
                                    {
                                        await _onShutdownRequested();
                                        _logger?.LogInformation("Graceful shutdown completed successfully");
                                    }
                                    catch (Exception ex)
                                    {
                                        _logger?.LogError(ex, "Error during graceful shutdown");
                                    }
                                    finally
                                    {
                                        lock (_shutdownLock)
                                        {
                                            _cleanupComplete = true;
                                        }
                                        try
                                        {
                                            NativeMethods.ShutdownBlockReasonDestroy(this.Handle);
                                        }
                                        catch { }
                                    }
                                });
                                
                                // Don't wait - just start it and let it complete in background
                                // Windows will wait based on ShutdownBlockReasonCreate
                            }
                            catch (Exception ex)
                            {
                                _logger?.LogError(ex, "Exception during fallback cleanup");
                            }
                        }
                    }

                    m.Result = IntPtr.Zero;
                    return;
            }

            base.WndProc(ref m);
        }
    }
}
