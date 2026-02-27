using System.IO;
using System.Text;
using System.Windows;
using ColDogStudios.ColDogLocker.Infrastructure.Configuration;

namespace ColDogStudios.ColDogLocker.Gui.WPF.Dialogs
{
    public partial class ErrorDialog : Window
    {
        private readonly Exception? _exception;
        private readonly string _errorMessage;
        private readonly string _errorTitle;

        public ErrorDialog(string errorMessage, Exception? exception = null, string? title = null)
        {
            InitializeComponent();

            _errorMessage = errorMessage;
            _exception = exception;
            _errorTitle = title ?? "An Error Occurred";

            LoadErrorDetails();
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            // Play scale-in animation if animations are enabled
            if (SettingsManager.Settings.EnableAnimations)
            {
                try
                {
                    if (TryFindResource("WindowScaleInAnimation") is System.Windows.Media.Animation.Storyboard storyboard)
                    {
                        storyboard.Begin(this);
                    }
                }
                catch
                {
                    // Animation failed, continue without it
                }
            }
        }

        private void LoadErrorDetails()
        {
            // Set title and message
            ErrorTitleText.Text = _errorTitle;
            ErrorMessageText.Text = _errorMessage;
            Title = _errorTitle;

            // Build detailed error information
            var errorDetails = new StringBuilder();
            errorDetails.AppendLine("=== ERROR DETAILS ===");
            errorDetails.AppendLine($"Time: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            errorDetails.AppendLine($"Application: ColDog Locker");
            errorDetails.AppendLine($"Version: {GetApplicationVersion()}");
            errorDetails.AppendLine();
            errorDetails.AppendLine("Error Message:");
            errorDetails.AppendLine(_errorMessage);
            errorDetails.AppendLine();

            if (_exception != null)
            {
                // Exception type
                ExceptionTypeText.Text = _exception.GetType().FullName ?? _exception.GetType().Name;

                // Stack trace
                StackTraceText.Text = _exception.StackTrace ?? "No stack trace available";

                // Add exception details to full error text
                errorDetails.AppendLine("Exception Type:");
                errorDetails.AppendLine(_exception.GetType().FullName);
                errorDetails.AppendLine();

                if (!string.IsNullOrEmpty(_exception.Message))
                {
                    errorDetails.AppendLine("Exception Message:");
                    errorDetails.AppendLine(_exception.Message);
                    errorDetails.AppendLine();
                }

                if (!string.IsNullOrEmpty(_exception.StackTrace))
                {
                    errorDetails.AppendLine("Stack Trace:");
                    errorDetails.AppendLine(_exception.StackTrace);
                    errorDetails.AppendLine();
                }

                // Inner exceptions
                var innerException = _exception.InnerException;
                var innerLevel = 1;
                while (innerException != null)
                {
                    errorDetails.AppendLine($"Inner Exception {innerLevel}:");
                    errorDetails.AppendLine($"Type: {innerException.GetType().FullName}");
                    errorDetails.AppendLine($"Message: {innerException.Message}");
                    if (!string.IsNullOrEmpty(innerException.StackTrace))
                    {
                        errorDetails.AppendLine("Stack Trace:");
                        errorDetails.AppendLine(innerException.StackTrace);
                    }

                    errorDetails.AppendLine();

                    innerException = innerException.InnerException;
                    innerLevel++;
                }
            }
            else
            {
                ExceptionTypeText.Text = "No exception details available";
                StackTraceText.Text = "N/A";
            }

            // System information
            errorDetails.AppendLine("=== SYSTEM INFORMATION ===");
            errorDetails.AppendLine($"OS: {Environment.OSVersion}");
            errorDetails.AppendLine($"OS Architecture: {System.Runtime.InteropServices.RuntimeInformation.OSArchitecture}");
            errorDetails.AppendLine($"Process Architecture: {System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture}");
            errorDetails.AppendLine($".NET Version: {Environment.Version}");
            errorDetails.AppendLine($"Runtime: {System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription}");
            errorDetails.AppendLine($"Processor Count: {Environment.ProcessorCount}");
            errorDetails.AppendLine($"Memory (Working Set): {Environment.WorkingSet / 1024 / 1024} MB");

            FullErrorTextBox.Text = errorDetails.ToString();
        }

        private static string GetApplicationVersion()
        {
            try
            {
                var assembly = System.Reflection.Assembly.GetExecutingAssembly();
                var version = assembly.GetName().Version;
                return version?.ToString() ?? "Unknown";
            }
            catch
            {
                return "Unknown";
            }
        }

        private void CopyError_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                System.Windows.Clipboard.SetText(FullErrorTextBox.Text);
                MessageDialog.ShowInformation("Error details copied to clipboard.", "Copied", this);
            }
            catch (Exception ex)
            {
                MessageDialog.ShowError($"Failed to copy to clipboard: {ex.Message}", "Error", this);
            }
        }

        private void OpenLogs_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var logsPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "ColDog Studios", "ColDog Locker", "logs");

                if (!Directory.Exists(logsPath))
                {
                    Directory.CreateDirectory(logsPath);
                }

                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = logsPath,
                    UseShellExecute = true,
                    Verb = "open"
                });
            }
            catch (Exception ex)
            {
                MessageDialog.ShowError($"Failed to open logs folder: {ex.Message}", "Error", this);
            }
        }

        private void OK_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = true;
            Close();
        }

        /// <summary>
        /// Convenience method to show an error dialog
        /// </summary>
        public static void Show(string errorMessage, Exception? exception = null, string? title = null, Window? owner = null)
        {
            var dialog = new ErrorDialog(errorMessage, exception, title);
            if (owner != null)
            {
                dialog.Owner = owner;
            }

            dialog.ShowDialog();
        }
    }
}
