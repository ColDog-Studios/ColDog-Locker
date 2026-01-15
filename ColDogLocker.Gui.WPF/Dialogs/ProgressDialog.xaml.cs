using System.Text;
using System.Windows;

namespace ColDogStudios.ColDogLocker.Gui.WPF.Dialogs
{
    public partial class ProgressDialog : Window
    {
        private readonly StringBuilder _statusLog = new();

        public bool IsCancelled { get; private set; }

        public ProgressDialog(string operationTitle)
        {
            InitializeComponent();
            OperationText.Text = operationTitle;
            IsCancelled = false;
        }

        public void UpdateProgress(int current, int total, string currentItem)
        {
            Dispatcher.Invoke(() =>
            {
                var percentage = total > 0 ? (int)((current / (double)total) * 100) : 0;
                OperationProgressBar.Value = percentage;
                ProgressText.Text = $"{current} of {total} ({percentage}%)";
                CurrentItemText.Text = $"Processing: {currentItem}";
            });
        }

        public void AddStatusMessage(string message)
        {
            Dispatcher.Invoke(() =>
            {
                _statusLog.AppendLine($"[{DateTime.Now:HH:mm:ss}] {message}");
                StatusText.Text = _statusLog.ToString();
                StatusScrollViewer.Visibility = Visibility.Visible;

                // Auto-scroll to bottom
                StatusScrollViewer.UpdateLayout();
                StatusScrollViewer.ScrollToEnd();
            });
        }

        public void SetIndeterminate(bool isIndeterminate)
        {
            Dispatcher.Invoke(() =>
            {
                OperationProgressBar.IsIndeterminate = isIndeterminate;
            });
        }

        public void Complete(string message)
        {
            Dispatcher.Invoke(() =>
            {
                OperationText.Text = "Operation Complete";
                CurrentItemText.Text = message;
                OperationProgressBar.Value = 100;
                CancelButton.Content = "Close";
            });
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            if (CancelButton.Content.ToString() == "Close")
            {
                DialogResult = true;
                Close();
            }
            else
            {
                IsCancelled = true;
                CancelButton.IsEnabled = false;
                CurrentItemText.Text = "Cancelling operation...";
            }
        }

        protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
        {
            if (!IsCancelled && CancelButton.Content.ToString() != "Close")
            {
                if (!MessageDialog.ShowQuestion(
                    "Are you sure you want to cancel the operation?",
                    "Cancel Operation",
                    this))
                {
                    e.Cancel = true;
                }
                else
                {
                    IsCancelled = true;
                }
            }

            base.OnClosing(e);
        }
    }
}
