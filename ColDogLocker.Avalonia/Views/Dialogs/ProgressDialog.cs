/*
**  Copyright (C) 2026 ColDog Studios
**
**  This program is free software: you can redistribute it and/or modify
**  it under the terms of the GNU General Public License as published by
**  the Free Software Foundation, either version 3 of the License, or
**  (at your option) any later version.
**
**  This program is distributed in the hope that it will be useful,
**  but WITHOUT ANY WARRANTY; without even the implied warranty of
**  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**  GNU General Public License for more details.
**
**  You should have received a copy of the GNU General Public License
**  long with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

using Avalonia.Controls;

namespace ColDogStudios.ColDogLocker.Avalonia.Views.Dialogs
{
    public sealed class ProgressDialog : Window
    {
        private readonly ProgressBar _progressBar;
        private readonly TextBlock _progressText;
        private readonly TextBlock _currentItemText;

        public ProgressDialog(string title)
        {
            Title = title;
            Width = 460;
            CanResize = false;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;

            _progressBar = new ProgressBar
            {
                Minimum = 0,
                Maximum = 100,
                IsIndeterminate = true
            };

            _progressText = new TextBlock { Text = "Working..." };
            _currentItemText = new TextBlock { TextWrapping = global::Avalonia.Media.TextWrapping.Wrap };

            Content = new StackPanel
            {
                Margin = new global::Avalonia.Thickness(18),
                Spacing = 12,
                Children =
                {
                    _progressText,
                    _progressBar,
                    _currentItemText
                }
            };
        }

        public void SetIndeterminate(string message)
        {
            _progressBar.IsIndeterminate = true;
            _progressText.Text = message;
            _currentItemText.Text = string.Empty;
        }

        public void UpdateProgress(int current, int total, string currentItem)
        {
            if (total <= 0)
            {
                SetIndeterminate(currentItem);
                return;
            }

            var percent = Math.Clamp(current * 100d / total, 0, 100);
            _progressBar.IsIndeterminate = false;
            _progressBar.Value = percent;
            _progressText.Text = $"{current} of {total} ({percent:0}%)";
            _currentItemText.Text = currentItem;
        }

        public void Complete(string message = "Complete")
        {
            _progressBar.IsIndeterminate = false;
            _progressBar.Value = 100;
            _progressText.Text = message;
        }
    }
}
