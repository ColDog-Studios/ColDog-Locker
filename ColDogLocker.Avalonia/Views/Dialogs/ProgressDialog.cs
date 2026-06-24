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
    public sealed partial class ProgressDialog : Window
    {
        public ProgressDialog()
        {
            InitializeComponent();
        }

        public ProgressDialog(string title)
            : this()
        {
            Title = title;
        }

        public void SetIndeterminate(string message)
        {
            ProgressBar.IsIndeterminate = true;
            ProgressText.Text = message;
            CurrentItemText.Text = string.Empty;
        }

        public void UpdateProgress(int current, int total, string currentItem)
        {
            if (total <= 0)
            {
                SetIndeterminate(currentItem);
                return;
            }

            var percent = Math.Clamp(current * 100d / total, 0, 100);
            ProgressBar.IsIndeterminate = false;
            ProgressBar.Value = percent;
            ProgressText.Text = $"{current} of {total} ({percent:0}%)";
            CurrentItemText.Text = currentItem;
        }

        public void Complete(string message = "Complete")
        {
            ProgressBar.IsIndeterminate = false;
            ProgressBar.Value = 100;
            ProgressText.Text = message;
        }
    }
}
