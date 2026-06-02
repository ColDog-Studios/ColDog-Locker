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
using ColDogStudios.ColDogLocker.Core.Environment;

namespace ColDogStudios.ColDogLocker.Avalonia.Views.Dialogs
{
    public sealed class AboutDialog : Window
    {
        public AboutDialog()
        {
            Title = "About ColDog Locker";
            Width = 520;
            CanResize = false;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;

            var closeButton = DialogHelpers.Button("Close");
            closeButton.Click += (_, _) => Close();

            Content = new StackPanel
            {
                Margin = new global::Avalonia.Thickness(18),
                Spacing = 12,
                Children =
                {
                    new TextBlock
                    {
                        Text = "ColDog Locker",
                        FontSize = 22,
                        FontWeight = global::Avalonia.Media.FontWeight.SemiBold
                    },
                    DialogHelpers.Body($"Version {AppInfo.SemanticVersion}\nSecure file locker by ColDog Studios.\n\nCopyright © 2026 ColDog Studios\nLicensed under the GNU General Public License v3.0\n\n.NET {Environment.Version}\n{Environment.OSVersion}"),
                    DialogHelpers.Buttons(closeButton)
                }
            };
        }
    }
}
