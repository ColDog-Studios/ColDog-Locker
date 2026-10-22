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
using Avalonia.Layout;
using Avalonia.Media;
using ColDogStudios.ColDogLocker.Core.Validation;

namespace ColDogStudios.ColDogLocker.Avalonia.Views.Dialogs
{
    internal static class PasswordRequirementsPresenter
    {
        internal static void Update(StackPanel panel, string password)
        {
            panel.Children.Clear();

            foreach (var requirement in PasswordFilter.Validate(password))
            {
                var brush = requirement.IsMet ? Brushes.ForestGreen : Brushes.Gray;
                var row = new StackPanel
                {
                    Orientation = Orientation.Horizontal,
                    Spacing = 8,
                    Children =
                    {
                        new TextBlock
                        {
                            Text = requirement.IsMet ? "✓" : "○",
                            Width = 18,
                            FontSize = 14,
                            Foreground = brush,
                            VerticalAlignment = VerticalAlignment.Center
                        },
                        new TextBlock { Text = requirement.Description, FontSize = 12, Foreground = brush, VerticalAlignment = VerticalAlignment.Center }
                    }
                };

                panel.Children.Add(row);
            }
        }
    }
}
