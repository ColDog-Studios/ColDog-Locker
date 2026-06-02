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

namespace ColDogStudios.ColDogLocker.Avalonia.Views.Dialogs
{
    internal static class DialogHelpers
    {
        public static TextBlock Label(string text)
        {
            return new TextBlock
            {
                Text = text,
                FontWeight = FontWeight.SemiBold,
                Margin = new global::Avalonia.Thickness(0, 0, 0, 4)
            };
        }

        public static TextBlock Body(string text)
        {
            return new TextBlock
            {
                Text = text,
                TextWrapping = TextWrapping.Wrap,
                MaxWidth = 560
            };
        }

        public static StackPanel Field(string label, Control control)
        {
            return new StackPanel
            {
                Spacing = 4,
                Children =
                {
                    Label(label),
                    control
                }
            };
        }

        public static StackPanel Buttons(params Button[] buttons)
        {
            var panel = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                HorizontalAlignment = HorizontalAlignment.Right,
                Spacing = 8
            };

            foreach (var button in buttons)
            {
                panel.Children.Add(button);
            }

            return panel;
        }

        public static Button Button(string text)
        {
            return new Button
            {
                Content = text,
                MinWidth = 92,
                HorizontalContentAlignment = HorizontalAlignment.Center
            };
        }
    }
}
