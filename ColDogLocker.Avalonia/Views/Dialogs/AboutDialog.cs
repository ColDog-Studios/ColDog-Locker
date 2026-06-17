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

using System;
using Avalonia.Controls;
using Avalonia.Interactivity;
using ColDogStudios.ColDogLocker.Avalonia.Services;
using ColDogStudios.ColDogLocker.Core.Environment;

namespace ColDogStudios.ColDogLocker.Avalonia.Views.Dialogs
{
    public sealed partial class AboutDialog : Window
    {
        private const string DocumentationUrl = "https://github.com/ColDog-Studios/ColDog-Locker/tree/main/docs";
        private const string GitHubUrl = "https://github.com/ColDog-Studios/ColDog-Locker";
        private const string ReportIssueUrl = "https://github.com/ColDog-Studios/ColDog-Locker/issues/new";
        private const string ContactSupportUrl = "mailto:support@coldogstudios.com?subject=ColDog%20Locker%20Support";

        private IPlatformService? _platformService;

        public AboutDialog()
        {
            InitializeComponent();

            VersionText.Text = $"Version {AppInfo.SemanticVersion ?? "unknown"}";
            SetInfoText(OperatingSystemText, SafeValue(() => Environment.OSVersion.ToString()));
            SetInfoText(RuntimeText, SafeValue(() => $".NET {Environment.Version}"));
            SetInfoText(InstallationPathText, SafeValue(() => AppContext.BaseDirectory));
            CloseButton.Click += CloseButton_Click;
        }

        public AboutDialog(IPlatformService platformService)
            : this()
        {
            _platformService = platformService;

            DocumentationButton.Click += async (_, _) => await OpenUrlAsync(DocumentationUrl);
            GitHubButton.Click += async (_, _) => await OpenUrlAsync(GitHubUrl);
            ReportIssueButton.Click += async (_, _) => await OpenUrlAsync(ReportIssueUrl);
            ContactSupportButton.Click += async (_, _) => await OpenUrlAsync(ContactSupportUrl);
        }

        private void CloseButton_Click(object? sender, RoutedEventArgs e)
        {
            Close();
        }

        private async Task OpenUrlAsync(string url)
        {
            if (_platformService == null)
            {
                return;
            }

            try
            {
                await _platformService.OpenUrlAsync(url);
            }
            catch (Exception ex)
            {
                await new MessageDialog("Error", $"Failed to open URL: {ex.Message}", MessageDialogKind.Error)
                    .ShowDialog<object?>(this);
            }
        }

        private static void SetInfoText(TextBlock textBlock, string value)
        {
            textBlock.Text = value;
            ToolTip.SetTip(textBlock, value);
        }

        private static string SafeValue(Func<string> valueFactory)
        {
            try
            {
                return valueFactory();
            }
            catch (InvalidOperationException)
            {
                return "Unknown";
            }
            catch (NotSupportedException)
            {
                return "Unknown";
            }
            catch (ArgumentException)
            {
                return "Unknown";
            }
        }
    }
}
