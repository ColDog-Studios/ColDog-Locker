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

using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Media.Imaging;
using Avalonia.Platform;
using ColDogStudios.ColDogLocker.Avalonia.Services;
using ColDogStudios.ColDogLocker.Core.Environment;
using ColDogStudios.ColDogLocker.Services.Updates;

namespace ColDogStudios.ColDogLocker.Avalonia.Views.Dialogs
{
    public sealed class AboutDialog : Window
    {
        private const string DocumentationUrl = "https://github.com/ColDogStudios/ColDog-Locker/wiki";
        private const string GitHubUrl = "https://github.com/ColDogStudios/ColDog-Locker";
        private const string ReportIssueUrl = "https://github.com/ColDogStudios/ColDog-Locker/issues/new";
        private const string ContactSupportUrl = "mailto:support@coldogstudios.com?subject=ColDog%20Locker%20Support";

        private readonly IPlatformService _platformService;
        private readonly UpdateWorkflow _updateWorkflow;

        public AboutDialog(IPlatformService platformService, UpdateWorkflow updateWorkflow)
        {
            _platformService = platformService;
            _updateWorkflow = updateWorkflow;

            Title = "About ColDog Locker";
            Width = 540;
            Height = 660;
            MinWidth = 500;
            MinHeight = 560;
            CanResize = true;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;

            Content = BuildContent();
        }

        private Control BuildContent()
        {
            var closeButton = DialogHelpers.Button("Close");
            closeButton.Click += (_, _) => Close();

            var updateButton = DialogHelpers.Button("Check for Updates");
            updateButton.Click += async (_, _) => await _updateWorkflow.RunAsync();

            var footer = new Border
            {
                Padding = new Thickness(18),
                Child = DialogHelpers.Buttons(updateButton, closeButton)
            };

            var root = new Grid
            {
                RowDefinitions = new RowDefinitions("*,Auto")
            };
            root.Children.Add(new ScrollViewer
            {
                VerticalScrollBarVisibility = global::Avalonia.Controls.Primitives.ScrollBarVisibility.Auto,
                Content = new StackPanel
                {
                    Children =
                    {
                        Header(),
                        Body()
                    }
                }
            });
            Grid.SetRow(footer, 1);
            root.Children.Add(footer);
            return root;
        }

        private Control Header()
        {
            return new Border
            {
                Padding = new Thickness(30),
                BorderThickness = new Thickness(0, 0, 0, 1),
                Child = new StackPanel
                {
                    HorizontalAlignment = HorizontalAlignment.Center,
                    Spacing = 8,
                    Children =
                    {
                        new Image
                        {
                            Source = new Bitmap(AssetLoader.Open(new Uri("avares://ColDogLocker/Assets/cdlIcon.ico"))),
                            Width = 112,
                            Height = 112
                        },
                        new TextBlock
                        {
                            Text = "ColDog Locker",
                            FontSize = 28,
                            FontWeight = FontWeight.Bold,
                            HorizontalAlignment = HorizontalAlignment.Center
                        },
                        new TextBlock
                        {
                            Text = $"Version {AppInfo.SemanticVersion ?? "unknown"}",
                            FontSize = 14,
                            Opacity = 0.75,
                            HorizontalAlignment = HorizontalAlignment.Center
                        }
                    }
                }
            };
        }

        private Control Body()
        {
            return new StackPanel
            {
                Margin = new Thickness(30, 20),
                Spacing = 18,
                Children =
                {
                    DescriptionBlock(),
                    CopyrightBlock(),
                    Section("Resources",
                        LinkButton("Documentation", DocumentationUrl),
                        LinkButton("GitHub Repository", GitHubUrl),
                        LinkButton("Report an Issue", ReportIssueUrl),
                        LinkButton("Contact Support", ContactSupportUrl)),
                    Section("Third-Party Libraries", ThirdPartyText()),
                    Section("System Information",
                        InfoRow("Operating System", SafeValue(() => Environment.OSVersion.ToString())),
                        InfoRow(".NET Runtime", SafeValue(() => $".NET {Environment.Version}")),
                        InfoRow("Installation Path", SafeValue(() => AppContext.BaseDirectory)))
                }
            };
        }

        private static Control DescriptionBlock()
        {
            return new StackPanel
            {
                Spacing = 8,
                Children =
                {
                    new TextBlock
                    {
                        Text = "ColDog Locker is a desktop app for securely locking, unlocking, and managing encrypted file lockers.",
                        FontSize = 13,
                        Opacity = 0.78,
                        TextWrapping = TextWrapping.Wrap,
                        TextAlignment = TextAlignment.Center
                    }
                }
            };
        }

        private static Control CopyrightBlock()
        {
            return Card(new StackPanel
            {
                Spacing = 4,
                Children =
                {
                    new TextBlock
                    {
                        Text = "Copyright (C) 2026 ColDog Studios",
                        FontSize = 14,
                        FontWeight = FontWeight.SemiBold,
                        HorizontalAlignment = HorizontalAlignment.Center
                    },
                    new TextBlock
                    {
                        Text = "Licensed under the GNU General Public License v3.0",
                        FontSize = 12,
                        Opacity = 0.75,
                        HorizontalAlignment = HorizontalAlignment.Center
                    }
                }
            });
        }

        private Button LinkButton(string text, string url)
        {
            var button = DialogHelpers.Button(text);
            button.HorizontalAlignment = HorizontalAlignment.Stretch;
            button.HorizontalContentAlignment = HorizontalAlignment.Left;
            button.Click += async (_, _) =>
            {
                try
                {
                    await _platformService.OpenUrlAsync(url);
                }
                catch (Exception ex)
                {
                    await new MessageDialog("Error", $"Failed to open URL: {ex.Message}", MessageDialogKind.Error)
                        .ShowDialog<object?>(this);
                }
            };
            return button;
        }

        private static Control ThirdPartyText()
        {
            return new TextBlock
            {
                Text =
                    "Avalonia - MIT License\n" +
                    "Cross-platform UI framework\n\n" +
                    "BCrypt.Net-Next - MIT License\n" +
                    "Password hashing and verification\n\n" +
                    "CommunityToolkit.Mvvm - MIT License\n" +
                    "MVVM helpers and source generators\n\n" +
                    "Microsoft.Data.Sqlite - MIT License\n" +
                    "Lightweight database engine\n\n" +
                    "Microsoft.Extensions.DependencyInjection - MIT License\n" +
                    "Dependency injection container\n\n" +
                    "Newtonsoft.Json - MIT License\n" +
                    "JSON serialization and deserialization",
                FontSize = 12,
                Opacity = 0.78,
                TextWrapping = TextWrapping.Wrap
            };
        }

        private static Control Section(string title, params Control[] controls)
        {
            var panel = new StackPanel
            {
                Spacing = 10
            };

            panel.Children.Add(new TextBlock
            {
                Text = title,
                FontSize = 14,
                FontWeight = FontWeight.SemiBold
            });

            foreach (var control in controls)
            {
                panel.Children.Add(control);
            }

            return panel;
        }

        private static Control InfoRow(string label, string value)
        {
            var grid = new Grid
            {
                ColumnDefinitions = new ColumnDefinitions("130,*"),
                ColumnSpacing = 10
            };

            grid.Children.Add(new TextBlock
            {
                Text = $"{label}:",
                FontSize = 12,
                FontWeight = FontWeight.SemiBold
            });

            var valueText = new TextBlock
            {
                Text = value,
                FontSize = 12,
                Opacity = 0.78,
                TextTrimming = TextTrimming.CharacterEllipsis
            };
            ToolTip.SetTip(valueText, value);
            Grid.SetColumn(valueText, 1);
            grid.Children.Add(valueText);
            return grid;
        }

        private static Border Card(Control content)
        {
            return new Border
            {
                Padding = new Thickness(15),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(6),
                Child = content
            };
        }

        private static string SafeValue(Func<string> valueFactory)
        {
            try
            {
                return valueFactory();
            }
            catch
            {
                return "Unknown";
            }
        }
    }
}
