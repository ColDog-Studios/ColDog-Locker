using Avalonia.Controls;
using ColDogStudios.ColDogLocker.Core.Models;

namespace ColDogStudios.ColDogLocker.Avalonia.Views.Dialogs
{
    public sealed class LockerPropertiesDialog : Window
    {
        public LockerPropertiesDialog(LockerModel locker)
        {
            Title = "Locker Properties";
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
                    DialogHelpers.Field("Name", new TextBox { Text = locker.LockerName, IsReadOnly = true }),
                    DialogHelpers.Field("Status", new TextBox { Text = locker.IsLocked ? "Locked" : "Unlocked", IsReadOnly = true }),
                    DialogHelpers.Field("Location", new TextBox { Text = locker.LockerLocation, IsReadOnly = true }),
                    DialogHelpers.Field("ID", new TextBox { Text = locker.Guid, IsReadOnly = true }),
                    DialogHelpers.Buttons(closeButton)
                }
            };
        }
    }
}
