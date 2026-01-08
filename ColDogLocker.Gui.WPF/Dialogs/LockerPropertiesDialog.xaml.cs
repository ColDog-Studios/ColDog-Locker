using System;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using ColDogStudios.ColDogLocker.Core.Models;
using ColDogStudios.ColDogLocker.Infrastructure.Data;

namespace ColDogStudios.ColDogLocker.Gui.WPF.Dialogs;

public partial class LockerPropertiesDialog : Window
{
    private readonly LockerModel _locker;
    private bool _hasChanges = false;

    public LockerPropertiesDialog(LockerModel locker)
    {
        InitializeComponent();
        _locker = locker;
        LoadLockerProperties();
    }

    private void LoadLockerProperties()
    {
        // Set name
        NameTextBox.Text = _locker.LockerName;

        // Set location
        LocationTextBox.Text = _locker.LockerLocation;

        // Set status
        if (_locker.IsLocked)
        {
            StatusIcon.Text = "\uE72E"; // Lock icon
            StatusIcon.Foreground = System.Windows.Media.Brushes.Red;
            StatusText.Text = "Locked";
            StatusText.Foreground = System.Windows.Media.Brushes.Red;
            
            // Disable location browsing when locked
            LocationWarningText.Visibility = Visibility.Visible;
        }
        else
        {
            StatusIcon.Text = "\uE785"; // Unlock icon
            StatusIcon.Foreground = System.Windows.Media.Brushes.Green;
            StatusText.Text = "Unlocked";
            StatusText.Foreground = System.Windows.Media.Brushes.Green;
            
            // Enable location browsing when unlocked
            var browseButton = (System.Windows.Controls.Button)((Grid)LocationTextBox.Parent).Children[1];
            browseButton.IsEnabled = true;
        }

        // Calculate and set size
        CalculateSize();

        // Set dates
        try
        {
            if (Directory.Exists(_locker.LockerLocation))
            {
                var dirInfo = new DirectoryInfo(_locker.LockerLocation);
                CreatedText.Text = dirInfo.CreationTime.ToString("yyyy-MM-dd HH:mm:ss");
                ModifiedText.Text = dirInfo.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss");
            }
            else
            {
                CreatedText.Text = "Directory not found";
                ModifiedText.Text = "Directory not found";
            }
        }
        catch
        {
            CreatedText.Text = "Unable to retrieve";
            ModifiedText.Text = "Unable to retrieve";
        }
    }

    private void CalculateSize()
    {
        try
        {
            if (Directory.Exists(_locker.LockerLocation))
            {
                long totalSize = CalculateDirectorySize(new DirectoryInfo(_locker.LockerLocation));
                SizeText.Text = FormatFileSize(totalSize);
            }
            else
            {
                SizeText.Text = "Directory not found";
            }
        }
        catch
        {
            SizeText.Text = "Unable to calculate";
        }
    }

    private long CalculateDirectorySize(DirectoryInfo directory)
    {
        long size = 0;
        try
        {
            // Add file sizes
            foreach (var file in directory.GetFiles())
            {
                size += file.Length;
            }

            // Add subdirectory sizes
            foreach (var dir in directory.GetDirectories())
            {
                size += CalculateDirectorySize(dir);
            }
        }
        catch
        {
            // Skip directories we can't access
        }

        return size;
    }

    private string FormatFileSize(long bytes)
    {
        string[] sizes = { "bytes", "KB", "MB", "GB", "TB" };
        double len = bytes;
        int order = 0;
        while (len >= 1024 && order < sizes.Length - 1)
        {
            order++;
            len = len / 1024;
        }

        return $"{len:0.##} {sizes[order]}";
    }

    private void NameTextBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        _hasChanges = !string.IsNullOrWhiteSpace(NameTextBox.Text) && 
                      NameTextBox.Text != _locker.LockerName;
        SaveButton.IsEnabled = _hasChanges;
    }

    private void BrowseButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new Microsoft.Win32.OpenFolderDialog
        {
            Title = "Select new location for locker",
            InitialDirectory = _locker.LockerLocation
        };

        if (dialog.ShowDialog() == true)
        {
            LocationTextBox.Text = dialog.FolderName;
            _hasChanges = LocationTextBox.Text != _locker.LockerLocation;
            SaveButton.IsEnabled = _hasChanges;
        }
    }

    private void SaveButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            // Validate name
            if (string.IsNullOrWhiteSpace(NameTextBox.Text))
            {
                MessageDialog.ShowWarning("Locker name cannot be empty.", "Invalid Name", this);
                return;
            }

            // Update locker name if changed
            if (NameTextBox.Text != _locker.LockerName)
            {
                _locker.LockerName = NameTextBox.Text;
            }

            // Update locker location if changed and unlocked
            if (LocationTextBox.Text != _locker.LockerLocation && !_locker.IsLocked)
            {
                _locker.LockerLocation = LocationTextBox.Text;
            }

            // Save to database
            LockerRepository.UpdateLocker(_locker);

            MessageDialog.ShowInformation("Locker properties saved successfully.", "Success", this);
            _hasChanges = false;
            SaveButton.IsEnabled = false;
            DialogResult = true;
        }
        catch (Exception ex)
        {
            MessageDialog.ShowError($"Failed to save locker properties: {ex.Message}", "Error", this);
        }
    }

    private void CloseButton_Click(object sender, RoutedEventArgs e)
    {
        if (_hasChanges)
        {
            if (!MessageDialog.ShowQuestion(
                "You have unsaved changes. Are you sure you want to close?",
                "Unsaved Changes",
                this))
            {
                return;
            }
        }

        DialogResult = false;
        Close();
    }

    public static void Show(LockerModel locker, Window owner)
    {
        var dialog = new LockerPropertiesDialog(locker)
        {
            Owner = owner
        };
        dialog.ShowDialog();
    }
}
