using System.Reflection;
using System.Windows;

namespace ColDogStudios.ColDogLocker.Desktop.Views
{
    public partial class AboutDialog : Window
    {
        public AboutDialog()
        {
            InitializeComponent();
            LoadVersionInfo();
        }

        private void LoadVersionInfo()
        {
            var assembly = Assembly.GetExecutingAssembly();
            var version = assembly.GetName().Version;
            
            VersionTextBlock.Text = $"Version {version?.ToString() ?? "1.0.0.0"}";
            CopyrightTextBlock.Text = "Copyright © ColDog Studios 2025";
        }

        private void OkButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}
