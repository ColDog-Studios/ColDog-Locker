using System.Windows;

namespace ColDogStudios.ColDogLocker.Desktop
{
    public partial class MinimalApp : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);
            
            var window = new TestWindow();
            window.Show();
        }
    }
}
