namespace ColDogStudios.ColDogLocker.Gui
{
    /// <summary>
    /// Abstraction for launching different GUI implementations.
    /// </summary>
    public interface IGuiLauncher
    {
        int Launch(string[] args);
    }

    /// <summary>
    /// Factory for creating GUI launcher instances based on platform.
    /// </summary>
    public static class GuiLauncherFactory
    {
        public static IGuiLauncher CreateLauncher()
        {
            // Windows: return new WpfGuiLauncher();
            // Linux: return new AvaloniaGuiLauncher();
            throw new NotImplementedException("GUI launcher not available on this platform");
        }
    }
}
