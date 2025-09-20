# ColDog Locker Images

This directory contains all image assets for the ColDog Locker application.

## Directory Structure

### `/icons/`
Application icons in various sizes for Windows integration:
- `cdlIcon.ico` - Multi-size Windows icon file (16x16, 32x32, 48x48, 256x256)
- `cdlIcon-16.png` - Small taskbar/notification icons
- `cdlIcon-32.png` - Standard window icons  
- `cdlIcon-48.png` - Large icons
- `cdlIcon-128.png` - High-resolution icons
- `cdlIcon-256.png` - Very high-resolution icons
- `cdlIcon-500.png` - Ultra high-resolution icons ✓ (existing)

### `/ui/toolbar/`
Toolbar button icons (recommend 24x24 or 32x32 PNG):
- `new.png` - New locker button
- `lock.png` - Lock button
- `unlock.png` - Unlock button
- `delete.png` - Delete button
- `settings.png` - Settings button
- `about.png` - About button
- `refresh.png` - Refresh/reload button
- `grid-view.png` - Grid view toggle
- `list-view.png` - List view toggle

### `/ui/menu/`
Menu item icons (recommend 16x16 PNG):
- `file-new.png` - File → New menu
- `file-open.png` - File → Open menu
- `file-exit.png` - File → Exit menu
- `edit-settings.png` - Edit → Settings menu
- `view-grid.png` - View → Grid menu
- `view-list.png` - View → List menu
- `help-about.png` - Help → About menu

### `/ui/dialogs/`
Dialog-specific images:
- `password-icon.png` - Password dialog icon
- `warning-icon.png` - Warning/confirmation dialogs
- `error-icon.png` - Error dialog icon
- `success-icon.png` - Success notification icon

### `/branding/`
Brand and logo assets:
- `logo-light.png` - Light theme logo
- `logo-dark.png` - Dark theme logo
- `cdlIcon.svg` - Vector format icon ✓ (existing)
- `splash-screen.png` - Application splash screen (optional)

## Usage Notes

- All PNG files should have transparent backgrounds where appropriate
- Icons should follow Windows design guidelines for consistency
- The .ico file should contain multiple sizes (16, 32, 48, 256) for proper Windows integration
- SVG files are vector format and can be scaled without quality loss

## Integration

These images are referenced in:
- `ColDogStudios.ColDogLocker.Desktop.csproj` - Application icon
- `ColDogStudios.ColDogLocker.Console.csproj` - Console application icon
- WPF XAML files - UI element icons
- Resource files - Embedded application resources
