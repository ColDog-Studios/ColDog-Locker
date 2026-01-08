# ColDog Locker Distribution Plan

## Build Strategy

### System Requirements
- **Operating System:**
  - **Minimum:** Windows 10 (version determined by .NET 10 support)
  - **Recommended:** Windows 11
- **Runtime:** .NET 10 Runtime (detected and prompted by installer if missing)
- **Architecture:** x64 or ARM64 (no 32-bit support)
- **Permissions:** Administrator required for installation (Program Files installation)

### Target Architectures
- **x64** (Windows 10/11 on Intel/AMD)
- **ARM64** (Windows on ARM devices - Surface, Qualcomm)
- ~~x86 (32-bit)~~ - Not a priority, most systems are 64-bit

### Build Configuration
- **Type:** Framework-dependent (requires .NET 10 runtime)
- **Packaging:** Separate DLLs (not single-file)
- **Optimization:** Release configuration with full optimizations

### Benefits of This Approach
- Smaller installer size (~5-10MB vs 80-120MB self-contained)
- Easier updates (replace only changed DLLs)
- Better for plugin architecture in the future
- Third-party DLLs can be organized in `libs` subfolder

---

## MSI Installer

### Installer Technology
- **Format:** MSI (Microsoft Installer)
- **Tools:** WiX Toolset / Advanced Installer / Visual Studio Installer Projects
- **Why MSI:** Better reputation, enterprise-friendly, proper uninstall/rollback support

### Installation Scope
- **Type:** System-wide installation (all users)
- **Location:** `C:\Program Files\ColDog Studios\ColDog Locker\`
- **Permissions:** Requires administrator privileges to install
- **Rationale:** 
  - Enterprise-friendly deployment
  - Centralized management for IT departments
  - Avoids per-user AppData pollution
  - Single installation for all users on the system
  - Professional application standard

> **Important:** No per-user installation option. MSI must require elevation for proper Program Files installation.

### Prerequisites Check
- Detect if .NET 10 Runtime is installed
- If missing, prompt user to install or download automatically
- Support both x64 and ARM64 runtime installations

### Installation Directory Structure
```
C:\Program Files\ColDog Studios\ColDog Locker\
├── ColDogLocker.exe                # GUI application
├── cdlocker.exe                    # CLI application
├── ColDogLocker.Core.dll           # Core library
├── ColDogLocker.Application.dll    # Application layer
├── ColDogLocker.Infrastructure.dll # Infrastructure layer
└── libs\                           # Third-party dependencies
    ├── BCrypt.Net-Next.dll
    ├── Microsoft.Data.Sqlite.dll
    ├── Newtonsoft.Json.dll
    ├── CommunityToolkit.Mvvm.dll
    └── Microsoft.Extensions.DependencyInjection.dll
```

### User Data Storage
- **Location:** `%LOCALAPPDATA%\ColDog Studios\ColDog Locker\`
- **Scope:** Per-user (each Windows user has their own data)
- **Contents:**
  - Locker database (`lockers.db`)
  - Application settings (`settings.json`)
  - Log files (`logs/` folder)
- **No Roaming:** Data stays on local machine only
- **Multi-User:** Fully supported - each user maintains separate lockers and settings

> **Important:** User data is stored outside Program Files to avoid permission issues and support multi-user scenarios.

---

## Installer Behavior

### Default Actions (Automatic)
- ✅ Create Start Menu shortcut
- ✅ Create Desktop shortcut
- ✅ Optional launch ColDogLocker.exe after installation completes

### Optional Actions (User Choice)
- ✅ Add installation directory to PATH (pre-checked)
  - Enables running `cdlocker` from any command prompt/PowerShell
  - Power users benefit, GUI-only users unaffected

### Explicitly NOT Included
- ❌ No auto-launch on Windows startup
- ❌ No installer-based update checks (handled by app settings)
- ❌ No file associations or context menu integration (future consideration)

### Uninstall Behavior
- **Program Files:** Always removed completely
- **User Data:** Optional removal (checkbox during uninstall)
  - If checked: Removes all logs, settings, and locker database from `%LOCALAPPDATA%`
  - If unchecked: Preserves user data for potential reinstall
  - **Default:** Unchecked (preserve data - avoid accidental data loss)

### EULA / License
- **License Display:** MSI shows ColDog Locker License text during installation
- **Acceptance Required:** User must accept license to proceed with installation
- **Language:** English only

---

## Update Strategy

### In-App Updates
- Update check handled by application (already implemented)
- Controlled via Settings → "Check for updates on startup"
- Default: Enabled
- No installer-level update mechanism needed

### Version Upgrades
- MSI GUID changes per version for proper upgrade handling
- Installer can detect and upgrade previous versions
- Clean uninstall of old version before installing new

### Database & Settings Migration
- **Handled by Application:** Schema/format changes managed by software, not installer
- **Automatic Backup:** Application creates backup before applying migrations
- **Backup Location:** `%LOCALAPPDATA%\ColDog Studios\ColDog Locker\backups\`
- **Migration Strategy:** On first launch after upgrade, detect version and migrate as needed

---

## Code Signing & Security

### Current Status (Pre-Release)
- No code signing (SmartScreen warnings may appear)
- Antivirus false positives expected (encryption triggers heuristics)

### Future Consideration (Stable Release)
- **Code Signing Certificate:** ~$100/year (probably won't happen)
  - Removes Windows SmartScreen warnings
  - Increases user trust
  - Required for enterprise deployment
- **Windows Defender Submission:** Submit to Microsoft for whitelisting at stable release
- **Antivirus Whitelisting:** File encryption operations may trigger false positives
  - Submit to major antivirus vendors for analysis
  - Document legitimate encryption use case

---

## Release Pipeline

### Build Commands

#### GUI (WPF)
```powershell
# x64
dotnet publish ColDogLocker.Gui.WPF/ColDogLocker.Gui.WPF.csproj -c Release -r win-x64 --self-contained false

# ARM64
dotnet publish ColDogLocker.Gui.WPF/ColDogLocker.Gui.WPF.csproj -c Release -r win-arm64 --self-contained false
```

#### CLI
```powershell
# x64
dotnet publish ColDogLocker.Cli/ColDogLocker.Cli.csproj -c Release -r win-x64 --self-contained false

# ARM64
dotnet publish ColDogLocker.Cli/ColDogLocker.Cli.csproj -c Release -r win-arm64 --self-contained false
```

### Automation Options
- **Manual:** Build and package locally for each release
- **GitHub Actions:** Automated builds on tag/release
- **CI/CD:** Auto-build, sign, and upload installers

---

## Next Steps

### Phase 1: Build Configuration
- [ ] Add Release configuration properties to WPF project
- [ ] Add Release configuration properties to CLI project
- [ ] Test Release builds for both x64 and ARM64
- [ ] Verify memory usage improvements in Release mode

### Phase 2: Installer Creation
- [ ] Choose installer tool (WiX / Advanced Installer / VS Installer)
- [ ] Create installer project/script
- [ ] Configure .NET runtime detection
- [ ] Add Start Menu + Desktop shortcuts
- [ ] Implement optional PATH addition (pre-checked)
- [ ] Set up launch-after-install

### Phase 3: Testing
- [ ] Test on clean Windows 10 x64 machine (no .NET 10)
- [ ] Test on Windows 11 ARM64 device (if available - no ARM64 hardware currently available)
- [ ] Test upgrade from previous version
- [ ] Test uninstallation (clean removal)
- [ ] Test uninstallation with user data removal option
- [ ] Verify PATH addition works correctly
- [ ] Verify database migration on upgrade
- [ ] Verify `Microsoft.Data.Sqlite` native libraries work on both architectures

### Phase 4: Distribution
- [ ] Create GitHub Release with MSI files
- [ ] Update README with installation instructions
- [ ] Consider code signing certificate
- [ ] Set up download page or release notes

---

## File Naming Convention

### Installers
- `ColDogLocker-0.2.0-x64.msi`
- `ColDogLocker-0.2.0-ARM64.msi`


---

## Notes

- MSI provides better user experience than plain EXE installers
- Framework-dependent approach keeps installer size small
- Dual architecture support future-proofs the application
- In-app update checks reduce installer complexity
- Clean directory structure allows for future expansion
- Program Files installation requires admin but ensures enterprise compatibility
- User data in %LOCALAPPDATA% avoids permission issues and supports multi-user
- Optional user data removal on uninstall protects against accidental data loss
- Application-level migrations provide more control than installer-based upgrades
- ARM64 support included but untested due to hardware limitations
