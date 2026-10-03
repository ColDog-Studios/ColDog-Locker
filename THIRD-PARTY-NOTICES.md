# Third-party notices

ColDog Locker includes or depends on third-party software. This inventory is based on the locked production dependency graph. Platform-specific packaging selects only the assets needed for that operating system and architecture.

The installers also include `DOTNET-LICENSE.txt` and `DOTNET-THIRD-PARTY-NOTICES.txt` from the exact .NET SDK used to produce the package. Those files cover the self-contained .NET runtime and its bundled components.

## MIT-licensed components

The following packages declare the MIT license. Package source and exact transitive relationships are recorded in the checked-in NuGet lock files and release manifest.

- Avalonia, Avalonia.Desktop, Avalonia.Fonts.Inter, Avalonia.FreeDesktop, Avalonia.FreeDesktop.AtSpi, Avalonia.HarfBuzz, Avalonia.Native, Avalonia.Remote.Protocol, Avalonia.Skia, Avalonia.Themes.Fluent, Avalonia.Win32 and Avalonia.X11 12.1.2 — Copyright 2013–2026 The AvaloniaUI Project
- CommunityToolkit.Mvvm 8.4.2 — .NET Foundation and contributors
- HarfBuzzSharp and HarfBuzzSharp.NativeAssets 8.3.1.3 — Microsoft Corporation and HarfBuzz contributors
- Material.Icons and Material.Icons.Avalonia 3.0.2 — SKProCH and contributors
- MicroCom.Runtime 0.11.6 — Copyright 2021 Nikita Tsukanov
- Microsoft.Data.Sqlite.Core, Microsoft.Extensions.DependencyInjection and Microsoft.Extensions.DependencyInjection.Abstractions 10.0.12 — Microsoft Corporation
- Newtonsoft.Json 13.0.4 — Copyright 2008 James Newton-King
- SkiaSharp and SkiaSharp.NativeAssets 3.119.4 — Microsoft Corporation, Google and Skia contributors
- Tmds.DBus.Protocol 0.94.1 — Tom Deseyn and contributors

The MIT License:

> Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## SQLitePCLRaw

SQLitePCLRaw.bundle_e_sqlite3, SQLitePCLRaw.config.e_sqlite3, SQLitePCLRaw.core and SQLitePCLRaw.provider.e_sqlite3 3.0.5 are Copyright 2014–2026 SourceGear, LLC and are licensed under Apache License 2.0. The license text is available at <https://www.apache.org/licenses/LICENSE-2.0> and the source repository is <https://github.com/ericsink/SQLitePCL.raw>.

The SQLite 3.53.4 native library is dedicated to the public domain. Its copyright and public-domain statement is at <https://sqlite.org/copyright.html>.

## ANGLE

Avalonia.Angle.Windows.Natives 2.1.27548.20260419 contains ANGLE. Copyright 2018 The ANGLE Project Authors. All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
3. Neither the names of TransGaming Inc., Google Inc., 3DLabs Inc. Ltd., nor the names of their contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

## Inter font

The Inter font data distributed through Avalonia.Fonts.Inter is Copyright 2016 The Inter Project Authors and is licensed under the SIL Open Font License 1.1: <https://openfontlicense.org/open-font-license-official-text/>.

## Material Design icon data

Material icon data is derived from Material Design Icons and is licensed under Apache License 2.0. See <https://github.com/Templarian/MaterialDesign> for attribution and source.

## Build-only dependencies

Avalonia.BuildServices 11.3.2 and Microsoft.NET.ILLink.Tasks 10.0.12 participate in the build but are not application runtime components. Release tooling dependencies are locked separately in `.github/package-lock.json` and are not shipped in the application packages.
