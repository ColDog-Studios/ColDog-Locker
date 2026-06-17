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

namespace ColDogStudios.ColDogLocker.Core.Models
{
    public class LockerModel(string lockerName, string password, string cdlLocation)
    {
        // Properties of the locker
        public string Guid { get; set; } = System.Guid.NewGuid().ToString();
        public string LockerName { get; set; } = lockerName;
        public string Password { get; set; } = password;
        public string LockerLocation { get; set; } = cdlLocation;
        public bool IsLocked { get; set; } = false;
        public int? StorageFormatVersion { get; set; }
        public string? LockedArchiveSha256 { get; set; }
        public DateTime? LockedAtUtc { get; set; }
    }
}
