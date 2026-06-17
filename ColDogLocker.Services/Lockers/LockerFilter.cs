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

using ColDogStudios.ColDogLocker.Core.Models;

namespace ColDogStudios.ColDogLocker.Services.Lockers
{
    public static class LockerFilter
    {
        // Utility function to list lockers based on their locked status
        public static List<LockerModel> ListLockers(bool isLocked)
        {
            // Filter lockers based on the isLocked parameter
            var filteredLockers = LockerService.GetLockersSnapshot().Where(l => l.IsLocked == isLocked).ToList();

            // Return the filtered lockers
            return filteredLockers;
        }
    }
}
