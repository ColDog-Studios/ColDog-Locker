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
using ColDogStudios.ColDogLocker.Services.Lockers;

namespace ColDogStudios.ColDogLocker.Services.Tests.Lockers
{
    public class LockerFilterTests
    {
        [Fact]
        public void ListLockers_WithNoLockers_ShouldReturnEmptyList()
        {
            // Arrange
            LockerService.Lockers.Clear();

            // Act
            var result = LockerFilter.ListLockers(false);

            // Assert
            Assert.Empty(result);
        }

        [Fact]
        public void ListLockers_WithOnlyLockedLockers_FilteringForUnlocked_ShouldReturnEmptyList()
        {
            // Arrange
            LockerService.Lockers.Clear();
            LockerService.Lockers.Add(new LockerModel("Locker1", "pass1", "loc1") { IsLocked = true });
            LockerService.Lockers.Add(new LockerModel("Locker2", "pass2", "loc2") { IsLocked = true });

            // Act
            var result = LockerFilter.ListLockers(false);

            // Assert
            Assert.Empty(result);
        }

        [Fact]
        public void ListLockers_WithOnlyUnlockedLockers_FilteringForLocked_ShouldReturnEmptyList()
        {
            // Arrange
            LockerService.Lockers.Clear();
            LockerService.Lockers.Add(new LockerModel("Locker1", "pass1", "loc1") { IsLocked = false });
            LockerService.Lockers.Add(new LockerModel("Locker2", "pass2", "loc2") { IsLocked = false });

            // Act
            var result = LockerFilter.ListLockers(true);

            // Assert
            Assert.Empty(result);
        }

        [Fact]
        public void ListLockers_FilteringForLocked_ShouldReturnOnlyLockedLockers()
        {
            // Arrange
            LockerService.Lockers.Clear();
            var lockedLocker1 = new LockerModel("LockedLocker1", "pass1", "loc1") { IsLocked = true };
            var lockedLocker2 = new LockerModel("LockedLocker2", "pass2", "loc2") { IsLocked = true };
            var unlockedLocker = new LockerModel("UnlockedLocker", "pass3", "loc3") { IsLocked = false };

            LockerService.Lockers.Add(lockedLocker1);
            LockerService.Lockers.Add(unlockedLocker);
            LockerService.Lockers.Add(lockedLocker2);

            // Act
            var result = LockerFilter.ListLockers(true);

            // Assert
            Assert.Equal(2, result.Count);
            Assert.Contains(lockedLocker1, result);
            Assert.Contains(lockedLocker2, result);
            Assert.DoesNotContain(unlockedLocker, result);
        }

        [Fact]
        public void ListLockers_FilteringForUnlocked_ShouldReturnOnlyUnlockedLockers()
        {
            // Arrange
            LockerService.Lockers.Clear();
            var unlockedLocker1 = new LockerModel("UnlockedLocker1", "pass1", "loc1") { IsLocked = false };
            var unlockedLocker2 = new LockerModel("UnlockedLocker2", "pass2", "loc2") { IsLocked = false };
            var lockedLocker = new LockerModel("LockedLocker", "pass3", "loc3") { IsLocked = true };

            LockerService.Lockers.Add(unlockedLocker1);
            LockerService.Lockers.Add(lockedLocker);
            LockerService.Lockers.Add(unlockedLocker2);

            // Act
            var result = LockerFilter.ListLockers(false);

            // Assert
            Assert.Equal(2, result.Count);
            Assert.Contains(unlockedLocker1, result);
            Assert.Contains(unlockedLocker2, result);
            Assert.DoesNotContain(lockedLocker, result);
        }

        [Fact]
        public void ListLockers_WithMixedLockers_ShouldFilterCorrectly()
        {
            // Arrange
            LockerService.Lockers.Clear();
            var locker1 = new LockerModel("Locker1", "pass1", "loc1") { IsLocked = true };
            var locker2 = new LockerModel("Locker2", "pass2", "loc2") { IsLocked = false };
            var locker3 = new LockerModel("Locker3", "pass3", "loc3") { IsLocked = true };
            var locker4 = new LockerModel("Locker4", "pass4", "loc4") { IsLocked = false };
            var locker5 = new LockerModel("Locker5", "pass5", "loc5") { IsLocked = true };

            LockerService.Lockers.AddRange([locker1, locker2, locker3, locker4, locker5]);

            // Act
            var lockedResult = LockerFilter.ListLockers(true);
            var unlockedResult = LockerFilter.ListLockers(false);

            // Assert
            Assert.Equal(3, lockedResult.Count);
            Assert.Equal(2, unlockedResult.Count);

            Assert.Contains(locker1, lockedResult);
            Assert.Contains(locker3, lockedResult);
            Assert.Contains(locker5, lockedResult);

            Assert.Contains(locker2, unlockedResult);
            Assert.Contains(locker4, unlockedResult);
        }

        [Fact]
        public void ListLockers_ReturnsNewListInstance()
        {
            // Arrange
            LockerService.Lockers.Clear();
            LockerService.Lockers.Add(new LockerModel("Locker1", "pass1", "loc1") { IsLocked = true });

            // Act
            var result1 = LockerFilter.ListLockers(true);
            var result2 = LockerFilter.ListLockers(true);

            // Assert
            Assert.NotSame(result1, result2);
        }

        [Fact]
        public void ListLockers_WithSingleLockedLocker_ShouldReturnIt()
        {
            // Arrange
            LockerService.Lockers.Clear();
            var locker = new LockerModel("SingleLocker", "pass", "loc") { IsLocked = true };
            LockerService.Lockers.Add(locker);

            // Act
            var result = LockerFilter.ListLockers(true);

            // Assert
            Assert.Single(result);
            Assert.Contains(locker, result);
        }

        [Fact]
        public void ListLockers_WithSingleUnlockedLocker_ShouldReturnIt()
        {
            // Arrange
            LockerService.Lockers.Clear();
            var locker = new LockerModel("SingleLocker", "pass", "loc") { IsLocked = false };
            LockerService.Lockers.Add(locker);

            // Act
            var result = LockerFilter.ListLockers(false);

            // Assert
            Assert.Single(result);
            Assert.Contains(locker, result);
        }

        [Fact]
        public void ListLockers_DoesNotModifyOriginalList()
        {
            // Arrange
            LockerService.Lockers.Clear();
            var locker = new LockerModel("Locker1", "pass1", "loc1") { IsLocked = true };
            LockerService.Lockers.Add(locker);
            var originalCount = LockerService.Lockers.Count;

            // Act
            var result = LockerFilter.ListLockers(true);
            result.Add(new LockerModel("NewLocker", "pass", "loc") { IsLocked = true });

            // Assert
            Assert.Equal(originalCount, LockerService.Lockers.Count);
        }

        [Fact]
        public void ListLockers_WithMultipleCallsWithDifferentStates_ReturnsCorrectResults()
        {
            // Arrange
            LockerService.Lockers.Clear();
            LockerService.Lockers.Add(new LockerModel("Locked1", "pass1", "loc1") { IsLocked = true });
            LockerService.Lockers.Add(new LockerModel("Unlocked1", "pass2", "loc2") { IsLocked = false });

            // Act
            var lockedResult = LockerFilter.ListLockers(true);
            var unlockedResult = LockerFilter.ListLockers(false);

            // Assert
            Assert.Single(lockedResult);
            Assert.Single(unlockedResult);
            Assert.True(lockedResult[0].IsLocked);
            Assert.False(unlockedResult[0].IsLocked);
        }
    }
}
