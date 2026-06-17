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

namespace ColDogStudios.ColDogLocker.Core.Tests.Models
{
    public class LockerModelTests
    {
        [Fact]
        public void Constructor_ShouldSetPropertiesCorrectly()
        {
            // Arrange
            var lockerName = "MyLocker";
            var password = "SecurePassword@123!";
            var cdlLocation = @"C:\Users\TestUser\Documents\ColDog Locker\MyLocker";

            // Act
            var locker = new LockerModel(lockerName, password, cdlLocation);

            // Assert
            Assert.Equal(lockerName, locker.LockerName);
            Assert.Equal(password, locker.Password);
            Assert.Equal(cdlLocation, locker.LockerLocation);
        }

        [Fact]
        public void Constructor_ShouldGenerateUniqueGuid()
        {
            // Arrange & Act
            var locker1 = new LockerModel("Locker1", "pass1", "location1");
            var locker2 = new LockerModel("Locker2", "pass2", "location2");

            // Assert
            Assert.NotNull(locker1.Guid);
            Assert.NotNull(locker2.Guid);
            Assert.NotEqual(locker1.Guid, locker2.Guid);
            Assert.True(Guid.TryParse(locker1.Guid, out _), "Guid should be a valid GUID format");
            Assert.True(Guid.TryParse(locker2.Guid, out _), "Guid should be a valid GUID format");
        }

        [Fact]
        public void Constructor_ShouldSetIsLockedToFalseByDefault()
        {
            // Arrange & Act
            var locker = new LockerModel("TestLocker", "password", "location");

            // Assert
            Assert.False(locker.IsLocked);
        }

        [Fact]
        public void LockerName_CanBeModified()
        {
            // Arrange
            var locker = new LockerModel("OriginalName", "password", "location");
            var newName = "NewName";

            // Act
            locker.LockerName = newName;

            // Assert
            Assert.Equal(newName, locker.LockerName);
        }

        [Fact]
        public void Password_CanBeModified()
        {
            // Arrange
            var locker = new LockerModel("Locker", "OriginalPassword", "location");
            var newPassword = "NewPassword@456!";

            // Act
            locker.Password = newPassword;

            // Assert
            Assert.Equal(newPassword, locker.Password);
        }

        [Fact]
        public void LockerLocation_CanBeModified()
        {
            // Arrange
            var locker = new LockerModel("Locker", "password", "OriginalLocation");
            var newLocation = @"C:\NewPath\NewLocation";

            // Act
            locker.LockerLocation = newLocation;

            // Assert
            Assert.Equal(newLocation, locker.LockerLocation);
        }

        [Fact]
        public void IsLocked_CanBeToggled()
        {
            // Arrange
            var locker = new LockerModel("Locker", "password", "location");
            Assert.False(locker.IsLocked); // Initial state

            // Act
            locker.IsLocked = true;

            // Assert
            Assert.True(locker.IsLocked);

            // Act again
            locker.IsLocked = false;

            // Assert
            Assert.False(locker.IsLocked);
        }

        [Fact]
        public void Guid_CanBeModified()
        {
            // Arrange
            var locker = new LockerModel("Locker", "password", "location");
            var customGuid = Guid.NewGuid().ToString();

            // Act
            locker.Guid = customGuid;

            // Assert
            Assert.Equal(customGuid, locker.Guid);
        }

        [Theory]
        [InlineData("")]
        [InlineData(" ")]
        [InlineData("ValidLockerName")]
        public void Constructor_ShouldAcceptVariousLockerNames(string lockerName)
        {
            // Act
            var locker = new LockerModel(lockerName, "password", "location");

            // Assert
            Assert.Equal(lockerName, locker.LockerName);
        }

        [Theory]
        [InlineData("")]
        [InlineData("short")]
        [InlineData("VeryLongPasswordWith1234567890!@#$%^&*()")]
        public void Constructor_ShouldAcceptVariousPasswords(string password)
        {
            // Act
            var locker = new LockerModel("Locker", password, "location");

            // Assert
            Assert.Equal(password, locker.Password);
        }

        [Theory]
        [InlineData("")]
        [InlineData(@"C:\")]
        [InlineData(@"\\NetworkPath\Share\Folder")]
        [InlineData("/usr/local/share")]
        public void Constructor_ShouldAcceptVariousLocations(string location)
        {
            // Act
            var locker = new LockerModel("Locker", "password", location);

            // Assert
            Assert.Equal(location, locker.LockerLocation);
        }

        [Fact]
        public void MultipleLockers_ShouldHaveIndependentState()
        {
            // Arrange & Act
            var locker1 = new LockerModel("Locker1", "pass1", "loc1");
            var locker2 = new LockerModel("Locker2", "pass2", "loc2");

            locker1.IsLocked = true;
            locker2.IsLocked = false;

            // Assert
            Assert.True(locker1.IsLocked);
            Assert.False(locker2.IsLocked);
            Assert.NotEqual(locker1.LockerName, locker2.LockerName);
            Assert.NotEqual(locker1.Password, locker2.Password);
            Assert.NotEqual(locker1.LockerLocation, locker2.LockerLocation);
        }
    }
}
