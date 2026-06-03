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

using ColDogStudios.ColDogLocker.Avalonia.Models;

namespace ColDogStudios.ColDogLocker.Avalonia.Tests.Models
{
    public class LockerItemViewModelTests
    {
        [Theory]
        [InlineData(false, "Unlocked")]
        [InlineData(true, "Locked")]
        public void StatusText_ShouldReflectLockState(bool isLocked, string expectedStatus)
        {
            var item = new LockerItemViewModel { IsLocked = isLocked };

            Assert.Equal(expectedStatus, item.StatusText);
            Assert.NotNull(item.StatusBrush);
        }

        [Theory]
        [InlineData(0, "0 B")]
        [InlineData(512, "512 B")]
        [InlineData(1024, "1 KB")]
        [InlineData(1536, "1.5 KB")]
        [InlineData(1048576, "1 MB")]
        [InlineData(1073741824, "1 GB")]
        public void SizeText_ShouldFormatBytes(long size, string expectedText)
        {
            var item = new LockerItemViewModel { Size = size };

            Assert.Equal(expectedText, item.SizeText);
        }

        [Fact]
        public void ChangingIsLocked_ShouldNotifyDependentProperties()
        {
            var item = new LockerItemViewModel();
            var changedProperties = new List<string?>();
            item.PropertyChanged += (_, args) => changedProperties.Add(args.PropertyName);

            item.IsLocked = true;

            Assert.Contains(nameof(LockerItemViewModel.IsLocked), changedProperties);
            Assert.Contains(nameof(LockerItemViewModel.StatusText), changedProperties);
            Assert.Contains(nameof(LockerItemViewModel.StatusIconData), changedProperties);
            Assert.Contains(nameof(LockerItemViewModel.StatusBrush), changedProperties);
        }

        [Fact]
        public void ChangingSize_ShouldNotifySizeText()
        {
            var item = new LockerItemViewModel();
            var changedProperties = new List<string?>();
            item.PropertyChanged += (_, args) => changedProperties.Add(args.PropertyName);

            item.Size = 2048;

            Assert.Contains(nameof(LockerItemViewModel.Size), changedProperties);
            Assert.Contains(nameof(LockerItemViewModel.SizeText), changedProperties);
        }
    }
}
