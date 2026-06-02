using ColDogStudios.ColDogLocker.Core.Models;

namespace ColDogStudios.ColDogLocker.Services.Lockers
{
    public static class LockerFilter
    {
        // Utility function to list lockers based on their locked status
        public static List<LockerModel> ListLockers(bool isLocked)
        {
            // Filter lockers based on the isLocked parameter
            var filteredLockers = LockerService.Lockers.Where(l => l.IsLocked == isLocked).ToList();

            // Return the filtered lockers
            return filteredLockers;
        }
    }
}
