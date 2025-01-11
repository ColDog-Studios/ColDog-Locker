using ColDogStudios.ColDogLocker.Core;
using ColDogStudios.ColDogLocker.Models;

namespace ColDogStudios.ColDogLocker.Utils
{
    public static class LockerFilter
    {
        // Utility function to list lockers based on their locked status
        public static List<LockerModel> ListLockers(bool isLocked)
        {
            // Filter lockers based on the isLocked parameter
            var filteredLockers = Locker.Lockers.Where(l => l.IsLocked == isLocked).ToList();

            // Print lockers to the console
            for (int i = 0; i < filteredLockers.Count; i++)
            {
                Console.WriteLine($"{i + 1}) {filteredLockers[i].LockerName}");
            }

            // Return the filtered lockers
            return filteredLockers;
        }
    }
}
