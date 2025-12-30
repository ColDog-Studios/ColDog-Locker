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
    }
}
