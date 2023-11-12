namespace JWTApi.Helper.appsettingsSections
{
    public class JWT
    {
        public string Key { get; set; }
        public string Issure { get; set; }
        public string Audience { get; set; }
        public double DurationInMinutes { get; set; }
    }
}
