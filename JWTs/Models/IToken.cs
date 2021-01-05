namespace JWTs.Models
{
    public interface IToken
    {
        string access_token { get; set; }
        int expires_in { get; set; }
        string refresh_token { get; set; }
        string state { get; set; }
        string token_type { get; set; }
    }

    public class Token : IToken
    {
        public string access_token { get; set; }
        public int expires_in { get; set; }
        public string refresh_token { get; set; }
        public string state { get; set; }
        public string token_type { get; set; }
    }
}