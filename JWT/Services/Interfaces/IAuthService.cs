using JWTApi.Models;
using JWTApi.Models.Account;
using JWTApi.Models.AuthServiceVM;

namespace JWTApi.Services.Interfaces
{
    public interface IAuthService
    {
        Task<AuthModel> RegisterAsync(RegisterM registerVM);

        Task<AuthModel> GetTokenAsync(GetTokenM login);

        Task<string> AddRoleAsync(AddRoleM roleM);

        Task<AuthModel> CheckOrCreateRefreshTokenAsync(string refreshToken);

        // if you want Revoked for token is active, use this method
        Task<bool> RevokedTokenAsync (string refreshToken);
    }
}
