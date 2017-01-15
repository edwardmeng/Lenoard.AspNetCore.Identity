using System.Security.Claims;
using System.Threading.Tasks;

namespace Lenoard.AspNetCore.UnitTests
{
    public class TestUserClaimsPrincipalFilter: IUserClaimsPrincipalFilter<TestUser>
    {
        public Task ConfigureAsync(TestUser user, ClaimsPrincipal principal)
        {
            ((ClaimsIdentity)principal.Identity).AddClaim(new Claim("Permission", "TestUserPermission"));
            return Task.Delay(0);
        }
    }
}
