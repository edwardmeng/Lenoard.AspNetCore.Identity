using System.Security.Claims;
using System.Threading.Tasks;

namespace Lenoard.AspNetCore.Identity
{
    /// <summary>
    /// A filter that asynchronously configure the <see cref="ClaimsPrincipal"/> on creating user identity. 
    /// </summary>
    /// <typeparam name="TUser">The type encapsulating a user.</typeparam>
    public interface IUserClaimsPrincipalFilter<in TUser> where TUser:class
    {
        /// <summary>
        /// Configures the <see cref="ClaimsPrincipal"/> with the specified user information.
        /// </summary>
        /// <param name="user">The user to configure a <see cref="ClaimsPrincipal"/>.</param>
        /// <param name="principal">The principal to be configured.</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        Task ConfigureAsync(TUser user, ClaimsPrincipal principal);
    }
}
