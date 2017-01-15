using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace Lenoard.AspNetCore.Identity
{
    /// <summary>
    /// Provides methods to create a claims principal for a given user. 
    /// </summary>
    /// <typeparam name="TUser">The type used to represent a user.</typeparam>
    /// <typeparam name="TRole">The type used to represent a role.</typeparam>
    public class FilteredUserClaimsPrincipalFactory<TUser, TRole> : UserClaimsPrincipalFactory<TUser, TRole>
        where TUser : class where TRole : class
    {
        private readonly List<IUserClaimsPrincipalFilter<TUser>> _filters = new List<IUserClaimsPrincipalFilter<TUser>>();

        /// <summary>
        /// Initializes a new instance of the <see cref="FilteredUserClaimsPrincipalFactory{TUser,TRole}"/> class. 
        /// </summary>
        /// <param name="userManager">The <see cref="UserManager{TUser}"/> to retrieve user information from.</param>
        /// <param name="roleManager">The <see cref="RoleManager{TRole}"/> to retrieve a user's roles from.</param>
        /// <param name="optionsAccessor">The configured <see cref="IdentityOptions"/>.</param>
        /// <param name="filters">A collection of <see cref="IUserClaimsPrincipalFilter{TUser}"/> to configure identity with.</param>
        public FilteredUserClaimsPrincipalFactory(UserManager<TUser> userManager, RoleManager<TRole> roleManager, IOptions<IdentityOptions> optionsAccessor, IEnumerable<IUserClaimsPrincipalFilter<TUser>> filters) : base(userManager, roleManager, optionsAccessor)
        {
            if (filters != null)
            {
                _filters.AddRange(filters);
            }
        }

        /// <summary>
        /// Creates a <see cref="ClaimsPrincipal"/> from an user asynchronously. 
        /// </summary>
        /// <param name="user">The user to create a <see cref="ClaimsPrincipal"/> from.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous creation operation, containing the created <see cref="ClaimsPrincipal"/>.</returns>
        public override async Task<ClaimsPrincipal> CreateAsync(TUser user)
        {
            var principal = await base.CreateAsync(user);
            foreach (var filter in _filters)
            {
                await filter.ConfigureAsync(user, principal);
            }
            return principal;
        }
    }
}
