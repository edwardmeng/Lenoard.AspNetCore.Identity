using System;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Lenoard.AspNetCore.Identity
{
    /// <summary>
    /// Contains extension methods to <see cref="IServiceCollection"/> for configuring identity services. 
    /// </summary>
    public static class IdentityServiceCollectionExtensions
    {
        /// <summary>
        /// Adds and configures the identity system for the specified User and Role types.
        /// </summary>
        /// <typeparam name="TUser">The type representing a User in the system.</typeparam>
        /// <typeparam name="TRole">The type representing a Role in the system.</typeparam>
        /// <param name="services">The services available in the application.</param>
        /// <param name="setupAction">An action to configure the <see cref="IdentityOptions"/>.</param>
        /// <returns>An <see cref="IdentityBuilder"/> for creating and configuring the identity system.</returns>
        public static IdentityBuilder AddIdentity<TUser, TRole>(this IServiceCollection services, Action<IdentityOptions> setupAction) where TUser : class where TRole : class
        {
            services.TryAddScoped<IUserClaimsPrincipalFactory<TUser>, FilteredUserClaimsPrincipalFactory<TUser, TRole>>();
            return Microsoft.Extensions.DependencyInjection.IdentityServiceCollectionExtensions.AddIdentity<TUser, TRole>(services, setupAction);
        }

        /// <summary>
        /// Adds the default identity system configuration for the specified User and Role types.
        /// </summary>
        /// <typeparam name="TUser">The type representing a User in the system.</typeparam>
        /// <typeparam name="TRole">The type representing a Role in the system.</typeparam>
        /// <param name="services">The services available in the application.</param>
        /// <returns>An <see cref="IdentityBuilder"/> for creating and configuring the identity system.</returns>
        public static IdentityBuilder AddIdentity<TUser, TRole>(this IServiceCollection services) where TUser : class where TRole : class
        {
            return services.AddIdentity<TUser, TRole>(null);
        }
    }
}
