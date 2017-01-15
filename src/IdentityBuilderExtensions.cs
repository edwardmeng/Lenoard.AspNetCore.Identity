using System;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace Lenoard.AspNetCore.Identity
{
    /// <summary>
    ///     Contains extension methods to <see cref="IdentityBuilder" /> for configuring identity services.
    /// </summary>
    public static class IdentityBuilderExtensions
    {
        /// <summary>
        ///     Adds an <see cref="IUserClaimsPrincipalFilter{T}" /> for the <see cref="IdentityBuilder.UserType" />.
        /// </summary>
        /// <typeparam name="T">The type of the claims principal filter.</typeparam>
        /// <param name="builder">The <see cref="IdentityBuilder" /> to add claims principal filter with.</param>
        /// <returns>The <see cref="IdentityBuilder" /> instance.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="builder"/> is null.</exception>
        public static IdentityBuilder AddClaimsPrincipalFilter<T>(this IdentityBuilder builder)
            where T : class
        {
            if (builder == null)
                throw new ArgumentNullException(nameof(builder));
            builder.Services.AddScoped(typeof(IUserClaimsPrincipalFilter<>).MakeGenericType(builder.UserType), typeof(T));
            return builder;
        }
    }
}