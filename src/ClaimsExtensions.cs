using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;

namespace Lenoard.AspNetCore.Identity
{
    /// <summary>
    /// Claims related extensions for <see cref="ClaimsPrincipal"/> and <see cref="ClaimsIdentity"/>. 
    /// </summary>
    public static class ClaimsExtensions
    {
        /// <summary>
        /// Determines whether this claims identity contains a claim with the specified claim type.
        /// </summary>
        /// <param name="identity">The claims identity to determine with.</param>
        /// <param name="type">The type of the claim to match.</param>
        /// <returns><c>true</c> if a matching claim exists; otherwise, <c>false</c>.</returns>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="identity"/> is null.
        /// -or-
        /// <paramref name="type"/> is null.
        /// </exception>
        public static bool HasClaim(this ClaimsIdentity identity, string type)
        {
            if (identity == null) throw new ArgumentNullException(nameof(identity));
            if (type == null) throw new ArgumentNullException(nameof(type));
            return identity.Claims.Any(x => x.Type == type);
        }

        /// <summary>
        /// Determines whether any of the claims identities associated with this claims principal contains a claim with the specified claim type.
        /// </summary>
        /// <param name="principal">The claims principal to determine with.</param>
        /// <param name="type">The type of the claim to match.</param>
        /// <returns><c>true</c> if a matching claim exists; otherwise, <c>false</c>.</returns>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="principal"/> is null.
        /// -or-
        /// <paramref name="type"/> is null.
        /// </exception>
        public static bool HasClaim(this ClaimsPrincipal principal, string type)
        {
            if (principal == null) throw new ArgumentNullException(nameof(principal));
            return principal.Claims.Any(x => x.Type == type);
        }

        /// <summary>
        /// Attempts to remove all the claims from the claims identity with the specified claim type.
        /// </summary>
        /// <param name="identity">The identity to remove claims.</param>
        /// <param name="type">The type of the claim to match.</param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="identity"/> is null.
        /// -or-
        /// <paramref name="type"/> is null.
        /// </exception>
        /// <exception cref="InvalidOperationException">The claim cannot be removed.</exception>
        public static void RemoveClaims(this ClaimsIdentity identity, string type)
        {
            if (identity == null) throw new ArgumentNullException(nameof(identity));
            if (type == null) throw new ArgumentNullException(nameof(type));

            foreach (var claim in identity.FindAll(x => x.Type == type).ToArray())
            {
                identity.RemoveClaim(claim);
            }
        }

        /// <summary>
        /// Attempts to remove all the claims from the claims identity with the specified claim type.
        /// </summary>
        /// <param name="identity">The identity to remove claims.</param>
        /// <param name="type">The type of the claim to match.</param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="identity"/> is null.
        /// </exception>
        /// <returns><c>true</c> if the claim was successfully removed; otherwise, <c>false</c>.</returns>
        public static bool TryRemoveClaims(this ClaimsIdentity identity, string type)
        {
            if (identity == null) throw new ArgumentNullException(nameof(identity));
            if (type == null) return false;

            var removedClaims = new List<Claim>();
            foreach (var claim in identity.FindAll(x => x.Type == type).ToArray())
            {
                if (identity.TryRemoveClaim(claim))
                {
                    removedClaims.Add(claim);
                }
                else
                {
                    identity.AddClaims(removedClaims);
                    return false;
                }
            }
            return true;
        }

        /// <summary>
        /// Adds a single claim to the claims identity using the specified claim type and value.
        /// </summary>
        /// <param name="identity">The identity to add claim.</param>
        /// <param name="type">The type of the claim.</param>
        /// <param name="value">The value of the claim.</param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="identity"/> is null.
        /// -or-
        /// <paramref name="type"/> is null.
        /// -or-
        /// <paramref name="value"/> is null.
        /// </exception>
        /// <returns><c>true</c> if the claim was successfully added; otherwise, <c>false</c>.</returns>
        public static bool AddClaim(this ClaimsIdentity identity, string type, string value)
        {
            if (identity == null) throw new ArgumentNullException(nameof(identity));
            if (type == null) throw new ArgumentNullException(nameof(type));
            if (value == null) throw new ArgumentNullException(nameof(value));
            if (!identity.HasClaim(type, value))
            {
                identity.AddClaim(new Claim(type, value));
                return true;
            }
            return false;
        }

        /// <summary>
        /// Sets the value of a single claim to the claims identity using the specified claim type and value.
        /// </summary>
        /// <param name="identity">The identity to set claim value.</param>
        /// <param name="type">The type of the claim.</param>
        /// <param name="value">The value of the claim.</param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="identity"/> is null.
        /// -or-
        /// <paramref name="type"/> is null.
        /// -or-
        /// <paramref name="value"/> is null.
        /// </exception>
        /// <returns><c>true</c> if the claim value was successfully changed; otherwise, <c>false</c>.</returns>
        public static bool SetClaim(this ClaimsIdentity identity, string type, string value)
        {
            if (identity == null) throw new ArgumentNullException(nameof(identity));
            if (type == null) throw new ArgumentNullException(nameof(type));
            if (value == null) throw new ArgumentNullException(nameof(value));
            if (identity.TryRemoveClaims(type))
            {
                identity.AddClaim(type, value);
                return true;
            }
            return false;
        }

        /// <summary>
        /// Retrieves all of the claim values that have the specified claim type.
        /// </summary>
        /// <param name="identity">The claims identity to retrieve claim values with.</param>
        /// <param name="type">The claim type against which to match claims.</param>
        /// <returns>The matching claim values. The list is read-only.</returns>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="identity"/> is null.
        /// -or-
        /// <paramref name="type"/> is null.
        /// </exception>
        public static IEnumerable<string> GetClaimValues(this ClaimsIdentity identity, string type)
        {
            if (identity == null) throw new ArgumentNullException(nameof(identity));
            return identity.FindAll(type).Select(claim => claim.Value);
        }

        /// <summary>
        /// Retrieves the first claim value with the specified claim type.
        /// </summary>
        /// <param name="identity">The claims identity to retrieve claim value with.</param>
        /// <param name="type">The claim type against which to match claims.</param>
        /// <returns>The matching claim value.</returns>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="identity"/> is null.
        /// -or-
        /// <paramref name="type"/> is null.
        /// </exception>
        public static string GetClaimValue(this ClaimsIdentity identity, string type)
        {
            return identity.GetClaimValues(type).FirstOrDefault();
        }

        /// <summary>
        /// Retrieves all of the claim values that have the specified claim type.
        /// </summary>
        /// <param name="principal">The claims principal to retrieve claim values with.</param>
        /// <param name="type">The claim type against which to match claims.</param>
        /// <returns>The matching claim values. The list is read-only.</returns>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="principal"/> is null.
        /// -or-
        /// <paramref name="type"/> is null.
        /// </exception>
        public static IEnumerable<string> GetClaimValues(this ClaimsPrincipal principal, string type)
        {
            if (principal == null) throw new ArgumentNullException(nameof(principal));
            return principal.FindAll(type).Select(claim => claim.Value);
        }

        /// <summary>
        /// Retrieves the first claim value with the specified claim type.
        /// </summary>
        /// <param name="principal">The claims principal to retrieve claim value with.</param>
        /// <param name="type">The claim type against which to match claims.</param>
        /// <returns>The matching claim value.</returns>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="principal"/> is null.
        /// -or-
        /// <paramref name="type"/> is null.
        /// </exception>
        public static string GetClaimValue(this ClaimsPrincipal principal, string type)
        {
            return principal.GetClaimValues(type).FirstOrDefault();
        }
    }
}
