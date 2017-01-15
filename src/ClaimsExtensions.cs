using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using static System.String;

namespace Lenoard.AspNetCore.Identity
{
    public static class ClaimsExtensions
    {
        public static bool HasClaim(this IEnumerable<Claim> claims, string type)
        {
            if (claims == null) throw new ArgumentNullException(nameof(claims));
            if (IsNullOrWhiteSpace(type)) throw new ArgumentNullException(nameof(type));
            return claims.Any(x => x.Type == type);
        }

        public static bool HasClaim(this ClaimsIdentity identity, string type)
        {
            if (identity == null) throw new ArgumentNullException(nameof(identity));
            return identity.Claims.HasClaim(type);
        }

        public static bool HasClaim(this ClaimsPrincipal principal, string type)
        {
            if (principal == null) throw new ArgumentNullException(nameof(principal));
            return principal.Claims.HasClaim(type);
        }

        public static void RemoveClaims(this ClaimsIdentity identity, string type)
        {
            if (identity == null) throw new ArgumentNullException(nameof(identity));
            if (IsNullOrWhiteSpace(type)) throw new ArgumentNullException(nameof(type));

            foreach (var claim in identity.FindAll(x => x.Type == type).ToArray())
            {
                identity.RemoveClaim(claim);
            }
        }

        public static void AddClaim(this ClaimsIdentity identity, string type, string value)
        {
            if (identity == null) throw new ArgumentNullException(nameof(identity));
            if (IsNullOrWhiteSpace(type)) throw new ArgumentNullException(nameof(type));
            if (IsNullOrWhiteSpace(value)) throw new ArgumentNullException(nameof(value));
            if (!identity.HasClaim(type, value))
            {
                identity.AddClaim(new Claim(type, value));
            }
        }

        public static void SetClaim(this ClaimsIdentity identity, string type, string value)
        {
            if (identity == null) throw new ArgumentNullException(nameof(identity));
            if (IsNullOrWhiteSpace(type)) throw new ArgumentNullException(nameof(type));
            identity.RemoveClaims(type);
            if (!IsNullOrWhiteSpace(value))
            {
                identity.AddClaim(type, value);
            }
        }

        public static IEnumerable<string> FindClaims(this ClaimsIdentity identity, string type)
        {
            if (identity == null) throw new ArgumentNullException(nameof(identity));
            if (IsNullOrWhiteSpace(type)) throw new ArgumentNullException(nameof(type));
            return identity.FindAll(x => x.Type == type).Select(x=>x.Value);
        }

        public static string FindClaim(this ClaimsIdentity identity, string type)
        {
            return identity.FindClaims(type).FirstOrDefault();
        }

        public static IEnumerable<string> FindClaims(this ClaimsPrincipal principal, string type)
        {
            if (principal == null) throw new ArgumentNullException(nameof(principal));
            if (IsNullOrWhiteSpace(type)) throw new ArgumentNullException(nameof(type));
            return principal.FindAll(x => x.Type == type).Select(x => x.Value);
        }

        public static string FindClaim(this ClaimsPrincipal principal, string type)
        {
            return principal.FindClaims(type).FirstOrDefault();
        }
    }
}
