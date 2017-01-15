using System;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Lenoard.AspNetCore.Identity.UnitTests
{
    public class UserClaimsPrincipalFilterTest
    {
        private readonly IServiceProvider _services;

        public UserClaimsPrincipalFilterTest()
        {
            var services = new ServiceCollection();
            services.AddIdentity<TestUser, TestRole>()
                .AddClaimsPrincipalFilter<TestUserClaimsPrincipalFilter>()
                .AddUserStore<InMemoryUserStore<TestUser, TestRole>>()
                .AddRoleStore<InMemoryRoleStore<TestRole>>();
            services.AddLogging();
            _services = services.BuildServiceProvider();
        }

        [Fact]
        public async Task TestClaimsPrincipalFilter()
        {
            var signin = _services.GetService<SignInManager<TestUser>>();
            var principal = await signin.CreateUserPrincipalAsync(new TestUser("Foo") {SecurityStamp = Guid.NewGuid().ToString()});
            var identity = Assert.IsType<ClaimsIdentity>(principal.Identity);
            Assert.True(identity.HasClaim("Permission"));
        }
    }
}