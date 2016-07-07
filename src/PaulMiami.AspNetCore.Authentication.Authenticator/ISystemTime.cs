using System;

namespace PaulMiami.AspNetCore.Authentication.Authenticator
{
    public interface ISystemTime
    {
        DateTime GetUtcNow();
    }
}
