using System;
using Microsoft.Extensions.DependencyInjection;

namespace SharedModels.Domain
{
    public static class ServiceScopeExtensions
    {
        public static T GetNotNullService<T>(this IServiceScope scope)
        {
            var service = scope.ServiceProvider.GetService<T>();
            if (service == null) throw new NullReferenceException(nameof(service));
            return service;
        }
    }
}
