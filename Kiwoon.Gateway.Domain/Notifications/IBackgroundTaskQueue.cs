using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;

namespace Kiwoon.Gateway.Domain.Notifications
{
    public interface IBackgroundTaskQueue
    {
        void QueueBackgroundWorkItem(Func<IServiceScope, CancellationToken, Task<ApiQueuedResponse>> workItem);
        void QueueBackgroundWorkItemRange(params Func<IServiceScope, CancellationToken, Task<ApiQueuedResponse>>[] workItems);

        Task<Func<IServiceScope, CancellationToken, Task<ApiQueuedResponse>>> DequeueAsync(
            CancellationToken cancellationToken);
    }
}
