using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using Kiwoon.Gateway.Domain.Notifications;
using Microsoft.Extensions.DependencyInjection;

namespace Kiwoon.Gateway.Notifications
{
    public class BackgroundTaskQueue : IBackgroundTaskQueue
    {
        private readonly ConcurrentQueue<Func<IServiceScope, CancellationToken, Task<ApiQueuedResponse>>> _workItems =
            new();
        private readonly SemaphoreSlim _signal = new(0);

        public void QueueBackgroundWorkItemRange(params Func<IServiceScope, CancellationToken, Task<ApiQueuedResponse>>[] workItems)
        {
            if (workItems == null)
            {
                throw new ArgumentNullException(nameof(workItems));
            }
            foreach(var workItem in workItems)
                _workItems.Enqueue(workItem);
            _signal.Release();
        }

        public async Task<Func<IServiceScope, CancellationToken, Task<ApiQueuedResponse>>> 
            DequeueAsync(CancellationToken cancellationToken)
        {
            await _signal.WaitAsync(cancellationToken);
            _workItems.TryDequeue(out var result);
            return result;
        }
        public void QueueBackgroundWorkItem(
            Func<IServiceScope, CancellationToken, Task<ApiQueuedResponse>> workItem)
        {
            if (workItem == null)
            {
                throw new ArgumentNullException(nameof(workItem));
            }

            _workItems.Enqueue(workItem);
            _signal.Release();
        }

    }
}
