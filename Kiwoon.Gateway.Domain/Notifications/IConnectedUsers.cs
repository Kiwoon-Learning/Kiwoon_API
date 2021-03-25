using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Kiwoon.Gateway.Domain.Notifications
{
    public interface IConnectedUsers
    {
        public Task<bool> AddConnectedUser(string id, CancellationToken token = default);
        public Task<bool> RemoveConnectedUser(string id, CancellationToken token = default);
        public Task<bool> IsConnectedUser(string user);
        public Task<IList<string>> GetAllConnectedUsers();
    }
}
