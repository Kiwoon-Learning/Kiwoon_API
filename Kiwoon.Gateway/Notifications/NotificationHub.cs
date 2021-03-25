using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.SignalR;

namespace Kiwoon.Gateway.Notifications
{
    [Authorize]
    public class NotificationHub : Hub
    {
    }
}
