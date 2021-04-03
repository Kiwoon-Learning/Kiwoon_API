using System;

namespace Kiwoon.Domain
{
    public class ApiResponse<T>
    {
        public ApiResponse()
        {
            
        }
#nullable enable

        public ApiResponse(bool succeeded, int statusCode, params T[]? response)
        {
            Succeeded = succeeded;
            StatusCode = statusCode;
            Response = response ?? Array.Empty<T>();
        }
        public bool Succeeded { get; set; }
        public int StatusCode { get; set; }
        public T[] Response { get; set; }
    }
}
