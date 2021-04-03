using System.Threading.Tasks;

namespace Kiwoon.Domain
{
    public interface IGenericRepository<TResult, T>
    {
        public Task<TResult> Create(T item);
        public Task<T> Read(T item);
        public Task Update(T item);
        public Task Delete(T item);
    }
}
