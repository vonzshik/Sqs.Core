using NUnit.Framework;
using System.Net;
using System.Threading.Tasks;

namespace Scs.Core.Raw.Tests
{
    public class Tests
    {
        const string EndPoint = "127.0.0.1:1433";
        const string UserName = "sa";
        const string Password = "Master1234";
        const string Database = "master";

        [Test]
        public async Task Test1()
        {
            var endpoint = IPEndPoint.Parse(EndPoint);
            using var db = await SqsDB.OpenAsync(endpoint, UserName, Password, Database);

            await db.ExecuteAsync("SELECT 1");
            await db.EnsureSinglePacketAsync();

            var packet = db.ReadPacket();
        }
    }
}