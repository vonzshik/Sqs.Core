using BenchmarkDotNet.Attributes;
using Microsoft.Data.SqlClient;
using Scs.Core.Raw;
using System;
using System.Net;
using System.Threading.Tasks;

namespace Benchmark
{
    public class SelectOne
    {
        const string DefaultConnectionString = "Server=.; Database=master; Integrated Security=false; User ID=sa; Password=Master1234; Connect Timeout=200; pooling='true'; Max Pool Size=200;";

        SqlCommand Command { get; set; } = default!;

        string RawQuery = string.Empty;
        SqsDB RawDB;

        [GlobalSetup(Target = nameof(ReadSqlClientManaged))]
        public void SetupSqlClientManaged()
        {
            AppContext.SetSwitch("Switch.Microsoft.Data.SqlClient.UseManagedNetworkingOnWindows", true);

            var conn = new SqlConnection(DefaultConnectionString);
            conn.Open();
            this.Command = new SqlCommand("SELECT 1", conn);
        }

        [GlobalSetup(Target = nameof(ReadSqlClientUnmanaged))]
        public void SetupSqlClientUnmanaged()
        {
            AppContext.SetSwitch("Switch.Microsoft.Data.SqlClient.UseManagedNetworkingOnWindows", false);

            var conn = new SqlConnection(DefaultConnectionString);
            conn.Open();
            this.Command = new SqlCommand("SELECT 1", conn);
        }

        [GlobalSetup(Target = nameof(ReadRaw))]
        public async Task SetupRaw()
        {
            var endpoint = IPEndPoint.Parse("127.0.0.1:1433");
            this.RawDB = await SqsDB.OpenAsync(endpoint, "sa", "Master1234", "master");
            this.RawQuery = "SELECT 1";
        }

        [Benchmark]
        public async ValueTask ReadSqlClientManaged()
        {
            await using var reader = await this.Command.ExecuteReaderAsync();
            await reader.ReadAsync();
        }

        [Benchmark]
        public async ValueTask ReadSqlClientUnmanaged()
        {
            await using var reader = await this.Command.ExecuteReaderAsync();
            await reader.ReadAsync();
        }

        [Benchmark]
        public async ValueTask ReadRaw()
        {
            await this.RawDB.ExecuteAsync(this.RawQuery);

            await this.RawDB.EnsureSinglePacketAsync();
            var response = this.RawDB.ReadPacket();
        }
    }
}
