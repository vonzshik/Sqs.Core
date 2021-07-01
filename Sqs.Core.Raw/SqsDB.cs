using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace Scs.Core.Raw
{
    public sealed class SqsDB : IDisposable
    {
        private readonly Stream _stream;

        private readonly TdsParser _parser;

        public SqsDB(Stream stream, TdsParser parser)
        {
            this._stream = stream;
            this._parser = parser;
        }

        public void Dispose()
        {
            this._stream.Dispose();
            this._parser.Dispose();
        }

        public static async ValueTask<SqsDB> OpenAsync(EndPoint endPoint, string username, string password, string database)
        {
            var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            await socket.ConnectAsync(endPoint).ConfigureAwait(false);

            var stream = new NetworkStream(socket, ownsSocket: true);
            using var parser = new TdsParser(stream);

            await parser.SendPreLoginRequestAsync().ConfigureAwait(false);
            await parser.EnsureSinglePacketAsync().ConfigureAwait(false);
            var preLoginPacket = parser.ReadPacket();

            var tdsSslStream = new TdsSslStream(stream, leaveInnerStreamOpen: false);
            var sslStream = new SslStream(tdsSslStream, leaveInnerStreamOpen: false);
            await sslStream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions()
            {
                TargetHost = "localhost",
                RemoteCertificateValidationCallback = (_, _, _, _) => true,
            }).ConfigureAwait(false);
            tdsSslStream.Complete();
            var sslParser = new TdsParser(sslStream);

            await sslParser.SendLogin7RequestAsync(username, password, database).ConfigureAwait(false);
            await sslParser.EnsureSinglePacketAsync().ConfigureAwait(false);
            var loginPacket = sslParser.ReadPacket();

            if (loginPacket.Span[8] != 0xAD)
            {
                throw new Exception("Unsuccessful login");
            }

            var db = new SqsDB(sslStream, sslParser);

            return db;
        }

        public ValueTask ExecuteAsync(string sql) => this._parser.ExecuteAsync(sql);

        public ValueTask EnsureSinglePacketAsync() => this._parser.EnsureSinglePacketAsync();

        public ReadOnlyMemory<byte> ReadPacket() => this._parser.ReadPacket();
    }
}
