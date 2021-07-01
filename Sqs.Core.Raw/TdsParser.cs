using System;
using System.Buffers.Binary;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Scs.Core.Raw
{
    public sealed class TdsParser : IDisposable
    {
        private readonly ReadBuffer _readBuffer;
        private readonly WriteBuffer _writeBuffer;

        private int _packetLength = -1;

        private static readonly Encoding _encoding = Encoding.Unicode;

        public TdsParser(Stream stream)
        {
            this._readBuffer = new ReadBuffer(stream);
            this._writeBuffer = new WriteBuffer(stream);
        }

        public void Dispose()
        {
            this._readBuffer.Dispose();
            this._writeBuffer.Dispose();
        }

        public ValueTask SendPreLoginRequestAsync()
        {
            static void Write(TdsParser parser)
            {
                Span<byte> bytes = stackalloc byte[200];
                var length = GeneratePreLogin(bytes);
                parser.WritePacket(bytes.Slice(0, length), PacketTypes.PreLogin);
            }

            Write(this);
            return this._writeBuffer.FlushAsync();
        }

        private static int GeneratePreLogin(Span<byte> output)
        {
            short length = 0;
            short offset = 1;

            Span<byte> payload = stackalloc byte[100];
            short payloadLength = 0;


            output[length++] = 0; // PreLoginOption (Version)
            BinaryPrimitives.WriteInt16BigEndian(output.Slice(length), offset);
            length += 2;

            short optionLength = 0;
            payload[payloadLength++] = 1; // Major version
            payload[payloadLength++] = 0; // Minor version
            BinaryPrimitives.WriteInt16BigEndian(payload.Slice(payloadLength), 0); // Build
            payloadLength += 2;
            BinaryPrimitives.WriteInt16LittleEndian(payload.Slice(payloadLength), 0); // Sub build (little endian)
            payloadLength += 2;

            offset += 6;
            optionLength = 6;

            BinaryPrimitives.WriteInt16BigEndian(output.Slice(length), optionLength);
            length += 2;


            output[length++] = 1; // PreLoginOption (Encryption)
            BinaryPrimitives.WriteInt16BigEndian(output.Slice(length), offset);
            length += 2;

            payload[payloadLength++] = 0;

            offset++;
            optionLength = 1;


            BinaryPrimitives.WriteInt16BigEndian(output.Slice(length), optionLength);
            length += 2;


            output[length++] = 255; // Terminator

            payload.Slice(0, payloadLength).CopyTo(output.Slice(length));
            length += payloadLength;

            return length;
        }

        public ValueTask SendLogin7RequestAsync(string username, string password, string database)
        {
            static void Write(TdsParser parser, string username, string password, string database)
            {
                Span<byte> bytes = stackalloc byte[400];
                var length = GenerateLogin7(bytes, username, password, database);
                parser.WritePacket(bytes.Slice(0, length), PacketTypes.Login7);
            }

            Write(this, username, password, database);
            return this._writeBuffer.FlushAsync();
        }

        private static int GenerateLogin7(Span<byte> output, string username, string password, string database)
        {
            var length = 4;
            var lengthBytes = output.Slice(0, 4);

            BinaryPrimitives.WriteInt32LittleEndian(output.Slice(length), 1946157060); // TDS version
            length += 4;

            BinaryPrimitives.WriteInt32LittleEndian(output.Slice(length), 8000); // Packet size
            length += 4;

            BinaryPrimitives.WriteInt32LittleEndian(output.Slice(length), 100663296); // Version of the interface
            length += 4;

            BinaryPrimitives.WriteInt32LittleEndian(output.Slice(length), 0); // Client PID
            length += 4;

            BinaryPrimitives.WriteInt32LittleEndian(output.Slice(length), 0); // Connection ID
            length += 4;

            BinaryPrimitives.WriteInt32LittleEndian(output.Slice(length), 0); // Flags
            length += 4;

            BinaryPrimitives.WriteInt32LittleEndian(output.Slice(length), 0); // Client time zone
            length += 4;

            BinaryPrimitives.WriteInt32LittleEndian(output.Slice(length), 0); // Client LCID
            length += 4;

            var offset = 94;
            BinaryPrimitives.WriteInt16LittleEndian(output.Slice(length), (short)offset);
            length += 2;
            var clientMachineName = Environment.MachineName;
            BinaryPrimitives.WriteInt16LittleEndian(output.Slice(length), (short)clientMachineName.Length); // Client machine name
            length += 2;
            offset += clientMachineName.Length * 2;

            BinaryPrimitives.WriteInt16LittleEndian(output.Slice(length), (short)offset);
            length += 2;
            BinaryPrimitives.WriteInt16LittleEndian(output.Slice(length), (short)username.Length); // Username
            length += 2;
            offset += username.Length * 2;

            var encryptedPassword = EncryptPassword(password);
            BinaryPrimitives.WriteInt16LittleEndian(output.Slice(length), (short)offset);
            length += 2;
            BinaryPrimitives.WriteInt16LittleEndian(output.Slice(length), (short)(encryptedPassword.Length / 2)); // Password
            length += 2;
            offset += encryptedPassword.Length;

            var appName = "Scs";
            BinaryPrimitives.WriteInt16LittleEndian(output.Slice(length), (short)offset);
            length += 2;
            BinaryPrimitives.WriteInt16LittleEndian(output.Slice(length), (short)appName.Length); // Application name
            length += 2;
            offset += appName.Length * 2;

            var serverName = ".";
            BinaryPrimitives.WriteInt16LittleEndian(output.Slice(length), (short)offset);
            length += 2;
            BinaryPrimitives.WriteInt16LittleEndian(output.Slice(length), (short)serverName.Length); // Server name
            length += 2;
            offset += serverName.Length * 2;

            BinaryPrimitives.WriteInt16LittleEndian(output.Slice(length), (short)offset);
            length += 2;
            BinaryPrimitives.WriteInt16LittleEndian(output.Slice(length), 0); // Extensions
            length += 2;

            BinaryPrimitives.WriteInt16LittleEndian(output.Slice(length), (short)offset);
            length += 2;
            BinaryPrimitives.WriteInt16LittleEndian(output.Slice(length), (short)appName.Length); // Client interface name
            length += 2;
            offset += appName.Length * 2;

            BinaryPrimitives.WriteInt16LittleEndian(output.Slice(length), (short)offset);
            length += 2;
            BinaryPrimitives.WriteInt16LittleEndian(output.Slice(length), 0); // Language name
            length += 2;

            BinaryPrimitives.WriteInt16LittleEndian(output.Slice(length), (short)offset);
            length += 2;
            BinaryPrimitives.WriteInt16LittleEndian(output.Slice(length), (short)database.Length); // Database name
            length += 2;
            offset += database.Length * 2;

            var clientID = new byte[6];
            clientID.AsSpan().CopyTo(output.Slice(length)); // Client ID
            length += clientID.Length;

            BinaryPrimitives.WriteInt16LittleEndian(output.Slice(length), (short)offset);
            length += 2;
            BinaryPrimitives.WriteInt16LittleEndian(output.Slice(length), 0); // SSPI
            length += 2;

            BinaryPrimitives.WriteInt16LittleEndian(output.Slice(length), (short)offset);
            length += 2;
            BinaryPrimitives.WriteInt16LittleEndian(output.Slice(length), 0); // DB file name
            length += 2;

            BinaryPrimitives.WriteInt16LittleEndian(output.Slice(length), (short)offset);
            length += 2;
            BinaryPrimitives.WriteInt16LittleEndian(output.Slice(length), 0); // Reset password
            length += 2;

            BinaryPrimitives.WriteInt32LittleEndian(output.Slice(length), 0); // SSPI long
            length += 4;

            length += _encoding.GetBytes(clientMachineName, output.Slice(length)); // Client machine name

            length += _encoding.GetBytes(username, output.Slice(length)); // Username

            encryptedPassword.AsSpan().CopyTo(output.Slice(length)); // Password
            length += encryptedPassword.Length;

            length += _encoding.GetBytes(appName, output.Slice(length)); // Application name

            length += _encoding.GetBytes(serverName, output.Slice(length)); // Server name

            length += _encoding.GetBytes(appName, output.Slice(length)); // Client interface name

            length += _encoding.GetBytes(database, output.Slice(length)); // Database name

            BinaryPrimitives.WriteInt32LittleEndian(lengthBytes, length);
            return length;
        }

        private static byte[] EncryptPassword(string password)
        {
            var bytes = _encoding.GetBytes(password);
            for (var i = 0; i < bytes.Length; i++)
            {
                var firstFourBits = bytes[i] & 240;
                var secondFourBits = bytes[i] & 15;

                var swappedFirstFourBits = secondFourBits << 4;
                var swappedSecondFourBits = firstFourBits >> 4;
                bytes[i] = (byte)(swappedFirstFourBits + swappedSecondFourBits);

                bytes[i] ^= 0xA5;
            }
            return bytes;
        }

        public ValueTask ExecuteAsync(string sql)
        {
            static void Write(TdsParser parser, string sql)
            {
                Debug.Assert(parser._writeBuffer.Position == 0);
                parser._writeBuffer.Position = 8;

                const int marsLength = 18;
                const int headerLength = marsLength + 4;

                parser._writeBuffer.WriteInt32LittleEndian(headerLength);
                parser._writeBuffer.WriteInt32LittleEndian(marsLength);
                parser._writeBuffer.WriteInt16LittleEndian(2);
                parser._writeBuffer.WriteInt64LittleEndian(0);
                parser._writeBuffer.WriteInt32LittleEndian(1);

                parser._writeBuffer.WriteString(sql, _encoding);

                var length = parser._writeBuffer.Position;
                parser._writeBuffer.Position = 0;

                parser._writeBuffer.WriteByte(1); // Packet type
                parser._writeBuffer.WriteByte(1); // Packet status (ST_EOM)
                parser._writeBuffer.WriteInt16BigEndian(length); // Length
                parser._writeBuffer.WriteInt16BigEndian(0); // Channel
                parser._writeBuffer.WriteByte(1); // Packet number
                parser._writeBuffer.WriteByte(0); // Window

                parser._writeBuffer.Position = length;
            }

            Write(this, sql);
            return this._writeBuffer.FlushAsync();
        }

        private void WritePacket(ReadOnlySpan<byte> packet, byte packetType)
        {
            this._writeBuffer.WriteByte(packetType); // Packet type
            this._writeBuffer.WriteByte(1); // Packet status (ST_EOM)
            this._writeBuffer.WriteInt16BigEndian(packet.Length + 8); // Length
            this._writeBuffer.WriteInt16BigEndian(0); // Channel
            this._writeBuffer.WriteByte(1); // Packet number
            this._writeBuffer.WriteByte(0); // Window

            this._writeBuffer.WriteBytes(packet);
        }

        public ValueTask EnsureSinglePacketAsync(CancellationToken cancellationToken = default)
        {
            Debug.Assert(this._packetLength == -1);
            var packet = this._readBuffer.TryEnsureFast(4);
            if (packet.Length < 4)
            {
                return this.EnsureSinglePacketAsyncSlow(cancellationToken);
            }

            var length = BinaryPrimitives.ReadInt16BigEndian(packet.Span.Slice(2, 2));
            Debug.Assert(length < 8192);
            if (packet.Length >= length)
            {
                this._packetLength = length;
                return new ValueTask();
            }

            return this.EnsureSinglePacketAsyncSlow(cancellationToken);
        }

        private async ValueTask EnsureSinglePacketAsyncSlow(CancellationToken cancellationToken = default)
        {
            var packet = await this._readBuffer.EnsureAsync(4).ConfigureAwait(false);
            var length = BinaryPrimitives.ReadInt16BigEndian(packet.Span.Slice(2, 2));
            Debug.Assert(length < 8192);
            this._packetLength = length;
            if (packet.Length >= length)
            {
                return;
            }

            await this._readBuffer.EnsureAsync(length).ConfigureAwait(false);
            return;
        }

        public ReadOnlyMemory<byte> ReadPacket()
        {
            var length = this._packetLength;
            var packet = this._readBuffer.TryEnsureFast(length);
            Debug.Assert(packet.Length >= length);
            this._readBuffer.MovePosition(this._packetLength);
            this._packetLength = -1;
            return packet.Slice(0, length);
        }
    }
}
