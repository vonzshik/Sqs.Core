using System;
using System.Buffers;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Scs.Core.Raw
{
    public sealed class TdsSslStream : Stream
    {
        private readonly Stream _stream;
        private readonly bool _leaveInnerStreamOpen;

        private bool _completed;

        private int _packetBytes;

        public void Complete() => _completed = true;

        public TdsSslStream(Stream stream, bool leaveInnerStreamOpen)
        {
            this._stream = stream;
            this._leaveInnerStreamOpen = leaveInnerStreamOpen;
        }

        public override bool CanRead => _stream.CanRead;

        public override bool CanSeek => _stream.CanSeek;

        public override bool CanWrite => _stream.CanWrite;

        public override long Length => _stream.Length;

        public override long Position 
        { 
            get => _stream.Position; 
            set => _stream.Position = value; 
        }

        public override void Flush() => _stream.Flush();

        public override Task FlushAsync(CancellationToken cancellationToken) => _stream.FlushAsync(cancellationToken);

        public override int Read(byte[] buffer, int offset, int count) => this._stream.Read(buffer, offset, count);

        public override long Seek(long offset, SeekOrigin origin) => this._stream.Seek(offset, origin);

        public override void SetLength(long value) => this._stream.SetLength(value);

        public override void Write(byte[] buffer, int offset, int count) => this._stream.Write(buffer, offset, count);

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => this._stream.ReadAsync(buffer, offset, count, cancellationToken);

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (!this._completed)
            {
                if (this._packetBytes > 0)
                {
                    int wantedCount = Math.Min(buffer.Length, _packetBytes);
                    int readCount = await _stream.ReadAsync(buffer.Slice(0, wantedCount), cancellationToken).ConfigureAwait(false);
                    if (readCount == 0)
                    {
                        throw new EndOfStreamException();
                    }
                    _packetBytes -= readCount;
                    return readCount;
                }

                var headerBytes = new byte[8];

                var headerBytesRead = 0;
                do
                {
                    int headerBytesReadIteration = await _stream.ReadAsync(headerBytes.AsMemory().Slice(headerBytesRead, 8 - headerBytesRead), cancellationToken).ConfigureAwait(false);
                    if (headerBytesReadIteration == 0)
                    {
                        throw new EndOfStreamException();
                    }
                    headerBytesRead += headerBytesReadIteration;
                } while (headerBytesRead < 8);

                // read the packet data size from the header and store it in case it is needed for a subsequent call
                _packetBytes = ((headerBytes[2] << 8) | headerBytes[3]) - 8;

                // read as much from the packet as the caller can accept
                var packetBytesRead = await _stream.ReadAsync(buffer.Slice(0, Math.Min(buffer.Length, _packetBytes)), cancellationToken).ConfigureAwait(false);
                _packetBytes -= packetBytesRead;
                return packetBytesRead;
            }

            return await this._stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
        }

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => this._stream.WriteAsync(buffer, offset, count, cancellationToken);

        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (!this._completed)
            {
                var handshakeBuffer = ArrayPool<byte>.Shared.Rent(buffer.Length + 8);
                buffer.CopyTo(handshakeBuffer.AsMemory(8));

                handshakeBuffer[0] = PacketTypes.PreLogin;
                handshakeBuffer[1] = 1;
                handshakeBuffer[2] = 0;
                handshakeBuffer[3] = (byte)(buffer.Length + 8);
                handshakeBuffer[4] = 0;
                handshakeBuffer[5] = 0;
                handshakeBuffer[6] = 0;
                handshakeBuffer[7] = 0;

                await this._stream.WriteAsync(handshakeBuffer.AsMemory().Slice(0, buffer.Length + 8), cancellationToken).ConfigureAwait(false);
                ArrayPool<byte>.Shared.Return(handshakeBuffer, true);
                return;
            }

            await this._stream.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing && !_leaveInnerStreamOpen)
            {
                this._stream.Dispose();
            }
        }
    }
}
