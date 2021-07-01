using System;
using System.Buffers;
using System.Buffers.Binary;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace Scs.Core.Raw
{
    public sealed class WriteBuffer : IDisposable
    {
        private readonly Stream _stream;

        private readonly Memory<byte> _buffer;
        private readonly IMemoryOwner<byte> _bufferOwner;

        private int _position;

        public WriteBuffer(Stream stream)
        {
            this._stream = stream;
            this._bufferOwner = MemoryPool<byte>.Shared.Rent(8192);
            this._buffer = this._bufferOwner.Memory;
        }

        public Memory<byte> Buffer => this._buffer.Slice(this._position);

        public int Position
        {
            get => this._position;
            set => this._position = value;
        }

        public async ValueTask FlushAsync()
        {
            if (this._position == 0)
                return;

            await this._stream.WriteAsync(this._buffer.Slice(0, this._position)).ConfigureAwait(false);
            await this._stream.FlushAsync().ConfigureAwait(false);
            this._position = 0;
        }

        public void WriteBytes(ReadOnlySpan<byte> bytes)
        {
            bytes.CopyTo(this._buffer.Slice(this._position).Span);
            this._position += bytes.Length;
        }

        public void WriteInt32BigEndian(int value)
        {
            BinaryPrimitives.WriteInt32BigEndian(this._buffer.Slice(this._position).Span, value);
            this._position += 4;
        }

        public void WriteInt32LittleEndian(int value)
        {
            BinaryPrimitives.WriteInt32LittleEndian(this._buffer.Slice(this._position).Span, value);
            this._position += 4;
        }

        public void WriteInt16BigEndian(short value)
        {
            BinaryPrimitives.WriteInt16BigEndian(this._buffer.Slice(this._position).Span, value);
            this._position += 2;
        }

        public void WriteInt16BigEndian(int value) => WriteInt16BigEndian((short)value);

        public void WriteInt16LittleEndian(short value)
        {
            BinaryPrimitives.WriteInt16LittleEndian(this._buffer.Slice(this._position).Span, value);
            this._position += 2;
        }

        public void WriteInt16LittleEndian(int value) => WriteInt16LittleEndian((short)value);

        public void WriteInt64LittleEndian(long value)
        {
            BinaryPrimitives.WriteInt64LittleEndian(this._buffer.Slice(this._position).Span, value);
            this._position += 8;
        }

        public void WriteByte(byte value)
        {
            this._buffer.Span[this._position] = value;
            this._position++;
        }

        public int WriteString(string str, Encoding encoding)
        {
            var length = encoding.GetBytes(str, this._buffer.Slice(this._position).Span);
            this._position += length;
            return length;
        }

        public void Dispose()
        {
            this._bufferOwner.Dispose();
        }
    }
}
