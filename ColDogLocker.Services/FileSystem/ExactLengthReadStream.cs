using System.Security.Cryptography;

namespace ColDogStudios.ColDogLocker.Services.FileSystem
{
    /// <summary>Exposes only the inspected source length and rejects observed length changes. Leaves the source open.</summary>
    internal sealed class ExactLengthReadStream : Stream
    {
        private readonly Stream _source;
        private readonly long _length;
        private readonly IncrementalHash? _digest;
        private readonly CancellationToken _cancellationToken;

        internal ExactLengthReadStream(Stream source, long length, IncrementalHash? digest = null,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(source);
            ArgumentOutOfRangeException.ThrowIfNegative(length);
            if (!source.CanRead || !source.CanSeek || source.Position != 0)
            {
                throw new ArgumentException("An archive source must be readable, seekable and positioned at its beginning.", nameof(source));
            }

            _source = source;
            _length = length;
            _digest = digest;
            _cancellationToken = cancellationToken;
            CheckLength();
        }

        public override bool CanRead => true;
        public override bool CanSeek => true;
        public override bool CanWrite => false;
        public override long Length => _length;
        public override long Position
        {
            get => _source.Position;
            set => Seek(value, SeekOrigin.Begin);
        }

        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

        public override int Read(Span<byte> buffer)
        {
            _cancellationToken.ThrowIfCancellationRequested();
            CheckLength();
            var remaining = _length - Position;
            if (remaining < 0)
            {
                throw new IOException("Archive source position exceeded its inspected length.");
            }

            if (buffer.IsEmpty || remaining == 0)
            {
                return 0;
            }

            var read = _source.Read(buffer[..(int)Math.Min(buffer.Length, remaining)]);
            _cancellationToken.ThrowIfCancellationRequested();
            CheckLength();
            if (read == 0)
            {
                throw new EndOfStreamException("Archive source ended before its inspected length.");
            }

            _digest?.AppendData(buffer[..read]);

            return read;
        }

        internal void EnsureComplete()
        {
            CheckLength();
            if (Position != _length)
            {
                throw new IOException("Archive source was not completely consumed.");
            }
        }

        private void CheckLength()
        {
            if (_source.Length != _length)
            {
                throw new IOException("Locker file length changed while it was being archived. Original files have not been removed.");
            }
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            var target = origin switch
            {
                SeekOrigin.Begin => offset,
                SeekOrigin.Current => checked(Position + offset),
                SeekOrigin.End => checked(_length + offset),
                _ => throw new ArgumentOutOfRangeException(nameof(origin))
            };
            if (target < 0 || target > _length)
            {
                throw new IOException("Cannot seek outside the inspected source length.");
            }

            if (_digest != null && target != Position)
            {
                throw new IOException("Cannot seek while computing an archive source manifest.");
            }

            CheckLength();
            return _source.Seek(target, SeekOrigin.Begin);
        }

        public override void Flush() { }
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
