using System.Formats.Tar;
using ColDogStudios.ColDogLocker.Core.Models;
using ColDogStudios.ColDogLocker.Services.FileSystem;
using ColDogStudios.ColDogLocker.Services.Lockers;

namespace ColDogStudios.ColDogLocker.Services.Tests.FileSystem
{
    public sealed class ExactLengthReadStreamTests
    {
        [Theory]
        [InlineData(0)]
        [InlineData(7)]
        [InlineData(81921)]
        public void TarWriterProducesExactlyTheExpectedContents(int length)
        {
            var contents = new byte[length];
            new Random(42).NextBytes(contents);
            using var source = new MemoryStream(contents);
            using var archive = new MemoryStream();
            using (var bounded = new ExactLengthReadStream(source, length))
            using (var writer = new TarWriter(archive, TarEntryFormat.Pax, leaveOpen: true))
            {
                writer.WriteEntry(new PaxTarEntry(TarEntryType.RegularFile, "payload") { DataStream = bounded });
                bounded.EnsureComplete();
            }

            Assert.True(source.CanRead);
            archive.Position = 0;
            using var reader = new TarReader(archive);
            var entry = reader.GetNextEntry()!;
            Assert.Equal(length, entry.Length);
            using var recovered = new MemoryStream();
            entry.DataStream?.CopyTo(recovered);
            Assert.Equal(contents, recovered.ToArray());
            Assert.Null(reader.GetNextEntry());
        }

        [Theory]
        [InlineData(2)]
        [InlineData(8)]
        public void ChangedLengthDuringReadIsRejectedWithoutDeliveringExtraBytes(int newLength)
        {
            using var source = new MutatingStream(newLength);
            using var bounded = new ExactLengthReadStream(source, 4);
            using var copied = new MemoryStream();

            Assert.Throws<IOException>(() => bounded.CopyTo(copied));
            Assert.InRange(source.LargestReadRequest, 1, 4);
            Assert.Equal(0, copied.Length);
        }

        [Fact]
        public void EarlyEndOfStreamIsNotAcceptedAsComplete()
        {
            using var source = new PrematureEndStream();
            using var bounded = new ExactLengthReadStream(source, 4);
            Assert.Throws<EndOfStreamException>(() => bounded.CopyTo(Stream.Null));
        }

        [Fact]
        public void PartialConsumptionCannotBeReportedComplete()
        {
            using var source = new MemoryStream(new byte[4]);
            using var bounded = new ExactLengthReadStream(source, 4);
            Assert.Equal(0, bounded.ReadByte());
            Assert.Throws<IOException>(bounded.EnsureComplete);
        }

        [Fact]
        public void GrowthAfterLastByteIsDetectedAtCompletion()
        {
            using var source = new MemoryStream();
            source.SetLength(4);
            using var bounded = new ExactLengthReadStream(source, 4);
            bounded.CopyTo(Stream.Null);
            source.SetLength(5);
            Assert.Throws<IOException>(bounded.EnsureComplete);
        }

        [Theory]
        [InlineData(2)]
        [InlineData(8)]
        public void ArchiveFailureRemovesOutputAndPreservesOriginal(int newLength)
        {
            var root = Directory.CreateDirectory(Path.Join(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), $"cdl-read-limit-{Guid.NewGuid():N}")).FullName;
            try
            {
                var source = Directory.CreateDirectory(Path.Join(root, "Vault")).FullName;
                var original = Path.Join(source, "payload");
                File.WriteAllBytes(original, [1, 2, 3, 4]);
                var archive = Path.Join(root, "locker.cdl");
                var locker = new LockerModel("Vault", "unused", source);

                Assert.Throws<IOException>(() => LockerArchiveService.CreateFromDirectory(
                    source, archive, locker, "River!Cobalt8Fern", 4, _ => new MutatingStream(newLength)));

                Assert.False(File.Exists(archive));
                Assert.Equal(new byte[] { 1, 2, 3, 4 }, File.ReadAllBytes(original));
            }
            finally
            {
                Directory.Delete(root, true);
            }
        }

        private sealed class PrematureEndStream : MemoryStream
        {
            internal PrematureEndStream() : base(new byte[4]) { }
            public override int Read(Span<byte> buffer) => 0;
        }

        private sealed class MutatingStream : MemoryStream
        {
            private readonly int _newLength;
            public int LargestReadRequest { get; private set; }

            internal MutatingStream(int newLength)
            {
                _newLength = newLength;
                Write([1, 2, 3, 4]);
                Position = 0;
            }

            public override int Read(Span<byte> buffer)
            {
                LargestReadRequest = Math.Max(LargestReadRequest, buffer.Length);
                SetLength(_newLength);
                return base.Read(buffer);
            }
        }
    }
}
