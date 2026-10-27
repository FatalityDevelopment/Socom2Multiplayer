using System;
using System.IO;

namespace DNAS;

/// <summary>
/// Reads raw 2048-byte ISO user sectors. No title names, file paths, LBAs,
/// or ISO9660 assumptions are built into the sector reader.
/// </summary>
public static class DiscImage
{
    public const int SectorBytes = 2048;
    public const int ImageBytes = ClientImage.ImageLength;
    public const int ImageSectors = ImageBytes / SectorBytes;

    /// <summary>
    /// Reads an entire DNAS image by its known starting LBA. The no-count
    /// overload reads 32 contiguous sectors (64 KiB), as observed in the
    /// captured client. This is raw ISO user-data access, not file I/O.
    /// </summary>
    public static byte[] ReadISOSector(Stream iso, long lba) => ReadSectors(iso, lba, ImageSectors);

    /// <summary>Reads a caller-selected number of contiguous ISO user sectors.</summary>
    public static byte[] ReadISOSector(Stream iso, long lba, int sectorCount) => ReadSectors(iso, lba, sectorCount);

    /// <summary>Reads exactly one 2048-byte ISO user sector.</summary>
    public static byte[] ReadSector(Stream iso, long lba) => ReadSectors(iso, lba, 1);

    /// <summary>Reads exactly the requested contiguous sector range, or throws.</summary>
    public static byte[] ReadSectors(Stream iso, long lba, int sectorCount)
    {
        if (iso == null) throw new ArgumentNullException(nameof(iso));
        if (!iso.CanRead || !iso.CanSeek) throw new ArgumentException("The ISO stream must support reading and seeking.", nameof(iso));
        if (lba < 0 || lba > long.MaxValue / SectorBytes) throw new ArgumentOutOfRangeException(nameof(lba));
        if (sectorCount <= 0 || sectorCount > int.MaxValue / SectorBytes) throw new ArgumentOutOfRangeException(nameof(sectorCount));
        long offset = checked(lba * SectorBytes);
        int length = checked(sectorCount * SectorBytes);
        if (offset > iso.Length || iso.Length - offset < length) throw new EndOfStreamException("ISO does not contain the requested sector range.");
        iso.Position = offset;
        byte[] data = new byte[length];
        iso.ReadExactly(data);
        return data;
    }

    /// <summary>Reads a 64 KiB image from a byte-aligned location, without an LBA lookup.</summary>
    public static byte[] ReadAtIsoByteOffset(Stream iso, long byteOffset)
    {
        if (byteOffset < 0 || byteOffset % SectorBytes != 0) throw new ArgumentOutOfRangeException(nameof(byteOffset), "A user-data ISO image requires a 2048-byte-aligned offset.");
        return ReadISOSector(iso, byteOffset / SectorBytes);
    }

    /// <summary>Reads a 64 KiB image from an explicitly provided starting LBA.</summary>
    public static byte[] ReadAtIsoLba(Stream iso, long lba) => ReadISOSector(iso, lba);
}
