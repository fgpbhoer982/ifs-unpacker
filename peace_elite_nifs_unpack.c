#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>


const char *base_name(const char *path) {
	const char *last_slash = strrchr(path, '/');
	return last_slash != NULL ? last_slash + 1 : path;
}

typedef struct {
	uint32_t Magic;
	uint32_t HeaderSize;
	uint16_t Version;
	uint16_t SectorSize;

	uint64_t ArchiveSize;
	uint64_t BetTablePos;
	uint64_t HetTablePos;
	uint64_t MD5TablePos;
	uint64_t BitmapPos;

	uint64_t HetTableSize;
	uint64_t BetTableSize;
	uint64_t MD5TableSize;
	uint64_t BitmapSize;

	uint32_t MD5PieceSize;
	uint32_t RawChunkSize;
} __attribute__((packed)) IFSHeader;

typedef struct {
	uint32_t Magic;
	uint32_t Version;
	uint32_t DataSize;
} __attribute__((packed)) IFSHetHeader;

typedef struct {
	uint32_t Magic;
	uint32_t Version;
	uint32_t DataSize;
} __attribute__((packed)) IFSBetHeader;

typedef struct {
	uint32_t TableSize;
	uint32_t EntryCount;
	uint32_t HashTableSize;
	uint32_t HashEntrySize;
	uint32_t IndexSizeTotal;
	uint32_t IndexSizeExtra;
	uint32_t IndexSize;
	uint32_t BlockTableSize;
} __attribute__((packed)) IFSHetTable;

typedef struct {
	uint32_t TableSize;
	uint32_t EntryCount;
	uint32_t TableEntrySize;

	uint32_t BitIndexFilePos;
	uint32_t BitIndexFileSize;
	uint32_t BitIndexCmpSize;
	uint32_t BitIndexFlagPos;
	uint32_t BitIndexHashPos;

	uint32_t UnknownRepeatPos;

	uint32_t BitCountFilePos;
	uint32_t BitCountFileSize;
	uint32_t BitCountCmpSize;
	uint32_t BitCountFlagSize;
	uint32_t BitCountHashSize;

	uint32_t UnknownZero;

	uint32_t HashSizeTotal;
	uint32_t HashSizeExtra;
	uint32_t HashSize;

	uint32_t HashPart1;
	uint32_t HashPart2;

	uint32_t HashArraySize;
} __attribute__((packed)) IFSBetTable;

typedef struct {
	uint32_t FilePackageIndex;
	uint64_t FilePosition;
	uint64_t FileSize;
	uint64_t CompressedSize;
	uint64_t Flags;
} __attribute__((packed)) IFSFileEntry;


// The IFSEncrypt table, used internally
uint32_t IFSEncryptionTable[0x500];

// Build the encryption table
void BuildIFSEncryptionTable()
{
	// Seed and constant
	int32_t q, r = 0x100001;
	uint32_t seed = 0;

	// Generate 5 256 byte long tables
	for (int i = 0; i < 0x100; i++)
	{
		for (int j = 0; j < 5; j++)
		{
			// Pass 1
			div_t qt = div(r * 125 + 3, 0x2AAAAB);
			q = qt.quot;
			r = qt.rem;
			seed = (uint32_t)(r & 0xFFFF) << 16;

			// Pass 2
			qt = div(r * 125 + 3, 0x2AAAAB);
			q = qt.quot;
			r = qt.rem;
			seed |= (uint32_t)(r & 0xFFFF);

			// Assign it
			IFSEncryptionTable[0x100 * j + i] = seed;
		}
	}
}


// Hash a string input with the given hash table
const uint32_t HashString(const char* Value, uint32_t HashOffset)
{
	// Seed and constant
	uint32_t hash = 0x7FED7FED, seed = 0xEEEEEEEE;
	
	// Buffers
	int8_t c;
	uint8_t b;

	for (size_t i = 0; i < strlen(Value); i++)
	{
		// Strip invalid chars
		c = Value[i];
		if (c >= 127)
			c = '?';
		b = (uint8_t)c;

		// Char to upper
		if (b > 0x60 && b < 0x7B)
			b -= 0x20;

		// Hash the round and shift the seed
		hash = IFSEncryptionTable[HashOffset + b] ^ (hash + seed);
		seed += hash + (seed << 5) + b + 3;
	}

	// Return result
	return hash;
}


// Decrypts an IFS data block
void DecryptIFSBlock(uint32_t* Data, uint32_t Length, uint32_t Hash)
{
	// Buffer and constant
	uint32_t Buffer, Temp = 0xEEEEEEEE;

	// Iterate backwards
	for (uint32_t i = Length; i-- != 0;)
	{
		// Read from the data stream into temp
		Temp += IFSEncryptionTable[0x400 + (Hash & 0xFF)];
		Buffer = *Data ^ (Temp + Hash);

		// Shift the seed
		Temp += Buffer + (Temp << 5) + 3;

		// Assign decrypted value
		*Data++ = Buffer;

		// Shift the hash
		Hash = (Hash >> 11) | (0x11111111 + ((Hash ^ 0x7FF) << 21));
	}
}

// Calculates the rounded buffer size
const uint32_t IntegralBufferSize(uint32_t Buffer)
{
	// Calculate
	if ((Buffer % 4) == 0)
		return Buffer / 4;

	// Add one for safety
	return (Buffer / 4) + 1;
}


// Reads a bit-len integer from the stream
const int64_t ReadBitLenInteger(const uint8_t* Buffer, uint32_t BitIndex, uint32_t NumBits)
{
	int64_t Data = 0, Wei = 1;

	for (uint32_t j = 0; j < NumBits; j++)
	{
		if ((((Buffer[BitIndex / 8]) >> (BitIndex % 8)) & 1) != 0) Data += Wei;
		BitIndex++; Wei *= 2;
	}

	return Data;
}

// Reads a bit-len integer from the stream
const uint64_t ReadBitLenUInteger(const uint8_t* Buffer, uint32_t BitIndex, uint32_t NumBits)
{
	uint64_t Data = 0, Wei = 1;

	for (uint32_t j = 0; j < NumBits; j++)
	{
		if ((((Buffer[BitIndex / 8]) >> (BitIndex % 8)) & 1) != 0) Data += Wei;
		BitIndex++; Wei *= 2;
	}

	return Data;
}

#include <zlib.h>

unsigned int ZLIB_decompress(unsigned char *InData, unsigned int InSize, unsigned char *OutData, unsigned int OutSize) {
	z_stream strm;
	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	strm.opaque = Z_NULL;
	strm.next_in = InData;
	strm.avail_in = InSize;
	strm.next_out = OutData;
	strm.avail_out = OutSize;
	
	
	if (inflateInit(&strm) != Z_OK) {
		// fprintf(stderr, "Failed to initialize zlib.\n");
		return 0;
	}
	
	if (inflate(&strm, Z_FINISH) != Z_STREAM_END) {
		// fprintf(stderr, "inflate failed: %s\n", strm.msg);
		inflateEnd(&strm);
		return 0;
	}
	
	if (inflateEnd(&strm) != Z_OK) {
		// fprintf(stderr, "inflateEnd failed: %s\n", strm.msg);
		return 0;
	}
	
	return strm.total_out;
}

int main(int argc, const char *argv[]) {
	if (argc != 2) {
		fprintf(stderr, "Usage: ./%s <file>\n", base_name(argv[0]));
		return 1;
	}
	
	BuildIFSEncryptionTable();
	
	printf("This tool extract tencent games .ifs (nifs) archive!\n");
	printf("Developed by halloweeks\n");
	printf("Contact: https://t.me/halloweeks\n");
	printf("If you have an problem please open issue on github: \nhttps://github.com/halloweeks/pubg-mobile-unpacker/issues/\n\n");
	
	clock_t start_time = clock();
	
	IFSHeader Header;
	IFSHetHeader HetHeader;
	IFSBetHeader BetHeader;
	
	IFSHetTable HetTable;
	IFSBetTable BetTable;
	
	IFSFileEntry *Entry;
	
	struct stat st;
	
	if (stat(argv[1], &st) != 0) {
		fprintf(stderr, "'%s' does not exist.\n", argv[1]);
		return EXIT_FAILURE;
	}
	
	if (!S_ISREG(st.st_mode)) {
		fprintf(stderr, "'%s' not an regular file!\n", argv[1]);
		return EXIT_FAILURE;
	}
	
	int file = open(argv[1], O_RDONLY);
	
	if (file == -1) {
		perror("Error opening file");
		return 1;
	}
	
	if (read(file, &Header, sizeof(Header)) != sizeof(Header)) {
		fprintf(stderr, "Can't read header!\n");
		close(file);
		return 1;
	}
	
	
	if (Header.Magic != 0x7366696e) {
		fprintf(stderr, "This file is not (nifs) archive!\n");
		close(file);
		return 1;
	}
	
	// IFSHeader
	printf("magic: 0x%08X\n", Header.Magic);
	printf("HeaderSize: %u\n", Header.HeaderSize);
	printf("Version: %u\n", Header.Version);
	
	printf("SectorSize: %u\n", Header.SectorSize);
	printf("ArchiveSize: %lu\n", Header.ArchiveSize);
	
	printf("BetTablePos: 0x%lx\n", Header.BetTablePos);
	printf("HetTablePos: 0x%lx\n", Header.HetTablePos);
	printf("MD5TablePos: 0x%lx\n", Header.MD5TablePos);
	printf("BitmapPos: 0x%lx\n", Header.BitmapPos);
	
	
	printf("HetTableSize: %lu\n", Header.HetTableSize);
	printf("BetTableSize: %lu\n", Header.BetTableSize);
	printf("MD5TableSize: %lu\n", Header.MD5TableSize);
	printf("BitmapSize: %lu\n", Header.BitmapSize);
	
	printf("MD5PieceSize: %u\n", Header.MD5PieceSize);
	printf("RawChunkSize: %u\n", Header.RawChunkSize);
	
	printf("\n");
	
	
	if (lseek(file, Header.HetTablePos, SEEK_SET) == -1) {
		fprintf(stderr, "Can't seek!\n");
		close(file);
		return 1;
	}
	
	
	
	
	if (read(file, &HetHeader, sizeof(HetHeader)) != sizeof(HetHeader)) {
		fprintf(stderr, "Can't read header!\n");
		close(file);
		return 1;
	}
	
	// IFSHetHeader
	printf("IFSHetHeader\n");
	printf("Magic: 0x%08X\n", HetHeader.Magic);
	printf("Version: %u\n", HetHeader.Version);
	printf("DataSize: %u\n", HetHeader.DataSize);
	
	printf("\n");
	
	
	uint32_t HetKey = HashString("(hash table)", 0x300);
	uint32_t BetKey = HashString("(block table)", 0x300);
	
	
	
	uint8_t *HetBuffer = (uint8_t*)malloc(HetHeader.DataSize);
	
	if (HetBuffer == NULL) {
		fprintf(stderr, "Can't allocate memory\n");
		close(file);
		return 1;
	}
	
	if (read(file, HetBuffer, HetHeader.DataSize) != HetHeader.DataSize) {
		fprintf(stderr, "Can't read HetBuffer\n");
		free(HetBuffer);
		close(file);
		return 1;
	}
	
	DecryptIFSBlock((uint32_t*)HetBuffer, IntegralBufferSize(HetHeader.DataSize), HetKey);
	
	
	memcpy(&HetTable, HetBuffer, sizeof(HetTable));
	
	printf("TableSize: %u\n", HetTable.TableSize);
	printf("EntryCount: %u\n", HetTable.EntryCount);
	printf("HashTableSize: %u\n", HetTable.HashTableSize);
	printf("HashEntrySize: %u\n", HetTable.HashEntrySize);
	printf("IndexSizeTotal: %u\n", HetTable.IndexSizeTotal);
	printf("IndexSizeExtra: %u\n", HetTable.IndexSizeExtra);
	printf("IndexSize: %u\n", HetTable.IndexSize);
	printf("BlockTableSize: %u\n", HetTable.BlockTableSize);
	
	
	
	
	
	
	if (lseek(file, Header.BetTablePos, SEEK_SET) == -1) {
		fprintf(stderr, "Can't seek!\n");
		close(file);
		return 1;
	}
	
	if (read(file, &BetHeader, sizeof(BetHeader)) != sizeof(BetHeader)) {
		fprintf(stderr, "Can't read header!\n");
		close(file);
		return 1;
	}
	
	// BetHeader
	printf("\nIFSBetHeader\n");
	printf("Magic: 0x%08X\n", BetHeader.Magic);
	printf("Version: %u\n", BetHeader.Version);
	printf("DataSize: %u\n", BetHeader.DataSize);
	
	printf("\n");
	
	
	
	uint8_t *BetBuffer = (uint8_t*)malloc(BetHeader.DataSize);
	
	if (BetBuffer == NULL) {
		fprintf(stderr, "Can't allocate memory\n");
		close(file);
		return 1;
	}
	
	if (read(file, BetBuffer, BetHeader.DataSize) != BetHeader.DataSize) {
		fprintf(stderr, "Can't read HetBuffer\n");
		free(BetBuffer);
		close(file);
		return 1;
	}
	
	
	DecryptIFSBlock((uint32_t*)BetBuffer, IntegralBufferSize(BetHeader.DataSize), BetKey);
	
	
	memcpy(&BetTable, BetBuffer, sizeof(BetTable));
	
	printf("\nBet Table\n");
	
	printf("TableSize: %u\n", BetTable.TableSize);
	printf("EntryCount: %u\n", BetTable.EntryCount);
	printf("TableEntrySize: %u\n", BetTable.TableEntrySize);
	
	printf("BitIndexFilePos: %u\n", BetTable.BitIndexFilePos);
	printf("BitIndexFileSize: %u\n", BetTable.BitIndexFileSize);
	printf("BitIndexCmpSize: %u\n", BetTable.BitIndexCmpSize);
	printf("BitIndexFlagPos: %u\n", BetTable.BitIndexFlagPos);
	printf("BitIndexHashPos: %u\n", BetTable.BitIndexHashPos);
	
	
	printf("UnknownRepeatPos: %u\n", BetTable.UnknownRepeatPos);
	
	
	printf("BitCountFilePos: %u\n", BetTable.BitCountFilePos);
	printf("BitCountFileSize: %u\n", BetTable.BitCountFileSize);
	printf("BitCountCmpSize: %u\n", BetTable.BitCountCmpSize);
	printf("BitCountFlagSize: %u\n", BetTable.BitCountFlagSize);
	printf("BitCountHashSize: %u\n", BetTable.BitCountHashSize);
	
	
	printf("UnknownZero: %u\n", BetTable.UnknownZero);
	
	
	printf("HashSizeTotal: %u\n", BetTable.HashSizeTotal);
	printf("HashSizeExtra: %u\n", BetTable.HashSizeExtra);
	printf("HashSize: %u\n", BetTable.HashSize);
	
	
	printf("HashPart1: %u\n", BetTable.HashPart1);
	printf("HashPart2: %u\n", BetTable.HashPart2);
	
	printf("HashArraySize: %u\n", BetTable.HashArraySize);
	
	
	
	// free(BetBuffer);
	
	
	// Allocate memory for table entries, and hash table
	/*
	uint8_t *TableEntries = malloc((BetTable.TableEntrySize * BetTable.EntryCount + 7) / 8);
	uint8_t *TableHashes = malloc((BetTable.HashSizeTotal*BetTable.EntryCount + 7) / 8);
		
	uint64_t TableEntriesSize = (BetTable.TableEntrySize * BetTable.EntryCount + 7) / 8;
	uint64_t TableHashesSize = (BetTable.HashSizeTotal * BetTable.EntryCount + 7) / 8;
	*/
	
	uint8_t *TableEntries = malloc(BetTable.TableEntrySize * BetTable.EntryCount);
	uint8_t *TableHashes = malloc(BetTable.HashSizeTotal * BetTable.EntryCount);
		
	uint64_t TableEntriesSize = (BetTable.TableEntrySize * BetTable.EntryCount);
	uint64_t TableHashesSize = (BetTable.HashSizeTotal * BetTable.EntryCount);
	
	
	memcpy(TableEntries, BetBuffer + sizeof(BetTable), TableEntriesSize);
	memcpy(TableHashes, BetBuffer + sizeof(BetTable) + TableEntriesSize, TableHashesSize);
	
	
	free(HetBuffer);
	free(BetBuffer);
	
	// Offsets
	uint32_t BitOffset = 0, HashOffset = 0;
	
	
	uint32_t FilePackageIndex;
	uint64_t FilePosition;
	uint64_t FileSize;
	uint64_t CompressedSize;
	uint64_t Flags;
	
	uint64_t ListFileHash;
	
	printf("\n\n");
	
	uint8_t buffer[65536];
	uint8_t decom[65536];
	
	char filename[1024];
	
	mkdir("nifs", 0775);
	
	uint32_t arr[65536] = {0}; // maximum 1024 
	uint32_t offset = 0;
	uint32_t chunk = 0;
	uint8_t flag = 0;
	
	uint32_t chunk_size[65536];
	
	printf("files: %u\n", BetTable.EntryCount);
	
	// Prepare to parse and read each entry
	for (uint32_t i = 0; i < BetTable.EntryCount - 1; i++) {
		FilePosition = ReadBitLenInteger(TableEntries, BitOffset, BetTable.BitCountFilePos); BitOffset += BetTable.BitCountFilePos;
		
		FileSize = ReadBitLenInteger(TableEntries, BitOffset, BetTable.BitCountFileSize); BitOffset += BetTable.BitCountFileSize;
		CompressedSize = ReadBitLenInteger(TableEntries, BitOffset, BetTable.BitCountCmpSize); BitOffset += BetTable.BitCountCmpSize;
		Flags = ReadBitLenInteger(TableEntries, BitOffset, BetTable.BitCountFlagSize); BitOffset += BetTable.BitCountFlagSize;

		// Skip over unknown data
		BitOffset += BetTable.BitCountHashSize;
		BitOffset += BetTable.HashArraySize;

		// Grab the hash and use as the key
		uint64_t NameHash = ReadBitLenUInteger(TableHashes, HashOffset, BetTable.HashSizeTotal); HashOffset += BetTable.HashSizeTotal;
		
		// Check for list file, starts at header size
		if (FilePosition == Header.HeaderSize && Flags == 0x80000000) {
			ListFileHash = NameHash;
		}
		
		if (FileSize == 0 && CompressedSize == 0) {
			continue;
		}
		
		printf("FileName: %u.dat\n", i);
		printf("FilePosition: %lu\n", FilePosition);
		printf("FileSize: %lu\n", FileSize);
		printf("CompressedSize: %lu\n", CompressedSize);
		// printf("\n");
		
		if (lseek(file, FilePosition, SEEK_SET) == -1) {
			fprintf(stderr, "Can't seek!\n");
		}
		
		read(file, &offset, 4);
		
		chunk = (offset / 4) - 1;
		
		for (uint32_t index = 0; index < chunk; index++) {
			read(file, &arr[index], 4);
			arr[index] -= (offset + 1);
		}
		
		chunk_size[0] = arr[0];
		
		for (uint32_t c = 1; c < chunk; c++) {
			chunk_size[c] = (arr[c] - arr[c-1]) - 1;
		}
		
		snprintf(filename, 1024, "nifs/%u.dat", i);
		int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		
		uint8_t type = 0;
		
		if (lseek(file, FilePosition + offset, SEEK_SET) == -1) {
			fprintf(stderr, "Can't seek!\n");
			goto done;
		}
		
		int len = 0;
		uint32_t total = 0;
		
		off_t off = 0;
		
		for (uint32_t x = 0; x < chunk; x++) {
			read(file, &type, 1);
			read(file, buffer, chunk_size[x]);
			
			len = ZLIB_decompress(buffer, chunk_size[x], decom, 65536);
			
			if (len == 0) {
				write(fd, &type, 1);
				write(fd, buffer, chunk_size[x]);
				total += chunk_size[x] + 1;
				// printf("Uncompressed chunk\n");
			} else {
				// printf("Decompressed %d bytes\n", len);
				total += len;
				write(fd, decom, len);
			}
			
			// printf("\n\n");
		}
		
		close(fd);
		printf("Extract size: %u\n", total);
		
		printf("\n\n");
	}
	
	done:
	
	free(TableEntries);
	free(TableHashes);
	
	close(file);
	
	clock_t end_time = clock();
	double time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
	const double MB = 1024.0 * 1024.0;
	printf("Processed %.2f MB, speed = %.2f MB/s, complete in %f seconds\n", st.st_size / MB, st.st_size / MB / time, time);
	return EXIT_SUCCESS;
}
