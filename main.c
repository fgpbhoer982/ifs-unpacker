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




int main(int argc, const char *argv[]) {
	if (argc != 2) {
		fprintf(stderr, "Usage: ./%s <file>\n", base_name(argv[0]));
		return 1;
	}
	BuildIFSEncryptionTable();
	
	
	unsigned char key[24] = { 0x15, 0x9a, 0x03, 0x25, 0xe0, 0x75, 0x2e, 0x80,
                              0xc6, 0xc0, 0x94, 0x2a, 0x50, 0x5c, 0x1c, 0x68,
                              0x8c, 0x17, 0xef, 0x53, 0x99, 0xf8, 0x68, 0x3c };

    unsigned char iv[16] = { 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
                             0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10 };
	
	printf("Developed by halloweeks\n");
	printf("Contact: https://t.me/halloweeks\n");
	printf("If you have an problem please open issue on github: \nhttps://github.com/halloweeks/pubg-mobile-unpacker/issues/\n\n");
	
	clock_t start_time = clock();
	
	IFSHeader Header;
	IFSHetHeader HetHeader;
	IFSBetHeader BetHeader;
	
	IFSHetTable HetTable;
	IFSBetTable BetTable;
	
	struct stat st;
	
	if (stat(argv[1], &st) != 0) {
		fprintf(stderr, "'%s' does not exist.\n", argv[1]);
		return EXIT_FAILURE;
	}
	
	if (!S_ISREG(st.st_mode)) {
		fprintf(stderr, "'%s' not an regular file!\n", argv[1]);
		return EXIT_FAILURE;
	}
	
	int file = open(argv[1], O_RDWR);
	
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
		fprintf(stderr, "This file is unsupported\n");
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
	
	
	free(HetBuffer);
	
	
	
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
	printf("IFSBetHeader\n");
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
	
	
	
	free(BetBuffer);
	
	
	close(file);
	
	clock_t end_time = clock();
	double time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
	const double MB = 1024.0 * 1024.0;
	printf("Processed %.2f MB, speed = %.2f MB/s, complete in %f seconds\n", st.st_size / MB, st.st_size / MB / time, time);
	return EXIT_SUCCESS;
}