/*
 * SILLAGE TRANSFER — partage de fichiers pair-à-pair, chiffré de bout en bout.
 *
 * Un seul fichier C. Interface raylib. Cryptographie SILLAGE BRUME-512.
 *
 *   Build :  ./build.sh
 *   Run   :  ./sillage-transfer
 *   Test  :  ./sillage-transfer --selftest
 *
 * Dépendances : raylib >= 5, SILLAGE (../sillage/c), OpenSSL (libcrypto),
 * POSIX sockets, pthreads. Le générateur de QR code de Nayuki (MIT) est
 * embarqué ci-dessous.
 *
 * SÉCURITÉ
 * --------
 *  - WebRTC/ICE/STUN ou TCP direct : aucune donnée ne passe par un relais.
 *  - Signalisation facultative : elle ne relaie que des SDP signés.
 *  - Clé de 512 bits, nonce de 192 bits, tag de 128 bits (BRUME-512).
 *  - Authentification par défi-réponse HMAC-SHA256 avec un jeton à usage
 *    unique ; un seul transfert réussi par invitation.
 *  - Métadonnées et données découpées en trames AEAD indépendantes.
 *  - Mode mot de passe : la clé est dérivée localement (scrypt) ; le mot de
 *    passe ne transite jamais.
 *  - SILLAGE est une suite de recherche : voir la page « À propos ».
 */

#define _GNU_SOURCE 1

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <limits.h>
#include <math.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <raylib.h>

#ifndef SILLAGE_WEBRTC
#define SILLAGE_WEBRTC 1
#endif
#if SILLAGE_WEBRTC
#include <rtc/rtc.h>
#endif

#include "sillage.h"

#define APP_NAME        "SILLAGE Transfer"
#define APP_VERSION     "1.1"
#define LINK_PREFIX     "sillage://v1?"
#define LINK_PREFIX_V2  "sillage://v2?"

#define TRANSPORT_TCP     0
#define TRANSPORT_WEBRTC  1

#define CODE_LEN          10
#define SIGNAL_MAX_BLOB   (192u * 1024u)
#define SIGNAL_DEFAULT    "0.peerjs.com:443"
#define SIGNAL_DEFAULT_PORT 443
#define LEGACY_SIGNAL_PORT 8787
#define STUN_DEFAULT      "stun:stun.l.google.com:19302"
#define SIGNAL_ROOM_TTL   7200.0
#define SIGNAL_ROOMS      128
#define STREAM_RING_CAP   (8u * 1024u * 1024u)

#define INVITE_ID_LEN   16
#define TOKEN_LEN       16
#define KEY_LEN         64
#define NONCE_LEN       24
#define NONCE_PREFIX_LEN 16
#define TAG_LEN         16
#define CHALLENGE_LEN   32
#define HMAC_LEN        32

#define AEAD_PROFILE    0
#define CHUNK_SIZE      (1024u * 1024u)
#define MIN_CHUNK       (4u * 1024u)
#define MAX_CHUNK       (8u * 1024u * 1024u)
#define MAX_FILE_SIZE   (1ull << 40)      /* 1 Tio */
#define MAX_NAME        (180)

#define SOCK_IO_TIMEOUT_MS  60000
#define MAX_AUTH_FAILS      10

#define COLOR_BG        ((Color){ 9, 12, 18, 255 })
#define COLOR_BG2       ((Color){ 12, 17, 26, 255 })
#define COLOR_SIDEBAR   ((Color){ 11, 15, 23, 255 })
#define COLOR_PANEL     ((Color){ 17, 23, 35, 255 })
#define COLOR_PANEL2    ((Color){ 21, 29, 44, 255 })
#define COLOR_FIELD     ((Color){ 11, 16, 25, 255 })
#define COLOR_BORDER    ((Color){ 32, 43, 64, 255 })
#define COLOR_BORDER_HI ((Color){ 48, 64, 92, 255 })
#define COLOR_TEXT      ((Color){231, 237, 247, 255 })
#define COLOR_MUTED     ((Color){146, 159, 182, 255 })
#define COLOR_DIM       ((Color){114, 128, 151, 255 })
#define COLOR_ACCENT    ((Color){ 88, 132, 255, 255 })
#define COLOR_ACCENT2   ((Color){124,  92, 255, 255 })
#define COLOR_TEAL      ((Color){ 52, 211, 153, 255 })
#define COLOR_WARN      ((Color){251, 191,  36, 255 })
#define COLOR_DANGER    ((Color){248, 113, 113, 255 })
#define COLOR_WHITE     ((Color){255, 255, 255, 255 })
#define COLOR_INK       ((Color){ 10,  14,  22, 255 })

#define SIDEBAR_W       236.0f
#define PAGE_PAD         30.0f
#define HEADER_H         86.0f

/* ===================================================================== */
/*  QR Code generator library (C) — Project Nayuki, MIT                  */
/* ===================================================================== */
/* 
 * QR Code generator library (C)
 * 
 * Copyright (c) Project Nayuki. (MIT License)
 * https://www.nayuki.io/page/qr-code-generator-library
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 * - The above copyright notice and this permission notice shall be included in
 *   all copies or substantial portions of the Software.
 * - The Software is provided "as is", without warranty of any kind, express or
 *   implied, including but not limited to the warranties of merchantability,
 *   fitness for a particular purpose and noninfringement. In no event shall the
 *   authors or copyright holders be liable for any claim, damages or other
 *   liability, whether in an action of contract, tort or otherwise, arising from,
 *   out of or in connection with the Software or the use or other dealings in the
 *   Software.
 */


#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>


#ifdef __cplusplus
extern "C" {
#endif


/* 
 * This library creates QR Code symbols, which is a type of two-dimension barcode.
 * Invented by Denso Wave and described in the ISO/IEC 18004 standard.
 * A QR Code structure is an immutable square grid of dark and light cells.
 * The library provides functions to create a QR Code from text or binary data.
 * The library covers the QR Code Model 2 specification, supporting all versions (sizes)
 * from 1 to 40, all 4 error correction levels, and 4 character encoding modes.
 * 
 * Ways to create a QR Code object:
 * - High level: Take the payload data and call qrcodegen_encodeText() or qrcodegen_encodeBinary().
 * - Low level: Custom-make the list of segments and call
 *   qrcodegen_encodeSegments() or qrcodegen_encodeSegmentsAdvanced().
 * (Note that all ways require supplying the desired error correction level and various byte buffers.)
 */


/*---- Enum and struct types----*/

/* 
 * The error correction level in a QR Code symbol.
 */
enum qrcodegen_Ecc {
	// Must be declared in ascending order of error protection
	// so that an internal qrcodegen function works properly
	qrcodegen_Ecc_LOW = 0 ,  // The QR Code can tolerate about  7% erroneous codewords
	qrcodegen_Ecc_MEDIUM  ,  // The QR Code can tolerate about 15% erroneous codewords
	qrcodegen_Ecc_QUARTILE,  // The QR Code can tolerate about 25% erroneous codewords
	qrcodegen_Ecc_HIGH    ,  // The QR Code can tolerate about 30% erroneous codewords
};


/* 
 * The mask pattern used in a QR Code symbol.
 */
enum qrcodegen_Mask {
	// A special value to tell the QR Code encoder to
	// automatically select an appropriate mask pattern
	qrcodegen_Mask_AUTO = -1,
	// The eight actual mask patterns
	qrcodegen_Mask_0 = 0,
	qrcodegen_Mask_1,
	qrcodegen_Mask_2,
	qrcodegen_Mask_3,
	qrcodegen_Mask_4,
	qrcodegen_Mask_5,
	qrcodegen_Mask_6,
	qrcodegen_Mask_7,
};


/* 
 * Describes how a segment's data bits are interpreted.
 */
enum qrcodegen_Mode {
	qrcodegen_Mode_NUMERIC      = 0x1,
	qrcodegen_Mode_ALPHANUMERIC = 0x2,
	qrcodegen_Mode_BYTE         = 0x4,
	qrcodegen_Mode_KANJI        = 0x8,
	qrcodegen_Mode_ECI          = 0x7,
};


/* 
 * A segment of character/binary/control data in a QR Code symbol.
 * The mid-level way to create a segment is to take the payload data
 * and call a factory function such as qrcodegen_makeNumeric().
 * The low-level way to create a segment is to custom-make the bit buffer
 * and initialize a qrcodegen_Segment struct with appropriate values.
 * Even in the most favorable conditions, a QR Code can only hold 7089 characters of data.
 * Any segment longer than this is meaningless for the purpose of generating QR Codes.
 * Moreover, the maximum allowed bit length is 32767 because
 * the largest QR Code (version 40) has 31329 modules.
 */
struct qrcodegen_Segment {
	// The mode indicator of this segment.
	enum qrcodegen_Mode mode;
	
	// The length of this segment's unencoded data. Measured in characters for
	// numeric/alphanumeric/kanji mode, bytes for byte mode, and 0 for ECI mode.
	// Always zero or positive. Not the same as the data's bit length.
	int numChars;
	
	// The data bits of this segment, packed in bitwise big endian.
	// Can be null if the bit length is zero.
	uint8_t *data;
	
	// The number of valid data bits used in the buffer. Requires
	// 0 <= bitLength <= 32767, and bitLength <= (capacity of data array) * 8.
	// The character count (numChars) must agree with the mode and the bit buffer length.
	int bitLength;
};



/*---- Macro constants and functions ----*/

#define qrcodegen_VERSION_MIN   1  // The minimum version number supported in the QR Code Model 2 standard
#define qrcodegen_VERSION_MAX  40  // The maximum version number supported in the QR Code Model 2 standard

// Calculates the number of bytes needed to store any QR Code up to and including the given version number,
// as a compile-time constant. For example, 'uint8_t buffer[qrcodegen_BUFFER_LEN_FOR_VERSION(25)];'
// can store any single QR Code from version 1 to 25 (inclusive). The result fits in an int (or int16).
// Requires qrcodegen_VERSION_MIN <= n <= qrcodegen_VERSION_MAX.
#define qrcodegen_BUFFER_LEN_FOR_VERSION(n)  ((((n) * 4 + 17) * ((n) * 4 + 17) + 7) / 8 + 1)

// The worst-case number of bytes needed to store one QR Code, up to and including
// version 40. This value equals 3918, which is just under 4 kilobytes.
// Use this more convenient value to avoid calculating tighter memory bounds for buffers.
#define qrcodegen_BUFFER_LEN_MAX  qrcodegen_BUFFER_LEN_FOR_VERSION(qrcodegen_VERSION_MAX)



/*---- Functions (high level) to generate QR Codes ----*/

/* 
 * Encodes the given text string to a QR Code, returning true if successful.
 * If the data is too long to fit in any version in the given range
 * at the given ECC level, then false is returned.
 * 
 * The input text must be encoded in UTF-8 and contain no NULs.
 * Requires 1 <= minVersion <= maxVersion <= 40.
 * 
 * The smallest possible QR Code version within the given range is automatically
 * chosen for the output. Iff boostEcl is true, then the ECC level of the result
 * may be higher than the ecl argument if it can be done without increasing the
 * version. The mask is either between qrcodegen_Mask_0 to 7 to force that mask, or
 * qrcodegen_Mask_AUTO to automatically choose an appropriate mask (which may be slow).
 * 
 * About the arrays, letting len = qrcodegen_BUFFER_LEN_FOR_VERSION(maxVersion):
 * - Before calling the function:
 *   - The array ranges tempBuffer[0 : len] and qrcode[0 : len] must allow
 *     reading and writing; hence each array must have a length of at least len.
 *   - The two ranges must not overlap (aliasing).
 *   - The initial state of both ranges can be uninitialized
 *     because the function always writes before reading.
 * - After the function returns:
 *   - Both ranges have no guarantee on which elements are initialized and what values are stored.
 *   - tempBuffer contains no useful data and should be treated as entirely uninitialized.
 *   - If successful, qrcode can be passed into qrcodegen_getSize() and qrcodegen_getModule().
 * 
 * If successful, the resulting QR Code may use numeric,
 * alphanumeric, or byte mode to encode the text.
 * 
 * In the most optimistic case, a QR Code at version 40 with low ECC
 * can hold any UTF-8 string up to 2953 bytes, or any alphanumeric string
 * up to 4296 characters, or any digit string up to 7089 characters.
 * These numbers represent the hard upper limit of the QR Code standard.
 * 
 * Please consult the QR Code specification for information on
 * data capacities per version, ECC level, and text encoding mode.
 */
bool qrcodegen_encodeText(const char *text, uint8_t tempBuffer[], uint8_t qrcode[],
	enum qrcodegen_Ecc ecl, int minVersion, int maxVersion, enum qrcodegen_Mask mask, bool boostEcl);


/* 
 * Encodes the given binary data to a QR Code, returning true if successful.
 * If the data is too long to fit in any version in the given range
 * at the given ECC level, then false is returned.
 * 
 * Requires 1 <= minVersion <= maxVersion <= 40.
 * 
 * The smallest possible QR Code version within the given range is automatically
 * chosen for the output. Iff boostEcl is true, then the ECC level of the result
 * may be higher than the ecl argument if it can be done without increasing the
 * version. The mask is either between qrcodegen_Mask_0 to 7 to force that mask, or
 * qrcodegen_Mask_AUTO to automatically choose an appropriate mask (which may be slow).
 * 
 * About the arrays, letting len = qrcodegen_BUFFER_LEN_FOR_VERSION(maxVersion):
 * - Before calling the function:
 *   - The array ranges dataAndTemp[0 : len] and qrcode[0 : len] must allow
 *     reading and writing; hence each array must have a length of at least len.
 *   - The two ranges must not overlap (aliasing).
 *   - The input array range dataAndTemp[0 : dataLen] should normally be
 *     valid UTF-8 text, but is not required by the QR Code standard.
 *   - The initial state of dataAndTemp[dataLen : len] and qrcode[0 : len]
 *     can be uninitialized because the function always writes before reading.
 * - After the function returns:
 *   - Both ranges have no guarantee on which elements are initialized and what values are stored.
 *   - dataAndTemp contains no useful data and should be treated as entirely uninitialized.
 *   - If successful, qrcode can be passed into qrcodegen_getSize() and qrcodegen_getModule().
 * 
 * If successful, the resulting QR Code will use byte mode to encode the data.
 * 
 * In the most optimistic case, a QR Code at version 40 with low ECC can hold any byte
 * sequence up to length 2953. This is the hard upper limit of the QR Code standard.
 * 
 * Please consult the QR Code specification for information on
 * data capacities per version, ECC level, and text encoding mode.
 */
bool qrcodegen_encodeBinary(uint8_t dataAndTemp[], size_t dataLen, uint8_t qrcode[],
	enum qrcodegen_Ecc ecl, int minVersion, int maxVersion, enum qrcodegen_Mask mask, bool boostEcl);


/*---- Functions (low level) to generate QR Codes ----*/

/* 
 * Encodes the given segments to a QR Code, returning true if successful.
 * If the data is too long to fit in any version at the given ECC level,
 * then false is returned.
 * 
 * The smallest possible QR Code version is automatically chosen for
 * the output. The ECC level of the result may be higher than the
 * ecl argument if it can be done without increasing the version.
 * 
 * About the byte arrays, letting len = qrcodegen_BUFFER_LEN_FOR_VERSION(qrcodegen_VERSION_MAX):
 * - Before calling the function:
 *   - The array ranges tempBuffer[0 : len] and qrcode[0 : len] must allow
 *     reading and writing; hence each array must have a length of at least len.
 *   - The two ranges must not overlap (aliasing).
 *   - The initial state of both ranges can be uninitialized
 *     because the function always writes before reading.
 *   - The input array segs can contain segments whose data buffers overlap with tempBuffer.
 * - After the function returns:
 *   - Both ranges have no guarantee on which elements are initialized and what values are stored.
 *   - tempBuffer contains no useful data and should be treated as entirely uninitialized.
 *   - Any segment whose data buffer overlaps with tempBuffer[0 : len]
 *     must be treated as having invalid values in that array.
 *   - If successful, qrcode can be passed into qrcodegen_getSize() and qrcodegen_getModule().
 * 
 * Please consult the QR Code specification for information on
 * data capacities per version, ECC level, and text encoding mode.
 * 
 * This function allows the user to create a custom sequence of segments that switches
 * between modes (such as alphanumeric and byte) to encode text in less space.
 * This is a low-level API; the high-level API is qrcodegen_encodeText() and qrcodegen_encodeBinary().
 */
bool qrcodegen_encodeSegments(const struct qrcodegen_Segment segs[], size_t len,
	enum qrcodegen_Ecc ecl, uint8_t tempBuffer[], uint8_t qrcode[]);


/* 
 * Encodes the given segments to a QR Code, returning true if successful.
 * If the data is too long to fit in any version in the given range
 * at the given ECC level, then false is returned.
 * 
 * Requires 1 <= minVersion <= maxVersion <= 40.
 * 
 * The smallest possible QR Code version within the given range is automatically
 * chosen for the output. Iff boostEcl is true, then the ECC level of the result
 * may be higher than the ecl argument if it can be done without increasing the
 * version. The mask is either between qrcodegen_Mask_0 to 7 to force that mask, or
 * qrcodegen_Mask_AUTO to automatically choose an appropriate mask (which may be slow).
 * 
 * About the byte arrays, letting len = qrcodegen_BUFFER_LEN_FOR_VERSION(qrcodegen_VERSION_MAX):
 * - Before calling the function:
 *   - The array ranges tempBuffer[0 : len] and qrcode[0 : len] must allow
 *     reading and writing; hence each array must have a length of at least len.
 *   - The two ranges must not overlap (aliasing).
 *   - The initial state of both ranges can be uninitialized
 *     because the function always writes before reading.
 *   - The input array segs can contain segments whose data buffers overlap with tempBuffer.
 * - After the function returns:
 *   - Both ranges have no guarantee on which elements are initialized and what values are stored.
 *   - tempBuffer contains no useful data and should be treated as entirely uninitialized.
 *   - Any segment whose data buffer overlaps with tempBuffer[0 : len]
 *     must be treated as having invalid values in that array.
 *   - If successful, qrcode can be passed into qrcodegen_getSize() and qrcodegen_getModule().
 * 
 * Please consult the QR Code specification for information on
 * data capacities per version, ECC level, and text encoding mode.
 * 
 * This function allows the user to create a custom sequence of segments that switches
 * between modes (such as alphanumeric and byte) to encode text in less space.
 * This is a low-level API; the high-level API is qrcodegen_encodeText() and qrcodegen_encodeBinary().
 */
bool qrcodegen_encodeSegmentsAdvanced(const struct qrcodegen_Segment segs[], size_t len, enum qrcodegen_Ecc ecl,
	int minVersion, int maxVersion, enum qrcodegen_Mask mask, bool boostEcl, uint8_t tempBuffer[], uint8_t qrcode[]);


/* 
 * Tests whether the given string can be encoded as a segment in numeric mode.
 * A string is encodable iff each character is in the range 0 to 9.
 */
bool qrcodegen_isNumeric(const char *text);


/* 
 * Tests whether the given string can be encoded as a segment in alphanumeric mode.
 * A string is encodable iff each character is in the following set: 0 to 9, A to Z
 * (uppercase only), space, dollar, percent, asterisk, plus, hyphen, period, slash, colon.
 */
bool qrcodegen_isAlphanumeric(const char *text);


/* 
 * Returns the number of bytes (uint8_t) needed for the data buffer of a segment
 * containing the given number of characters using the given mode. Notes:
 * - Returns SIZE_MAX on failure, i.e. numChars > INT16_MAX or the internal
 *   calculation of the number of needed bits exceeds INT16_MAX (i.e. 32767).
 * - Otherwise, all valid results are in the range [0, ceil(INT16_MAX / 8)], i.e. at most 4096.
 * - It is okay for the user to allocate more bytes for the buffer than needed.
 * - For byte mode, numChars measures the number of bytes, not Unicode code points.
 * - For ECI mode, numChars must be 0, and the worst-case number of bytes is returned.
 *   An actual ECI segment can have shorter data. For non-ECI modes, the result is exact.
 */
size_t qrcodegen_calcSegmentBufferSize(enum qrcodegen_Mode mode, size_t numChars);


/* 
 * Returns a segment representing the given binary data encoded in
 * byte mode. All input byte arrays are acceptable. Any text string
 * can be converted to UTF-8 bytes and encoded as a byte mode segment.
 */
struct qrcodegen_Segment qrcodegen_makeBytes(const uint8_t data[], size_t len, uint8_t buf[]);


/* 
 * Returns a segment representing the given string of decimal digits encoded in numeric mode.
 */
struct qrcodegen_Segment qrcodegen_makeNumeric(const char *digits, uint8_t buf[]);


/* 
 * Returns a segment representing the given text string encoded in alphanumeric mode.
 * The characters allowed are: 0 to 9, A to Z (uppercase only), space,
 * dollar, percent, asterisk, plus, hyphen, period, slash, colon.
 */
struct qrcodegen_Segment qrcodegen_makeAlphanumeric(const char *text, uint8_t buf[]);


/* 
 * Returns a segment representing an Extended Channel Interpretation
 * (ECI) designator with the given assignment value.
 */
struct qrcodegen_Segment qrcodegen_makeEci(long assignVal, uint8_t buf[]);


/*---- Functions to extract raw data from QR Codes ----*/

/* 
 * Returns the side length of the given QR Code, assuming that encoding succeeded.
 * The result is in the range [21, 177]. Note that the length of the array buffer
 * is related to the side length - every 'uint8_t qrcode[]' must have length at least
 * qrcodegen_BUFFER_LEN_FOR_VERSION(version), which equals ceil(size^2 / 8 + 1).
 */
int qrcodegen_getSize(const uint8_t qrcode[]);


/* 
 * Returns the color of the module (pixel) at the given coordinates, which is false
 * for light or true for dark. The top left corner has the coordinates (x=0, y=0).
 * If the given coordinates are out of bounds, then false (light) is returned.
 */
bool qrcodegen_getModule(const uint8_t qrcode[], int x, int y);


#ifdef __cplusplus
}
#endif

/* 
 * QR Code generator library (C)
 * 
 * Copyright (c) Project Nayuki. (MIT License)
 * https://www.nayuki.io/page/qr-code-generator-library
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 * - The above copyright notice and this permission notice shall be included in
 *   all copies or substantial portions of the Software.
 * - The Software is provided "as is", without warranty of any kind, express or
 *   implied, including but not limited to the warranties of merchantability,
 *   fitness for a particular purpose and noninfringement. In no event shall the
 *   authors or copyright holders be liable for any claim, damages or other
 *   liability, whether in an action of contract, tort or otherwise, arising from,
 *   out of or in connection with the Software or the use or other dealings in the
 *   Software.
 */

#include <assert.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#ifndef QRCODEGEN_TEST
	#define testable static  // Keep functions private
#else
	#define testable  // Expose private functions
#endif


/*---- Forward declarations for private functions ----*/

// Regarding all public and private functions defined in this source file:
// - They require all pointer/array arguments to be not null unless the array length is zero.
// - They only read input scalar/array arguments, write to output pointer/array
//   arguments, and return scalar values; they are "pure" functions.
// - They don't read mutable global variables or write to any global variables.
// - They don't perform I/O, read the clock, print to console, etc.
// - They allocate a small and constant amount of stack memory.
// - They don't allocate or free any memory on the heap.
// - They don't recurse or mutually recurse. All the code
//   could be inlined into the top-level public functions.
// - They run in at most quadratic time with respect to input arguments.
//   Most functions run in linear time, and some in constant time.
//   There are no unbounded loops or non-obvious termination conditions.
// - They are completely thread-safe if the caller does not give the
//   same writable buffer to concurrent calls to these functions.

testable void appendBitsToBuffer(unsigned int val, int numBits, uint8_t buffer[], int *bitLen);

testable void addEccAndInterleave(uint8_t data[], int version, enum qrcodegen_Ecc ecl, uint8_t result[]);
testable int getNumDataCodewords(int version, enum qrcodegen_Ecc ecl);
testable int getNumRawDataModules(int ver);

testable void reedSolomonComputeDivisor(int degree, uint8_t result[]);
testable void reedSolomonComputeRemainder(const uint8_t data[], int dataLen,
	const uint8_t generator[], int degree, uint8_t result[]);
testable uint8_t reedSolomonMultiply(uint8_t x, uint8_t y);

testable void initializeFunctionModules(int version, uint8_t qrcode[]);
static void drawLightFunctionModules(uint8_t qrcode[], int version);
static void drawFormatBits(enum qrcodegen_Ecc ecl, enum qrcodegen_Mask mask, uint8_t qrcode[]);
testable int getAlignmentPatternPositions(int version, uint8_t result[7]);
static void fillRectangle(int left, int top, int width, int height, uint8_t qrcode[]);

static void drawCodewords(const uint8_t data[], int dataLen, uint8_t qrcode[]);
static void applyMask(const uint8_t functionModules[], uint8_t qrcode[], enum qrcodegen_Mask mask);
static long getPenaltyScore(const uint8_t qrcode[]);
static int finderPenaltyCountPatterns(const int runHistory[7], int qrsize);
static int finderPenaltyTerminateAndCount(bool currentRunColor, int currentRunLength, int runHistory[7], int qrsize);
static void finderPenaltyAddHistory(int currentRunLength, int runHistory[7], int qrsize);

testable bool getModuleBounded(const uint8_t qrcode[], int x, int y);
testable void setModuleBounded(uint8_t qrcode[], int x, int y, bool isDark);
testable void setModuleUnbounded(uint8_t qrcode[], int x, int y, bool isDark);
static bool getBit(int x, int i);

testable int calcSegmentBitLength(enum qrcodegen_Mode mode, size_t numChars);
testable int getTotalBits(const struct qrcodegen_Segment segs[], size_t len, int version);
static int numCharCountBits(enum qrcodegen_Mode mode, int version);



/*---- Private tables of constants ----*/

// The set of all legal characters in alphanumeric mode, where each character
// value maps to the index in the string. For checking text and encoding segments.
static const char *ALPHANUMERIC_CHARSET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

// Sentinel value for use in only some functions.
#define LENGTH_OVERFLOW -1

// For generating error correction codes.
testable const int8_t ECC_CODEWORDS_PER_BLOCK[4][41] = {
	// Version: (note that index 0 is for padding, and is set to an illegal value)
	//0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40    Error correction level
	{-1,  7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30},  // Low
	{-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28},  // Medium
	{-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30},  // Quartile
	{-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30},  // High
};

#define qrcodegen_REED_SOLOMON_DEGREE_MAX 30  // Based on the table above

// For generating error correction codes.
testable const int8_t NUM_ERROR_CORRECTION_BLOCKS[4][41] = {
	// Version: (note that index 0 is for padding, and is set to an illegal value)
	//0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40    Error correction level
	{-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4,  4,  4,  4,  4,  6,  6,  6,  6,  7,  8,  8,  9,  9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25},  // Low
	{-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5,  5,  8,  9,  9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49},  // Medium
	{-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8,  8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68},  // Quartile
	{-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81},  // High
};

// For automatic mask pattern selection.
static const int PENALTY_N1 =  3;
static const int PENALTY_N2 =  3;
static const int PENALTY_N3 = 40;
static const int PENALTY_N4 = 10;



/*---- High-level QR Code encoding functions ----*/

// Public function - see documentation comment in header file.
bool qrcodegen_encodeText(const char *text, uint8_t tempBuffer[], uint8_t qrcode[],
		enum qrcodegen_Ecc ecl, int minVersion, int maxVersion, enum qrcodegen_Mask mask, bool boostEcl) {
	
	size_t textLen = strlen(text);
	if (textLen == 0)
		return qrcodegen_encodeSegmentsAdvanced(NULL, 0, ecl, minVersion, maxVersion, mask, boostEcl, tempBuffer, qrcode);
	size_t bufLen = (size_t)qrcodegen_BUFFER_LEN_FOR_VERSION(maxVersion);
	
	struct qrcodegen_Segment seg;
	if (qrcodegen_isNumeric(text)) {
		if (qrcodegen_calcSegmentBufferSize(qrcodegen_Mode_NUMERIC, textLen) > bufLen)
			goto fail;
		seg = qrcodegen_makeNumeric(text, tempBuffer);
	} else if (qrcodegen_isAlphanumeric(text)) {
		if (qrcodegen_calcSegmentBufferSize(qrcodegen_Mode_ALPHANUMERIC, textLen) > bufLen)
			goto fail;
		seg = qrcodegen_makeAlphanumeric(text, tempBuffer);
	} else {
		if (textLen > bufLen)
			goto fail;
		for (size_t i = 0; i < textLen; i++)
			tempBuffer[i] = (uint8_t)text[i];
		seg.mode = qrcodegen_Mode_BYTE;
		seg.bitLength = calcSegmentBitLength(seg.mode, textLen);
		if (seg.bitLength == LENGTH_OVERFLOW)
			goto fail;
		seg.numChars = (int)textLen;
		seg.data = tempBuffer;
	}
	return qrcodegen_encodeSegmentsAdvanced(&seg, 1, ecl, minVersion, maxVersion, mask, boostEcl, tempBuffer, qrcode);
	
fail:
	qrcode[0] = 0;  // Set size to invalid value for safety
	return false;
}


// Public function - see documentation comment in header file.
bool qrcodegen_encodeBinary(uint8_t dataAndTemp[], size_t dataLen, uint8_t qrcode[],
		enum qrcodegen_Ecc ecl, int minVersion, int maxVersion, enum qrcodegen_Mask mask, bool boostEcl) {
	
	struct qrcodegen_Segment seg;
	seg.mode = qrcodegen_Mode_BYTE;
	seg.bitLength = calcSegmentBitLength(seg.mode, dataLen);
	if (seg.bitLength == LENGTH_OVERFLOW) {
		qrcode[0] = 0;  // Set size to invalid value for safety
		return false;
	}
	seg.numChars = (int)dataLen;
	seg.data = dataAndTemp;
	return qrcodegen_encodeSegmentsAdvanced(&seg, 1, ecl, minVersion, maxVersion, mask, boostEcl, dataAndTemp, qrcode);
}


// Appends the given number of low-order bits of the given value to the given byte-based
// bit buffer, increasing the bit length. Requires 0 <= numBits <= 16 and val < 2^numBits.
testable void appendBitsToBuffer(unsigned int val, int numBits, uint8_t buffer[], int *bitLen) {
	assert(0 <= numBits && numBits <= 16 && (unsigned long)val >> numBits == 0);
	for (int i = numBits - 1; i >= 0; i--, (*bitLen)++)
		buffer[*bitLen >> 3] |= ((val >> i) & 1) << (7 - (*bitLen & 7));
}



/*---- Low-level QR Code encoding functions ----*/

// Public function - see documentation comment in header file.
bool qrcodegen_encodeSegments(const struct qrcodegen_Segment segs[], size_t len,
		enum qrcodegen_Ecc ecl, uint8_t tempBuffer[], uint8_t qrcode[]) {
	return qrcodegen_encodeSegmentsAdvanced(segs, len, ecl,
		qrcodegen_VERSION_MIN, qrcodegen_VERSION_MAX, qrcodegen_Mask_AUTO, true, tempBuffer, qrcode);
}


// Public function - see documentation comment in header file.
bool qrcodegen_encodeSegmentsAdvanced(const struct qrcodegen_Segment segs[], size_t len, enum qrcodegen_Ecc ecl,
		int minVersion, int maxVersion, enum qrcodegen_Mask mask, bool boostEcl, uint8_t tempBuffer[], uint8_t qrcode[]) {
	assert(segs != NULL || len == 0);
	assert(qrcodegen_VERSION_MIN <= minVersion && minVersion <= maxVersion && maxVersion <= qrcodegen_VERSION_MAX);
	assert(0 <= (int)ecl && (int)ecl <= 3 && -1 <= (int)mask && (int)mask <= 7);
	
	// Find the minimal version number to use
	int version, dataUsedBits;
	for (version = minVersion; ; version++) {
		int dataCapacityBits = getNumDataCodewords(version, ecl) * 8;  // Number of data bits available
		dataUsedBits = getTotalBits(segs, len, version);
		if (dataUsedBits != LENGTH_OVERFLOW && dataUsedBits <= dataCapacityBits)
			break;  // This version number is found to be suitable
		if (version >= maxVersion) {  // All versions in the range could not fit the given data
			qrcode[0] = 0;  // Set size to invalid value for safety
			return false;
		}
	}
	assert(dataUsedBits != LENGTH_OVERFLOW);
	
	// Increase the error correction level while the data still fits in the current version number
	for (int i = (int)qrcodegen_Ecc_MEDIUM; i <= (int)qrcodegen_Ecc_HIGH; i++) {  // From low to high
		if (boostEcl && dataUsedBits <= getNumDataCodewords(version, (enum qrcodegen_Ecc)i) * 8)
			ecl = (enum qrcodegen_Ecc)i;
	}
	
	// Concatenate all segments to create the data bit string
	memset(qrcode, 0, (size_t)qrcodegen_BUFFER_LEN_FOR_VERSION(version) * sizeof(qrcode[0]));
	int bitLen = 0;
	for (size_t i = 0; i < len; i++) {
		const struct qrcodegen_Segment *seg = &segs[i];
		appendBitsToBuffer((unsigned int)seg->mode, 4, qrcode, &bitLen);
		appendBitsToBuffer((unsigned int)seg->numChars, numCharCountBits(seg->mode, version), qrcode, &bitLen);
		for (int j = 0; j < seg->bitLength; j++) {
			int bit = (seg->data[j >> 3] >> (7 - (j & 7))) & 1;
			appendBitsToBuffer((unsigned int)bit, 1, qrcode, &bitLen);
		}
	}
	assert(bitLen == dataUsedBits);
	
	// Add terminator and pad up to a byte if applicable
	int dataCapacityBits = getNumDataCodewords(version, ecl) * 8;
	assert(bitLen <= dataCapacityBits);
	int terminatorBits = dataCapacityBits - bitLen;
	if (terminatorBits > 4)
		terminatorBits = 4;
	appendBitsToBuffer(0, terminatorBits, qrcode, &bitLen);
	appendBitsToBuffer(0, (8 - bitLen % 8) % 8, qrcode, &bitLen);
	assert(bitLen % 8 == 0);
	
	// Pad with alternating bytes until data capacity is reached
	for (uint8_t padByte = 0xEC; bitLen < dataCapacityBits; padByte ^= 0xEC ^ 0x11)
		appendBitsToBuffer(padByte, 8, qrcode, &bitLen);
	
	// Compute ECC, draw modules
	addEccAndInterleave(qrcode, version, ecl, tempBuffer);
	initializeFunctionModules(version, qrcode);
	drawCodewords(tempBuffer, getNumRawDataModules(version) / 8, qrcode);
	drawLightFunctionModules(qrcode, version);
	initializeFunctionModules(version, tempBuffer);
	
	// Do masking
	if (mask == qrcodegen_Mask_AUTO) {  // Automatically choose best mask
		long minPenalty = LONG_MAX;
		for (int i = 0; i < 8; i++) {
			enum qrcodegen_Mask msk = (enum qrcodegen_Mask)i;
			applyMask(tempBuffer, qrcode, msk);
			drawFormatBits(ecl, msk, qrcode);
			long penalty = getPenaltyScore(qrcode);
			if (penalty < minPenalty) {
				mask = msk;
				minPenalty = penalty;
			}
			applyMask(tempBuffer, qrcode, msk);  // Undoes the mask due to XOR
		}
	}
	assert(0 <= (int)mask && (int)mask <= 7);
	applyMask(tempBuffer, qrcode, mask);  // Apply the final choice of mask
	drawFormatBits(ecl, mask, qrcode);  // Overwrite old format bits
	return true;
}



/*---- Error correction code generation functions ----*/

// Appends error correction bytes to each block of the given data array, then interleaves
// bytes from the blocks and stores them in the result array. data[0 : dataLen] contains
// the input data. data[dataLen : rawCodewords] is used as a temporary work area and will
// be clobbered by this function. The final answer is stored in result[0 : rawCodewords].
testable void addEccAndInterleave(uint8_t data[], int version, enum qrcodegen_Ecc ecl, uint8_t result[]) {
	// Calculate parameter numbers
	assert(0 <= (int)ecl && (int)ecl < 4 && qrcodegen_VERSION_MIN <= version && version <= qrcodegen_VERSION_MAX);
	int numBlocks = NUM_ERROR_CORRECTION_BLOCKS[(int)ecl][version];
	int blockEccLen = ECC_CODEWORDS_PER_BLOCK  [(int)ecl][version];
	int rawCodewords = getNumRawDataModules(version) / 8;
	int dataLen = getNumDataCodewords(version, ecl);
	int numShortBlocks = numBlocks - rawCodewords % numBlocks;
	int shortBlockDataLen = rawCodewords / numBlocks - blockEccLen;
	
	// Split data into blocks, calculate ECC, and interleave
	// (not concatenate) the bytes into a single sequence
	uint8_t rsdiv[qrcodegen_REED_SOLOMON_DEGREE_MAX];
	reedSolomonComputeDivisor(blockEccLen, rsdiv);
	const uint8_t *dat = data;
	for (int i = 0; i < numBlocks; i++) {
		int datLen = shortBlockDataLen + (i < numShortBlocks ? 0 : 1);
		uint8_t *ecc = &data[dataLen];  // Temporary storage
		reedSolomonComputeRemainder(dat, datLen, rsdiv, blockEccLen, ecc);
		for (int j = 0, k = i; j < datLen; j++, k += numBlocks) {  // Copy data
			if (j == shortBlockDataLen)
				k -= numShortBlocks;
			result[k] = dat[j];
		}
		for (int j = 0, k = dataLen + i; j < blockEccLen; j++, k += numBlocks)  // Copy ECC
			result[k] = ecc[j];
		dat += datLen;
	}
}


// Returns the number of 8-bit codewords that can be used for storing data (not ECC),
// for the given version number and error correction level. The result is in the range [9, 2956].
testable int getNumDataCodewords(int version, enum qrcodegen_Ecc ecl) {
	int v = version, e = (int)ecl;
	assert(0 <= e && e < 4);
	return getNumRawDataModules(v) / 8
		- ECC_CODEWORDS_PER_BLOCK    [e][v]
		* NUM_ERROR_CORRECTION_BLOCKS[e][v];
}


// Returns the number of data bits that can be stored in a QR Code of the given version number, after
// all function modules are excluded. This includes remainder bits, so it might not be a multiple of 8.
// The result is in the range [208, 29648]. This could be implemented as a 40-entry lookup table.
testable int getNumRawDataModules(int ver) {
	assert(qrcodegen_VERSION_MIN <= ver && ver <= qrcodegen_VERSION_MAX);
	int result = (16 * ver + 128) * ver + 64;
	if (ver >= 2) {
		int numAlign = ver / 7 + 2;
		result -= (25 * numAlign - 10) * numAlign - 55;
		if (ver >= 7)
			result -= 36;
	}
	assert(208 <= result && result <= 29648);
	return result;
}



/*---- Reed-Solomon ECC generator functions ----*/

// Computes a Reed-Solomon ECC generator polynomial for the given degree, storing in result[0 : degree].
// This could be implemented as a lookup table over all possible parameter values, instead of as an algorithm.
testable void reedSolomonComputeDivisor(int degree, uint8_t result[]) {
	assert(1 <= degree && degree <= qrcodegen_REED_SOLOMON_DEGREE_MAX);
	// Polynomial coefficients are stored from highest to lowest power, excluding the leading term which is always 1.
	// For example the polynomial x^3 + 255x^2 + 8x + 93 is stored as the uint8 array {255, 8, 93}.
	memset(result, 0, (size_t)degree * sizeof(result[0]));
	result[degree - 1] = 1;  // Start off with the monomial x^0
	
	// Compute the product polynomial (x - r^0) * (x - r^1) * (x - r^2) * ... * (x - r^{degree-1}),
	// drop the highest monomial term which is always 1x^degree.
	// Note that r = 0x02, which is a generator element of this field GF(2^8/0x11D).
	uint8_t root = 1;
	for (int i = 0; i < degree; i++) {
		// Multiply the current product by (x - r^i)
		for (int j = 0; j < degree; j++) {
			result[j] = reedSolomonMultiply(result[j], root);
			if (j + 1 < degree)
				result[j] ^= result[j + 1];
		}
		root = reedSolomonMultiply(root, 0x02);
	}
}


// Computes the Reed-Solomon error correction codeword for the given data and divisor polynomials.
// The remainder when data[0 : dataLen] is divided by divisor[0 : degree] is stored in result[0 : degree].
// All polynomials are in big endian, and the generator has an implicit leading 1 term.
testable void reedSolomonComputeRemainder(const uint8_t data[], int dataLen,
		const uint8_t generator[], int degree, uint8_t result[]) {
	assert(1 <= degree && degree <= qrcodegen_REED_SOLOMON_DEGREE_MAX);
	memset(result, 0, (size_t)degree * sizeof(result[0]));
	for (int i = 0; i < dataLen; i++) {  // Polynomial division
		uint8_t factor = data[i] ^ result[0];
		memmove(&result[0], &result[1], (size_t)(degree - 1) * sizeof(result[0]));
		result[degree - 1] = 0;
		for (int j = 0; j < degree; j++)
			result[j] ^= reedSolomonMultiply(generator[j], factor);
	}
}

#undef qrcodegen_REED_SOLOMON_DEGREE_MAX


// Returns the product of the two given field elements modulo GF(2^8/0x11D).
// All inputs are valid. This could be implemented as a 256*256 lookup table.
testable uint8_t reedSolomonMultiply(uint8_t x, uint8_t y) {
	// Russian peasant multiplication
	uint8_t z = 0;
	for (int i = 7; i >= 0; i--) {
		z = (uint8_t)((z << 1) ^ ((z >> 7) * 0x11D));
		z ^= ((y >> i) & 1) * x;
	}
	return z;
}



/*---- Drawing function modules ----*/

// Clears the given QR Code grid with light modules for the given
// version's size, then marks every function module as dark.
testable void initializeFunctionModules(int version, uint8_t qrcode[]) {
	// Initialize QR Code
	int qrsize = version * 4 + 17;
	memset(qrcode, 0, (size_t)((qrsize * qrsize + 7) / 8 + 1) * sizeof(qrcode[0]));
	qrcode[0] = (uint8_t)qrsize;
	
	// Fill horizontal and vertical timing patterns
	fillRectangle(6, 0, 1, qrsize, qrcode);
	fillRectangle(0, 6, qrsize, 1, qrcode);
	
	// Fill 3 finder patterns (all corners except bottom right) and format bits
	fillRectangle(0, 0, 9, 9, qrcode);
	fillRectangle(qrsize - 8, 0, 8, 9, qrcode);
	fillRectangle(0, qrsize - 8, 9, 8, qrcode);
	
	// Fill numerous alignment patterns
	uint8_t alignPatPos[7];
	int numAlign = getAlignmentPatternPositions(version, alignPatPos);
	for (int i = 0; i < numAlign; i++) {
		for (int j = 0; j < numAlign; j++) {
			// Don't draw on the three finder corners
			if (!((i == 0 && j == 0) || (i == 0 && j == numAlign - 1) || (i == numAlign - 1 && j == 0)))
				fillRectangle(alignPatPos[i] - 2, alignPatPos[j] - 2, 5, 5, qrcode);
		}
	}
	
	// Fill version blocks
	if (version >= 7) {
		fillRectangle(qrsize - 11, 0, 3, 6, qrcode);
		fillRectangle(0, qrsize - 11, 6, 3, qrcode);
	}
}


// Draws light function modules and possibly some dark modules onto the given QR Code, without changing
// non-function modules. This does not draw the format bits. This requires all function modules to be previously
// marked dark (namely by initializeFunctionModules()), because this may skip redrawing dark function modules.
static void drawLightFunctionModules(uint8_t qrcode[], int version) {
	// Draw horizontal and vertical timing patterns
	int qrsize = qrcodegen_getSize(qrcode);
	for (int i = 7; i < qrsize - 7; i += 2) {
		setModuleBounded(qrcode, 6, i, false);
		setModuleBounded(qrcode, i, 6, false);
	}
	
	// Draw 3 finder patterns (all corners except bottom right; overwrites some timing modules)
	for (int dy = -4; dy <= 4; dy++) {
		for (int dx = -4; dx <= 4; dx++) {
			int dist = abs(dx);
			if (abs(dy) > dist)
				dist = abs(dy);
			if (dist == 2 || dist == 4) {
				setModuleUnbounded(qrcode, 3 + dx, 3 + dy, false);
				setModuleUnbounded(qrcode, qrsize - 4 + dx, 3 + dy, false);
				setModuleUnbounded(qrcode, 3 + dx, qrsize - 4 + dy, false);
			}
		}
	}
	
	// Draw numerous alignment patterns
	uint8_t alignPatPos[7];
	int numAlign = getAlignmentPatternPositions(version, alignPatPos);
	for (int i = 0; i < numAlign; i++) {
		for (int j = 0; j < numAlign; j++) {
			if ((i == 0 && j == 0) || (i == 0 && j == numAlign - 1) || (i == numAlign - 1 && j == 0))
				continue;  // Don't draw on the three finder corners
			for (int dy = -1; dy <= 1; dy++) {
				for (int dx = -1; dx <= 1; dx++)
					setModuleBounded(qrcode, alignPatPos[i] + dx, alignPatPos[j] + dy, dx == 0 && dy == 0);
			}
		}
	}
	
	// Draw version blocks
	if (version >= 7) {
		// Calculate error correction code and pack bits
		int rem = version;  // version is uint6, in the range [7, 40]
		for (int i = 0; i < 12; i++)
			rem = (rem << 1) ^ ((rem >> 11) * 0x1F25);
		long bits = (long)version << 12 | rem;  // uint18
		assert(bits >> 18 == 0);
		
		// Draw two copies
		for (int i = 0; i < 6; i++) {
			for (int j = 0; j < 3; j++) {
				int k = qrsize - 11 + j;
				setModuleBounded(qrcode, k, i, (bits & 1) != 0);
				setModuleBounded(qrcode, i, k, (bits & 1) != 0);
				bits >>= 1;
			}
		}
	}
}


// Draws two copies of the format bits (with its own error correction code) based
// on the given mask and error correction level. This always draws all modules of
// the format bits, unlike drawLightFunctionModules() which might skip dark modules.
static void drawFormatBits(enum qrcodegen_Ecc ecl, enum qrcodegen_Mask mask, uint8_t qrcode[]) {
	// Calculate error correction code and pack bits
	assert(0 <= (int)mask && (int)mask <= 7);
	static const int table[] = {1, 0, 3, 2};
	int data = table[(int)ecl] << 3 | (int)mask;  // errCorrLvl is uint2, mask is uint3
	int rem = data;
	for (int i = 0; i < 10; i++)
		rem = (rem << 1) ^ ((rem >> 9) * 0x537);
	int bits = (data << 10 | rem) ^ 0x5412;  // uint15
	assert(bits >> 15 == 0);
	
	// Draw first copy
	for (int i = 0; i <= 5; i++)
		setModuleBounded(qrcode, 8, i, getBit(bits, i));
	setModuleBounded(qrcode, 8, 7, getBit(bits, 6));
	setModuleBounded(qrcode, 8, 8, getBit(bits, 7));
	setModuleBounded(qrcode, 7, 8, getBit(bits, 8));
	for (int i = 9; i < 15; i++)
		setModuleBounded(qrcode, 14 - i, 8, getBit(bits, i));
	
	// Draw second copy
	int qrsize = qrcodegen_getSize(qrcode);
	for (int i = 0; i < 8; i++)
		setModuleBounded(qrcode, qrsize - 1 - i, 8, getBit(bits, i));
	for (int i = 8; i < 15; i++)
		setModuleBounded(qrcode, 8, qrsize - 15 + i, getBit(bits, i));
	setModuleBounded(qrcode, 8, qrsize - 8, true);  // Always dark
}


// Calculates and stores an ascending list of positions of alignment patterns
// for this version number, returning the length of the list (in the range [0,7]).
// Each position is in the range [0,177), and are used on both the x and y axes.
// This could be implemented as lookup table of 40 variable-length lists of unsigned bytes.
testable int getAlignmentPatternPositions(int version, uint8_t result[7]) {
	if (version == 1)
		return 0;
	int numAlign = version / 7 + 2;
	int step = (version * 8 + numAlign * 3 + 5) / (numAlign * 4 - 4) * 2;
	for (int i = numAlign - 1, pos = version * 4 + 10; i >= 1; i--, pos -= step)
		result[i] = (uint8_t)pos;
	result[0] = 6;
	return numAlign;
}


// Sets every module in the range [left : left + width] * [top : top + height] to dark.
static void fillRectangle(int left, int top, int width, int height, uint8_t qrcode[]) {
	for (int dy = 0; dy < height; dy++) {
		for (int dx = 0; dx < width; dx++)
			setModuleBounded(qrcode, left + dx, top + dy, true);
	}
}



/*---- Drawing data modules and masking ----*/

// Draws the raw codewords (including data and ECC) onto the given QR Code. This requires the initial state of
// the QR Code to be dark at function modules and light at codeword modules (including unused remainder bits).
static void drawCodewords(const uint8_t data[], int dataLen, uint8_t qrcode[]) {
	int qrsize = qrcodegen_getSize(qrcode);
	int i = 0;  // Bit index into the data
	// Do the funny zigzag scan
	for (int right = qrsize - 1; right >= 1; right -= 2) {  // Index of right column in each column pair
		if (right == 6)
			right = 5;
		for (int vert = 0; vert < qrsize; vert++) {  // Vertical counter
			for (int j = 0; j < 2; j++) {
				int x = right - j;  // Actual x coordinate
				bool upward = ((right + 1) & 2) == 0;
				int y = upward ? qrsize - 1 - vert : vert;  // Actual y coordinate
				if (!getModuleBounded(qrcode, x, y) && i < dataLen * 8) {
					bool dark = getBit(data[i >> 3], 7 - (i & 7));
					setModuleBounded(qrcode, x, y, dark);
					i++;
				}
				// If this QR Code has any remainder bits (0 to 7), they were assigned as
				// 0/false/light by the constructor and are left unchanged by this method
			}
		}
	}
	assert(i == dataLen * 8);
}


// XORs the codeword modules in this QR Code with the given mask pattern
// and given pattern of function modules. The codeword bits must be drawn
// before masking. Due to the arithmetic of XOR, calling applyMask() with
// the same mask value a second time will undo the mask. A final well-formed
// QR Code needs exactly one (not zero, two, etc.) mask applied.
static void applyMask(const uint8_t functionModules[], uint8_t qrcode[], enum qrcodegen_Mask mask) {
	assert(0 <= (int)mask && (int)mask <= 7);  // Disallows qrcodegen_Mask_AUTO
	int qrsize = qrcodegen_getSize(qrcode);
	for (int y = 0; y < qrsize; y++) {
		for (int x = 0; x < qrsize; x++) {
			if (getModuleBounded(functionModules, x, y))
				continue;
			bool invert;
			switch ((int)mask) {
				case 0:  invert = (x + y) % 2 == 0;                    break;
				case 1:  invert = y % 2 == 0;                          break;
				case 2:  invert = x % 3 == 0;                          break;
				case 3:  invert = (x + y) % 3 == 0;                    break;
				case 4:  invert = (x / 3 + y / 2) % 2 == 0;            break;
				case 5:  invert = x * y % 2 + x * y % 3 == 0;          break;
				case 6:  invert = (x * y % 2 + x * y % 3) % 2 == 0;    break;
				case 7:  invert = ((x + y) % 2 + x * y % 3) % 2 == 0;  break;
				default:  assert(false);  return;
			}
			bool val = getModuleBounded(qrcode, x, y);
			setModuleBounded(qrcode, x, y, val ^ invert);
		}
	}
}


// Calculates and returns the penalty score based on state of the given QR Code's current modules.
// This is used by the automatic mask choice algorithm to find the mask pattern that yields the lowest score.
static long getPenaltyScore(const uint8_t qrcode[]) {
	int qrsize = qrcodegen_getSize(qrcode);
	long result = 0;
	
	// Adjacent modules in row having same color, and finder-like patterns
	for (int y = 0; y < qrsize; y++) {
		bool runColor = false;
		int runX = 0;
		int runHistory[7] = {0};
		for (int x = 0; x < qrsize; x++) {
			if (getModuleBounded(qrcode, x, y) == runColor) {
				runX++;
				if (runX == 5)
					result += PENALTY_N1;
				else if (runX > 5)
					result++;
			} else {
				finderPenaltyAddHistory(runX, runHistory, qrsize);
				if (!runColor)
					result += finderPenaltyCountPatterns(runHistory, qrsize) * PENALTY_N3;
				runColor = getModuleBounded(qrcode, x, y);
				runX = 1;
			}
		}
		result += finderPenaltyTerminateAndCount(runColor, runX, runHistory, qrsize) * PENALTY_N3;
	}
	// Adjacent modules in column having same color, and finder-like patterns
	for (int x = 0; x < qrsize; x++) {
		bool runColor = false;
		int runY = 0;
		int runHistory[7] = {0};
		for (int y = 0; y < qrsize; y++) {
			if (getModuleBounded(qrcode, x, y) == runColor) {
				runY++;
				if (runY == 5)
					result += PENALTY_N1;
				else if (runY > 5)
					result++;
			} else {
				finderPenaltyAddHistory(runY, runHistory, qrsize);
				if (!runColor)
					result += finderPenaltyCountPatterns(runHistory, qrsize) * PENALTY_N3;
				runColor = getModuleBounded(qrcode, x, y);
				runY = 1;
			}
		}
		result += finderPenaltyTerminateAndCount(runColor, runY, runHistory, qrsize) * PENALTY_N3;
	}
	
	// 2*2 blocks of modules having same color
	for (int y = 0; y < qrsize - 1; y++) {
		for (int x = 0; x < qrsize - 1; x++) {
			bool  color = getModuleBounded(qrcode, x, y);
			if (  color == getModuleBounded(qrcode, x + 1, y) &&
			      color == getModuleBounded(qrcode, x, y + 1) &&
			      color == getModuleBounded(qrcode, x + 1, y + 1))
				result += PENALTY_N2;
		}
	}
	
	// Balance of dark and light modules
	int dark = 0;
	for (int y = 0; y < qrsize; y++) {
		for (int x = 0; x < qrsize; x++) {
			if (getModuleBounded(qrcode, x, y))
				dark++;
		}
	}
	int total = qrsize * qrsize;  // Note that size is odd, so dark/total != 1/2
	// Compute the smallest integer k >= 0 such that (45-5k)% <= dark/total <= (55+5k)%
	int k = (int)((labs(dark * 20L - total * 10L) + total - 1) / total) - 1;
	assert(0 <= k && k <= 9);
	result += k * PENALTY_N4;
	assert(0 <= result && result <= 2568888L);  // Non-tight upper bound based on default values of PENALTY_N1, ..., N4
	return result;
}


// Can only be called immediately after a light run is added, and
// returns either 0, 1, or 2. A helper function for getPenaltyScore().
static int finderPenaltyCountPatterns(const int runHistory[7], int qrsize) {
	int n = runHistory[1];
	assert(n <= qrsize * 3);  (void)qrsize;
	bool core = n > 0 && runHistory[2] == n && runHistory[3] == n * 3 && runHistory[4] == n && runHistory[5] == n;
	// The maximum QR Code size is 177, hence the dark run length n <= 177.
	// Arithmetic is promoted to int, so n*4 will not overflow.
	return (core && runHistory[0] >= n * 4 && runHistory[6] >= n ? 1 : 0)
	     + (core && runHistory[6] >= n * 4 && runHistory[0] >= n ? 1 : 0);
}


// Must be called at the end of a line (row or column) of modules. A helper function for getPenaltyScore().
static int finderPenaltyTerminateAndCount(bool currentRunColor, int currentRunLength, int runHistory[7], int qrsize) {
	if (currentRunColor) {  // Terminate dark run
		finderPenaltyAddHistory(currentRunLength, runHistory, qrsize);
		currentRunLength = 0;
	}
	currentRunLength += qrsize;  // Add light border to final run
	finderPenaltyAddHistory(currentRunLength, runHistory, qrsize);
	return finderPenaltyCountPatterns(runHistory, qrsize);
}


// Pushes the given value to the front and drops the last value. A helper function for getPenaltyScore().
static void finderPenaltyAddHistory(int currentRunLength, int runHistory[7], int qrsize) {
	if (runHistory[0] == 0)
		currentRunLength += qrsize;  // Add light border to initial run
	memmove(&runHistory[1], &runHistory[0], 6 * sizeof(runHistory[0]));
	runHistory[0] = currentRunLength;
}



/*---- Basic QR Code information ----*/

// Public function - see documentation comment in header file.
int qrcodegen_getSize(const uint8_t qrcode[]) {
	assert(qrcode != NULL);
	int result = qrcode[0];
	assert((qrcodegen_VERSION_MIN * 4 + 17) <= result
		&& result <= (qrcodegen_VERSION_MAX * 4 + 17));
	return result;
}


// Public function - see documentation comment in header file.
bool qrcodegen_getModule(const uint8_t qrcode[], int x, int y) {
	assert(qrcode != NULL);
	int qrsize = qrcode[0];
	return (0 <= x && x < qrsize && 0 <= y && y < qrsize) && getModuleBounded(qrcode, x, y);
}


// Returns the color of the module at the given coordinates, which must be in bounds.
testable bool getModuleBounded(const uint8_t qrcode[], int x, int y) {
	int qrsize = qrcode[0];
	assert(21 <= qrsize && qrsize <= 177 && 0 <= x && x < qrsize && 0 <= y && y < qrsize);
	int index = y * qrsize + x;
	return getBit(qrcode[(index >> 3) + 1], index & 7);
}


// Sets the color of the module at the given coordinates, which must be in bounds.
testable void setModuleBounded(uint8_t qrcode[], int x, int y, bool isDark) {
	int qrsize = qrcode[0];
	assert(21 <= qrsize && qrsize <= 177 && 0 <= x && x < qrsize && 0 <= y && y < qrsize);
	int index = y * qrsize + x;
	int bitIndex = index & 7;
	int byteIndex = (index >> 3) + 1;
	if (isDark)
		qrcode[byteIndex] |= 1 << bitIndex;
	else
		qrcode[byteIndex] &= (1 << bitIndex) ^ 0xFF;
}


// Sets the color of the module at the given coordinates, doing nothing if out of bounds.
testable void setModuleUnbounded(uint8_t qrcode[], int x, int y, bool isDark) {
	int qrsize = qrcode[0];
	if (0 <= x && x < qrsize && 0 <= y && y < qrsize)
		setModuleBounded(qrcode, x, y, isDark);
}


// Returns true iff the i'th bit of x is set to 1. Requires x >= 0 and 0 <= i <= 14.
static bool getBit(int x, int i) {
	return ((x >> i) & 1) != 0;
}



/*---- Segment handling ----*/

// Public function - see documentation comment in header file.
bool qrcodegen_isNumeric(const char *text) {
	assert(text != NULL);
	for (; *text != '\0'; text++) {
		if (*text < '0' || *text > '9')
			return false;
	}
	return true;
}


// Public function - see documentation comment in header file.
bool qrcodegen_isAlphanumeric(const char *text) {
	assert(text != NULL);
	for (; *text != '\0'; text++) {
		if (strchr(ALPHANUMERIC_CHARSET, *text) == NULL)
			return false;
	}
	return true;
}


// Public function - see documentation comment in header file.
size_t qrcodegen_calcSegmentBufferSize(enum qrcodegen_Mode mode, size_t numChars) {
	int temp = calcSegmentBitLength(mode, numChars);
	if (temp == LENGTH_OVERFLOW)
		return SIZE_MAX;
	assert(0 <= temp && temp <= INT16_MAX);
	return ((size_t)temp + 7) / 8;
}


// Returns the number of data bits needed to represent a segment
// containing the given number of characters using the given mode. Notes:
// - Returns LENGTH_OVERFLOW on failure, i.e. numChars > INT16_MAX
//   or the number of needed bits exceeds INT16_MAX (i.e. 32767).
// - Otherwise, all valid results are in the range [0, INT16_MAX].
// - For byte mode, numChars measures the number of bytes, not Unicode code points.
// - For ECI mode, numChars must be 0, and the worst-case number of bits is returned.
//   An actual ECI segment can have shorter data. For non-ECI modes, the result is exact.
testable int calcSegmentBitLength(enum qrcodegen_Mode mode, size_t numChars) {
	// All calculations are designed to avoid overflow on all platforms
	if (numChars > (unsigned int)INT16_MAX)
		return LENGTH_OVERFLOW;
	long result = (long)numChars;
	if (mode == qrcodegen_Mode_NUMERIC)
		result = (result * 10 + 2) / 3;  // ceil(10/3 * n)
	else if (mode == qrcodegen_Mode_ALPHANUMERIC)
		result = (result * 11 + 1) / 2;  // ceil(11/2 * n)
	else if (mode == qrcodegen_Mode_BYTE)
		result *= 8;
	else if (mode == qrcodegen_Mode_KANJI)
		result *= 13;
	else if (mode == qrcodegen_Mode_ECI && numChars == 0)
		result = 3 * 8;
	else {  // Invalid argument
		assert(false);
		return LENGTH_OVERFLOW;
	}
	assert(result >= 0);
	if (result > INT16_MAX)
		return LENGTH_OVERFLOW;
	return (int)result;
}


// Public function - see documentation comment in header file.
struct qrcodegen_Segment qrcodegen_makeBytes(const uint8_t data[], size_t len, uint8_t buf[]) {
	assert(data != NULL || len == 0);
	struct qrcodegen_Segment result;
	result.mode = qrcodegen_Mode_BYTE;
	result.bitLength = calcSegmentBitLength(result.mode, len);
	assert(result.bitLength != LENGTH_OVERFLOW);
	result.numChars = (int)len;
	if (len > 0)
		memcpy(buf, data, len * sizeof(buf[0]));
	result.data = buf;
	return result;
}


// Public function - see documentation comment in header file.
struct qrcodegen_Segment qrcodegen_makeNumeric(const char *digits, uint8_t buf[]) {
	assert(digits != NULL);
	struct qrcodegen_Segment result;
	size_t len = strlen(digits);
	result.mode = qrcodegen_Mode_NUMERIC;
	int bitLen = calcSegmentBitLength(result.mode, len);
	assert(bitLen != LENGTH_OVERFLOW);
	result.numChars = (int)len;
	if (bitLen > 0)
		memset(buf, 0, ((size_t)bitLen + 7) / 8 * sizeof(buf[0]));
	result.bitLength = 0;
	
	unsigned int accumData = 0;
	int accumCount = 0;
	for (; *digits != '\0'; digits++) {
		char c = *digits;
		assert('0' <= c && c <= '9');
		accumData = accumData * 10 + (unsigned int)(c - '0');
		accumCount++;
		if (accumCount == 3) {
			appendBitsToBuffer(accumData, 10, buf, &result.bitLength);
			accumData = 0;
			accumCount = 0;
		}
	}
	if (accumCount > 0)  // 1 or 2 digits remaining
		appendBitsToBuffer(accumData, accumCount * 3 + 1, buf, &result.bitLength);
	assert(result.bitLength == bitLen);
	result.data = buf;
	return result;
}


// Public function - see documentation comment in header file.
struct qrcodegen_Segment qrcodegen_makeAlphanumeric(const char *text, uint8_t buf[]) {
	assert(text != NULL);
	struct qrcodegen_Segment result;
	size_t len = strlen(text);
	result.mode = qrcodegen_Mode_ALPHANUMERIC;
	int bitLen = calcSegmentBitLength(result.mode, len);
	assert(bitLen != LENGTH_OVERFLOW);
	result.numChars = (int)len;
	if (bitLen > 0)
		memset(buf, 0, ((size_t)bitLen + 7) / 8 * sizeof(buf[0]));
	result.bitLength = 0;
	
	unsigned int accumData = 0;
	int accumCount = 0;
	for (; *text != '\0'; text++) {
		const char *temp = strchr(ALPHANUMERIC_CHARSET, *text);
		assert(temp != NULL);
		accumData = accumData * 45 + (unsigned int)(temp - ALPHANUMERIC_CHARSET);
		accumCount++;
		if (accumCount == 2) {
			appendBitsToBuffer(accumData, 11, buf, &result.bitLength);
			accumData = 0;
			accumCount = 0;
		}
	}
	if (accumCount > 0)  // 1 character remaining
		appendBitsToBuffer(accumData, 6, buf, &result.bitLength);
	assert(result.bitLength == bitLen);
	result.data = buf;
	return result;
}


// Public function - see documentation comment in header file.
struct qrcodegen_Segment qrcodegen_makeEci(long assignVal, uint8_t buf[]) {
	struct qrcodegen_Segment result;
	result.mode = qrcodegen_Mode_ECI;
	result.numChars = 0;
	result.bitLength = 0;
	if (assignVal < 0)
		assert(false);
	else if (assignVal < (1 << 7)) {
		memset(buf, 0, 1 * sizeof(buf[0]));
		appendBitsToBuffer((unsigned int)assignVal, 8, buf, &result.bitLength);
	} else if (assignVal < (1 << 14)) {
		memset(buf, 0, 2 * sizeof(buf[0]));
		appendBitsToBuffer(2, 2, buf, &result.bitLength);
		appendBitsToBuffer((unsigned int)assignVal, 14, buf, &result.bitLength);
	} else if (assignVal < 1000000L) {
		memset(buf, 0, 3 * sizeof(buf[0]));
		appendBitsToBuffer(6, 3, buf, &result.bitLength);
		appendBitsToBuffer((unsigned int)(assignVal >> 10), 11, buf, &result.bitLength);
		appendBitsToBuffer((unsigned int)(assignVal & 0x3FF), 10, buf, &result.bitLength);
	} else
		assert(false);
	result.data = buf;
	return result;
}


// Calculates the number of bits needed to encode the given segments at the given version.
// Returns a non-negative number if successful. Otherwise returns LENGTH_OVERFLOW if a segment
// has too many characters to fit its length field, or the total bits exceeds INT16_MAX.
testable int getTotalBits(const struct qrcodegen_Segment segs[], size_t len, int version) {
	assert(segs != NULL || len == 0);
	long result = 0;
	for (size_t i = 0; i < len; i++) {
		int numChars  = segs[i].numChars;
		int bitLength = segs[i].bitLength;
		assert(0 <= numChars  && numChars  <= INT16_MAX);
		assert(0 <= bitLength && bitLength <= INT16_MAX);
		int ccbits = numCharCountBits(segs[i].mode, version);
		assert(0 <= ccbits && ccbits <= 16);
		if (numChars >= (1L << ccbits))
			return LENGTH_OVERFLOW;  // The segment's length doesn't fit the field's bit width
		result += 4L + ccbits + bitLength;
		if (result > INT16_MAX)
			return LENGTH_OVERFLOW;  // The sum might overflow an int type
	}
	assert(0 <= result && result <= INT16_MAX);
	return (int)result;
}


// Returns the bit width of the character count field for a segment in the given mode
// in a QR Code at the given version number. The result is in the range [0, 16].
static int numCharCountBits(enum qrcodegen_Mode mode, int version) {
	assert(qrcodegen_VERSION_MIN <= version && version <= qrcodegen_VERSION_MAX);
	int i = (version + 7) / 17;
	switch (mode) {
		case qrcodegen_Mode_NUMERIC     : { static const int temp[] = {10, 12, 14}; return temp[i]; }
		case qrcodegen_Mode_ALPHANUMERIC: { static const int temp[] = { 9, 11, 13}; return temp[i]; }
		case qrcodegen_Mode_BYTE        : { static const int temp[] = { 8, 16, 16}; return temp[i]; }
		case qrcodegen_Mode_KANJI       : { static const int temp[] = { 8, 10, 12}; return temp[i]; }
		case qrcodegen_Mode_ECI         : return 0;
		default:  assert(false);  return -1;  // Dummy value
	}
}


#undef LENGTH_OVERFLOW

/* ===================================================================== */
/*  Utilitaires                                                          */
/* ===================================================================== */

static double mono_now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static time_t wall_now(void)
{
    return time(NULL);
}

static void secure_zero(void *p, size_t n)
{
    if (p && n)
        OPENSSL_cleanse(p, n);
}

static void fmt_bytes(uint64_t n, char *out, size_t cap)
{
    static const char *units[] = { "o", "Ko", "Mo", "Go", "To" };
    double v = (double)n;
    int u = 0;
    while (v >= 1024.0 && u < 4) {
        v /= 1024.0;
        u++;
    }
    if (u == 0)
        snprintf(out, cap, "%llu o", (unsigned long long)n);
    else
        snprintf(out, cap, "%.2f %s", v, units[u]);
}

static void fmt_duration(uint64_t secs, char *out, size_t cap)
{
    if (secs >= 3600)
        snprintf(out, cap, "%lluh %02llum", (unsigned long long)(secs / 3600),
                 (unsigned long long)((secs % 3600) / 60));
    else
        snprintf(out, cap, "%02llu:%02llu", (unsigned long long)(secs / 60),
                 (unsigned long long)(secs % 60));
}

static void fmt_speed(uint64_t bps, char *out, size_t cap)
{
    char b[32];
    fmt_bytes(bps, b, sizeof b);
    snprintf(out, cap, "%s/s", b);
}

static void hex_encode(const uint8_t *in, size_t n, char *out)
{
    static const char h[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[i * 2] = h[in[i] >> 4];
        out[i * 2 + 1] = h[in[i] & 15];
    }
    out[n * 2] = '\0';
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_decode(const char *in, uint8_t *out, size_t n)
{
    if (strlen(in) != n * 2)
        return -1;
    for (size_t i = 0; i < n; i++) {
        int a = hex_nibble(in[i * 2]), b = hex_nibble(in[i * 2 + 1]);
        if (a < 0 || b < 0) return -1;
        out[i] = (uint8_t)((a << 4) | b);
    }
    return 0;
}

static int sys_random(void *dst, size_t n)
{
    uint8_t *p = (uint8_t *)dst;
    size_t got = 0;
    while (got < n) {
        ssize_t r = getrandom(p + got, n - got, 0);
        if (r > 0) {
            got += (size_t)r;
            continue;
        }
        if (r < 0 && errno == EINTR)
            continue;
        break;
    }
    if (got == n)
        return 0;
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f)
        return -1;
    size_t r = fread(p + got, 1, n - got, f);
    fclose(f);
    return r == n - got ? 0 : -1;
}

static size_t url_encode(const char *in, char *out, size_t cap)
{
    static const char h[] = "0123456789ABCDEF";
    size_t o = 0;
    if (cap == 0) return 0;
    for (const unsigned char *p = (const unsigned char *)in; *p; p++) {
        unsigned char c = *p;
        int safe = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                   (c >= '0' && c <= '9') || c == '-' || c == '.' ||
                   c == '_' || c == '~';
        if (safe) {
            if (o + 1 >= cap) break;
            out[o++] = (char)c;
        } else {
            if (o + 3 >= cap) break;
            out[o++] = '%';
            out[o++] = h[c >> 4];
            out[o++] = h[c & 15];
        }
    }
    out[o] = '\0';
    return o;
}

static void url_decode_inplace(char *s)
{
    char *w = s;
    for (char *p = s; *p; p++) {
        if (*p == '%' && p[1] && p[2]) {
            int a = hex_nibble(p[1]), b = hex_nibble(p[2]);
            if (a >= 0 && b >= 0) {
                *w++ = (char)((a << 4) | b);
                p += 2;
                continue;
            }
        }
        if (*p == '+') {
            *w++ = ' ';
            continue;
        }
        *w++ = *p;
    }
    *w = '\0';
}

static const char *path_basename(const char *p)
{
    const char *s = strrchr(p, '/');
    return s ? s + 1 : p;
}

static void join_path(char *out, size_t cap, const char *a, const char *b)
{
    size_t al = strlen(a), bl = strlen(b);
    if (al >= cap) al = cap - 1;
    memcpy(out, a, al);
    out[al] = '\0';
    size_t o = al;
    if (o + 1 < cap) {
        out[o++] = '/';
        out[o] = '\0';
    }
    size_t rem = cap - o - 1;
    if (bl > rem) bl = rem;
    memcpy(out + o, b, bl);
    out[o + bl] = '\0';
}

static void copy_path(char *out, size_t cap, const char *in)
{
    size_t n = strlen(in);
    if (n >= cap) n = cap - 1;
    memcpy(out, in, n);
    out[n] = '\0';
}

static const char *home_dir(void)
{
    const char *h = getenv("HOME");
    return (h && *h) ? h : "/";
}

static void default_download_dir(char *out, size_t cap)
{
    const char *home = home_dir();
    static const char *cands[] = {
        "Downloads", "Téléchargements", "Téléchargement", "downloads"
    };
    for (size_t i = 0; i < sizeof cands / sizeof cands[0]; i++) {
        struct stat st;
        snprintf(out, cap, "%s/%s", home, cands[i]);
        if (stat(out, &st) == 0 && S_ISDIR(st.st_mode))
            return;
    }
    snprintf(out, cap, "%s", home);
}

static int ensure_dir(const char *path)
{
    char tmp[PATH_MAX];
    size_t n = strlen(path);
    if (n == 0 || n >= sizeof tmp)
        return -1;
    memcpy(tmp, path, n + 1);
    if (n > 1 && tmp[n - 1] == '/')
        tmp[n - 1] = '\0';
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0755) < 0 && errno != EEXIST)
                return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, 0755) < 0 && errno != EEXIST)
        return -1;
    return 0;
}

static void sanitize_filename(const char *in, char *out, size_t cap)
{
    const char *base = path_basename(in);
    size_t o = 0;
    for (const unsigned char *p = (const unsigned char *)base; *p && o + 1 < cap && o < MAX_NAME; p++) {
        unsigned char c = *p;
        if (c == '/' || c == '\\' || c < 32 || c == 127)
            c = '_';
        out[o++] = (char)c;
    }
    while (o > 0 && ((unsigned char)out[o - 1] & 0xC0) == 0x80)
        o--;
    out[o] = '\0';
    if (o == 0 || strcmp(out, ".") == 0 || strcmp(out, "..") == 0)
        snprintf(out, cap, "fichier-recu");
}

static void str_append(char *dst, size_t cap, const char *src);

static void unique_path(const char *dir, const char *name, char *out, size_t cap)
{
    char base[MAX_NAME + 1], ext[64];
    base[0] = '\0';
    ext[0] = '\0';
    const char *dot = strrchr(name, '.');
    if (dot && dot != name) {
        size_t bl = (size_t)(dot - name);
        if (bl >= sizeof base) bl = sizeof base - 1;
        memcpy(base, name, bl);
        base[bl] = '\0';
        snprintf(ext, sizeof ext, "%s", dot);
    } else {
        snprintf(base, sizeof base, "%s", name);
    }
    for (int i = 0; i < 1000; i++) {
        if (i == 0) {
            join_path(out, cap, dir, name);
        } else {
            char nm[MAX_NAME + 48];
            snprintf(nm, sizeof nm, "%s (%d)%s", base, i, ext);
            join_path(out, cap, dir, nm);
        }
        struct stat st;
        char part[PATH_MAX];
        copy_path(part, sizeof part, out);
        str_append(part, sizeof part, ".part");
        if (stat(out, &st) != 0 && stat(part, &st) != 0)
            return;
    }
}

static void local_ipv4(char *out, size_t cap)
{
    out[0] = '\0';
    struct ifaddrs *ifs = NULL;
    if (getifaddrs(&ifs) != 0)
        return;
    int best_score = -1;
    for (struct ifaddrs *i = ifs; i; i = i->ifa_next) {
        if (!i->ifa_addr || i->ifa_addr->sa_family != AF_INET)
            continue;
        if (!(i->ifa_flags & IFF_UP) || (i->ifa_flags & IFF_LOOPBACK))
            continue;
        const char *nm = i->ifa_name ? i->ifa_name : "";
        if (strncmp(nm, "lo", 2) == 0 || strncmp(nm, "docker", 6) == 0 ||
            strncmp(nm, "veth", 4) == 0 || strncmp(nm, "br-", 3) == 0 ||
            strncmp(nm, "virbr", 5) == 0 || strncmp(nm, "tun", 3) == 0 ||
            strncmp(nm, "tap", 3) == 0)
            continue;
        int score = 1;
        if (strncmp(nm, "en", 2) == 0 || strncmp(nm, "eth", 3) == 0) score = 5;
        else if (strncmp(nm, "wl", 2) == 0) score = 6;
        if (score <= best_score)
            continue;
        char host[NI_MAXHOST];
        if (getnameinfo(i->ifa_addr, sizeof(struct sockaddr_in), host,
                        sizeof host, NULL, 0, NI_NUMERICHOST) == 0) {
            size_t hl = strlen(host);
            if (hl >= cap) hl = cap - 1;
            memcpy(out, host, hl);
            out[hl] = '\0';
            best_score = score;
        }
    }
    freeifaddrs(ifs);
    if (!out[0])
        snprintf(out, cap, "127.0.0.1");
}

static void format_time_short(time_t t, char *out, size_t cap)
{
    struct tm tm;
    localtime_r(&t, &tm);
    strftime(out, cap, "%d/%m %H:%M", &tm);
}

/* ===================================================================== */
/*  Champs de texte                                                      */
/* ===================================================================== */

#define TF_CAP 1024

typedef struct {
    char buf[TF_CAP];
    int len;
    int cursor;
    bool focused;
} TextField;

static void tf_set(TextField *t, const char *s)
{
    memset(t, 0, sizeof *t);
    if (!s) return;
    size_t n = strlen(s);
    if (n >= TF_CAP) n = TF_CAP - 1;
    memcpy(t->buf, s, n);
    t->buf[n] = '\0';
    t->len = (int)n;
    t->cursor = (int)n;
}

static void tf_clear(TextField *t)
{
    memset(t, 0, sizeof *t);
}

static int utf8_prev(const char *s, int pos)
{
    if (pos <= 0) return 0;
    int i = pos - 1;
    while (i > 0 && ((unsigned char)s[i] & 0xC0) == 0x80)
        i--;
    return i;
}

static int utf8_next(const char *s, int len, int pos)
{
    if (pos >= len) return len;
    int i = pos + 1;
    while (i < len && ((unsigned char)s[i] & 0xC0) == 0x80)
        i++;
    return i;
}

static int utf8_count(const char *s, int bytes)
{
    int n = 0;
    for (int i = 0; i < bytes; i++)
        if (((unsigned char)s[i] & 0xC0) != 0x80)
            n++;
    return n;
}

static void tf_insert_cp(TextField *t, int cp)
{
    if (cp < 32 || cp == 127)
        return;
    int sz = 0;
    const char *u = CodepointToUTF8(cp, &sz);
    if (!u || sz <= 0 || t->len + sz >= TF_CAP)
        return;
    memmove(t->buf + t->cursor + sz, t->buf + t->cursor, (size_t)(t->len - t->cursor + 1));
    memcpy(t->buf + t->cursor, u, (size_t)sz);
    t->len += sz;
    t->cursor += sz;
}

static void tf_backspace(TextField *t)
{
    if (t->cursor <= 0) return;
    int p = utf8_prev(t->buf, t->cursor);
    int n = t->cursor - p;
    memmove(t->buf + p, t->buf + t->cursor, (size_t)(t->len - t->cursor + 1));
    t->len -= n;
    t->cursor = p;
}

static void tf_delete(TextField *t)
{
    if (t->cursor >= t->len) return;
    int n = utf8_next(t->buf, t->len, t->cursor);
    memmove(t->buf + t->cursor, t->buf + n, (size_t)(t->len - n + 1));
    t->len -= n - t->cursor;
}

static void tf_insert_text(TextField *t, const char *s)
{
    while (s && *s) {
        int sz = 0;
        int cp = GetCodepointNext(s, &sz);
        if (cp >= 32 && cp != 127)
            tf_insert_cp(t, cp);
        s += sz > 0 ? sz : 1;
    }
}

/* Retourne 1 si modifié, 2 si Entrée pressée. */
static int tf_update(TextField *t)
{
    if (!t->focused)
        return 0;
    int changed = 0;
    int cp;
    while ((cp = GetCharPressed()) != 0) {
        if (cp >= 32 && cp != 127) {
            tf_insert_cp(t, cp);
            changed = 1;
        }
    }
    bool ctrl = IsKeyDown(KEY_LEFT_CONTROL) || IsKeyDown(KEY_RIGHT_CONTROL) ||
                IsKeyDown(KEY_LEFT_SUPER) || IsKeyDown(KEY_RIGHT_SUPER);
    if (ctrl && IsKeyPressed(KEY_V)) {
        const char *clip = GetClipboardText();
        if (clip) {
            tf_insert_text(t, clip);
            changed = 1;
        }
    }
    if (IsKeyPressed(KEY_BACKSPACE) || IsKeyPressedRepeat(KEY_BACKSPACE)) {
        tf_backspace(t);
        changed = 1;
    }
    if (IsKeyPressed(KEY_DELETE) || IsKeyPressedRepeat(KEY_DELETE)) {
        tf_delete(t);
        changed = 1;
    }
    if (IsKeyPressed(KEY_LEFT) || IsKeyPressedRepeat(KEY_LEFT)) {
        t->cursor = utf8_prev(t->buf, t->cursor);
    }
    if (IsKeyPressed(KEY_RIGHT) || IsKeyPressedRepeat(KEY_RIGHT)) {
        t->cursor = utf8_next(t->buf, t->len, t->cursor);
    }
    if (IsKeyPressed(KEY_HOME)) t->cursor = 0;
    if (IsKeyPressed(KEY_END)) t->cursor = t->len;
    if (IsKeyPressed(KEY_ENTER)) return 2;
    return changed ? 1 : 0;
}

/* ===================================================================== */
/*  État des tâches (thread de transfert <-> interface)                  */
/* ===================================================================== */

typedef enum {
    JOB_IDLE = 0,
    JOB_PREPARING,
    JOB_WAITING,
    JOB_CONNECTING,
    JOB_HANDSHAKE,
    JOB_TRANSFER,
    JOB_FINALIZING,
    JOB_DONE,
    JOB_ERROR,
    JOB_CANCELLED
} JobPhase;

typedef struct {
    pthread_mutex_t mu;
    JobPhase phase;
    int running;
    int is_send;
    int result;                 /* 1 ok, -1 erreur, -2 annulé */
    char status[256];
    char detail[256];
    char filename[256];
    char savepath[PATH_MAX];
    char remote[128];
    uint64_t total;
    uint64_t done;
    uint64_t speed;
    double t0;
    double speed_t0;            /* début de la mesure de débit (transfert) */
    uint64_t speed_base;        /* octets déjà comptés à speed_t0 */
    uint64_t expires_at;
    int listen_port;
    int history_logged;
    atomic_int cancel;
} Job;

static void job_init(Job *j)
{
    memset(j, 0, sizeof *j);
    pthread_mutex_init(&j->mu, NULL);
    atomic_init(&j->cancel, 0);
    j->phase = JOB_IDLE;
}

static void job_lock(Job *j) { pthread_mutex_lock(&j->mu); }
static void job_unlock(Job *j) { pthread_mutex_unlock(&j->mu); }

static int job_cancelled(Job *j)
{
    return atomic_load_explicit(&j->cancel, memory_order_relaxed) != 0;
}

static void job_request_cancel(Job *j)
{
    atomic_store_explicit(&j->cancel, 1, memory_order_relaxed);
}

static void job_begin(Job *j, int is_send)
{
    job_lock(j);
    j->phase = JOB_PREPARING;
    j->running = 1;
    j->is_send = is_send;
    j->result = 0;
    j->total = 0;
    j->done = 0;
    j->speed = 0;
    j->t0 = mono_now();
    j->speed_t0 = 0.0;
    j->speed_base = 0;
    j->expires_at = 0;
    j->listen_port = 0;
    j->history_logged = 0;
    j->status[0] = j->detail[0] = j->filename[0] = j->savepath[0] = j->remote[0] = '\0';
    atomic_store_explicit(&j->cancel, 0, memory_order_relaxed);
    job_unlock(j);
}

static void job_set(Job *j, JobPhase ph, const char *fmt, ...)
{
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    job_lock(j);
    j->phase = ph;
    snprintf(j->status, sizeof j->status, "%s", buf);
    job_unlock(j);
}

static void job_detail(Job *j, const char *fmt, ...)
{
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    job_lock(j);
    snprintf(j->detail, sizeof j->detail, "%s", buf);
    job_unlock(j);
}

static void job_prog(Job *j, uint64_t done, uint64_t total)
{
    double now = mono_now();
    job_lock(j);
    if (j->speed_t0 <= 0.0) {
        /* Le débit ne doit pas inclure l'attente du destinataire ni la
         * négociation : la mesure démarre au premier octet transféré. */
        j->speed_t0 = now;
        j->speed_base = done > 0 ? 0 : done;
    }
    j->done = done;
    j->total = total;
    double el = now - j->speed_t0;
    if (el > 0.001)
        j->speed = (uint64_t)((double)(done - j->speed_base) / el);
    job_unlock(j);
}

static void job_end(Job *j)
{
    job_lock(j);
    j->running = 0;
    job_unlock(j);
}

/* ===================================================================== */
/*  Invitations                                                          */
/* ===================================================================== */

typedef struct {
    uint8_t id[INVITE_ID_LEN];
    uint8_t token[TOKEN_LEN];
    uint8_t key[KEY_LEN];
    uint8_t room[INVITE_ID_LEN];
    uint8_t auth[HMAC_LEN];
    int has_key;
    int has_password;
    int pw_unknown;
    char host[256];
    int port;
    uint64_t expires_at;

    /* Transport WebRTC */
    int transport;                 /* TRANSPORT_TCP ou TRANSPORT_WEBRTC */
    char code[CODE_LEN + 1];       /* code de partage normalisé */
    char signal[256];              /* hôte:port du serveur PeerJS */
    char signal_host[200];
    int signal_port;
    int sig_peerjs;                /* 1 = PeerJS Cloud, 0 = ancien relais local */
    char stun[256];
} Invite;

static void invite_random(Invite *v)
{
    memset(v, 0, sizeof *v);
    sys_random(v->id, sizeof v->id);
    sys_random(v->token, sizeof v->token);
    sys_random(v->key, sizeof v->key);
    v->has_key = 1;
    v->port = 45871;
    v->transport = TRANSPORT_TCP;
    v->sig_peerjs = 1;
}

/* --------------------------------------------------------------------- */
/*  Code de partage WebRTC                                               */
/* --------------------------------------------------------------------- */

/* Alphabet Crockford base32 : pas de I, L, O ni U (confusions fréquentes). */
static const char CODE_ALPHABET[] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

static const char *signal_default(void)
{
    const char *e = getenv("SILLAGE_PEERJS");
    if (!e || !*e)
        e = getenv("SILLAGE_SIGNAL");
    return (e && *e) ? e : SIGNAL_DEFAULT;
}

static const char *stun_default(void)
{
    const char *e = getenv("SILLAGE_STUN");
    return (e && *e) ? e : STUN_DEFAULT;
}

static void code_random(char out[CODE_LEN + 1])
{
    uint8_t rnd[8];
    if (sys_random(rnd, sizeof rnd) != 0) {
        /* Repli : le générateur système est indispensable, mais on évite
         * de laisser un code vide si /dev/urandom est momentanément absent. */
        uint64_t t = (uint64_t)mono_now() ^ (uint64_t)getpid();
        memcpy(rnd, &t, sizeof t);
    }
    uint64_t bits = 0;
    for (int i = 0; i < 8; i++)
        bits = (bits << 8) | rnd[i];
    for (int i = 0; i < CODE_LEN; i++) {
        int shift = 64 - 5 * (i + 1);
        out[i] = CODE_ALPHABET[(bits >> shift) & 31u];
    }
    out[CODE_LEN] = '\0';
    secure_zero(rnd, sizeof rnd);
}

/* Accepte minuscules, espaces, tirets et les confusions Crockford I/L/O/U. */
static int code_normalize(const char *in, char out[CODE_LEN + 1])
{
    if (!in) return -1;
    int n = 0;
    for (const unsigned char *p = (const unsigned char *)in; *p; p++) {
        int c = *p;
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '-' || c == '_')
            continue;
        if (c >= 'a' && c <= 'z') c -= 'a' - 'A';
        if (c == 'I' || c == 'L') c = '1';
        if (c == 'O') c = '0';
        if (c == 'U') c = 'V';
        if (!strchr(CODE_ALPHABET, c)) return -1;
        if (n >= CODE_LEN) return -1;
        out[n++] = (char)c;
    }
    out[n] = '\0';
    return n == CODE_LEN ? 0 : -1;
}

static void code_format(const char *code, char *out, size_t cap)
{
    if (!code || strlen(code) != CODE_LEN) {
        snprintf(out, cap, "%s", code ? code : "");
        return;
    }
    snprintf(out, cap, "%.5s-%.5s", code, code + 5);
}

/*
 * Dérive tout le matériel d'une session WebRTC à partir du code.
 *
 * scrypt rend une attaque hors ligne sur les 50 bits du code inexploitable
 * pour un serveur de signalisation curieux : il ne voit que l'identifiant de
 * salle (room) et les SDP, jamais le code ni les clés.
 */
static int code_derive(const char *code,
                       uint8_t room[INVITE_ID_LEN], uint8_t id[INVITE_ID_LEN],
                       uint8_t token[TOKEN_LEN], uint8_t auth[HMAC_LEN],
                       uint8_t key[KEY_LEN])
{
    char norm[CODE_LEN + 1];
    if (code_normalize(code, norm) != 0)
        return -1;
    static const char salt[] = "SILLAGE-WEBRTC-v2";
    uint8_t out[INVITE_ID_LEN * 3 + HMAC_LEN + KEY_LEN];
    int ok = EVP_PBE_scrypt(norm, CODE_LEN, (const unsigned char *)salt, sizeof salt - 1,
                            1u << 15, 8, 1, 64u * 1024u * 1024u, out, sizeof out);
    secure_zero(norm, sizeof norm);
    if (ok != 1)
        return -1;
    memcpy(room, out, INVITE_ID_LEN);
    memcpy(id, out + INVITE_ID_LEN, INVITE_ID_LEN);
    memcpy(token, out + INVITE_ID_LEN * 2, TOKEN_LEN);
    memcpy(auth, out + INVITE_ID_LEN * 3, HMAC_LEN);
    memcpy(key, out + INVITE_ID_LEN * 3 + HMAC_LEN, KEY_LEN);
    secure_zero(out, sizeof out);
    return 0;
}

static int invite_set_code(Invite *v, const char *code)
{
    char norm[CODE_LEN + 1];
    if (code_normalize(code, norm) != 0)
        return -1;
    if (code_derive(norm, v->room, v->id, v->token, v->auth, v->key) != 0)
        return -1;
    snprintf(v->code, sizeof v->code, "%s", norm);
    v->transport = TRANSPORT_WEBRTC;
    v->has_key = 1;
    v->sig_peerjs = 1;
    return 0;
}

static void invite_set_signal(Invite *v, const char *server)
{
    if (!server || !*server)
        server = signal_default();
    snprintf(v->signal, sizeof v->signal, "%s", server);

    char host[200];
    int port = SIGNAL_DEFAULT_PORT;
    snprintf(host, sizeof host, "%s", server);

    if (host[0] == '[') {
        char *close = strchr(host, ']');
        if (close) {
            *close = '\0';
            memmove(host, host + 1, strlen(host));
            if (close[1] == ':' && close[2]) {
                long p = strtol(close + 2, NULL, 10);
                if (p > 0 && p <= 65535) port = (int)p;
            }
        }
    } else {
        char *colon = strrchr(host, ':');
        if (colon && strchr(host, ':') == colon) {
            *colon = '\0';
            long p = strtol(colon + 1, NULL, 10);
            if (p > 0 && p <= 65535)
                port = (int)p;
        }
    }
    if (!host[0])
        snprintf(host, sizeof host, "127.0.0.1");
    snprintf(v->signal_host, sizeof v->signal_host, "%s", host);
    v->signal_port = port;
}

static void str_append(char *dst, size_t cap, const char *src)
{
    size_t d = strlen(dst), s = strlen(src);
    if (d + s >= cap)
        s = cap - d - 1;
    memcpy(dst + d, src, s);
    dst[d + s] = '\0';
}

static void invite_build_link(const Invite *v, char *out, size_t cap)
{
    if (v->transport == TRANSPORT_WEBRTC) {
        char sig[1024], stun[768];
        url_encode(v->signal, sig, sizeof sig);
        url_encode(v->stun, stun, sizeof stun);
        snprintf(out, cap, LINK_PREFIX_V2 "m=w&s=%s&st=%s&e=%llu&pw=%d#c=%s",
                 sig, stun, (unsigned long long)v->expires_at,
                 v->has_password ? 1 : 0, v->code);
        return;
    }

    char id[INVITE_ID_LEN * 2 + 1], tok[TOKEN_LEN * 2 + 1];
    char key[KEY_LEN * 2 + 1], host[768], frag[256];
    hex_encode(v->id, sizeof v->id, id);
    hex_encode(v->token, sizeof v->token, tok);
    hex_encode(v->key, sizeof v->key, key);
    url_encode(v->host, host, sizeof host);
    snprintf(out, cap, LINK_PREFIX "i=%s&h=%s&p=%d&e=%llu&pw=%d#t=%s",
             id, host, v->port, (unsigned long long)v->expires_at,
             v->has_password ? 1 : 0, tok);
    if (v->has_key && !v->has_password) {
        snprintf(frag, sizeof frag, "&k=%s", key);
        str_append(out, cap, frag);
    }
}

static int parse_u64(const char *s, uint64_t *out)
{
    if (!s || !*s) return -1;
    char *end = NULL;
    errno = 0;
    unsigned long long v = strtoull(s, &end, 10);
    if (errno || !end || *end) return -1;
    *out = (uint64_t)v;
    return 0;
}

static int invite_parse(const char *text, Invite *v, char *err, size_t errlen)
{
    char work[2048];
    size_t n = strlen(text);
    while (n > 0 && (text[n - 1] == '\n' || text[n - 1] == '\r' ||
                     text[n - 1] == ' ' || text[n - 1] == '\t'))
        n--;
    size_t start = 0;
    while (start < n && (text[start] == ' ' || text[start] == '\t' || text[start] == '\n'))
        start++;
    if (n - start >= sizeof work) {
        snprintf(err, errlen, "Lien trop long.");
        return -1;
    }
    memcpy(work, text + start, n - start);
    work[n - start] = '\0';

    memset(v, 0, sizeof *v);

    /* Code de partage saisi seul, éventuellement « CODE@serveur ». */
    if (strncmp(work, "sillage://", 10) != 0) {
        char codein[128], srv[256] = "";
        char *at = strchr(work, '@');
        if (at) {
            *at = '\0';
            snprintf(srv, sizeof srv, "%s", at + 1);
        }
        snprintf(codein, sizeof codein, "%.*s", (int)sizeof codein - 1, work);
        if (invite_set_code(v, codein) != 0) {
            snprintf(err, errlen,
                     "Code de partage invalide : attendu 10 caractères (sans I, L, O ni U).");
            return -1;
        }
        invite_set_signal(v, srv[0] ? srv : signal_default());
        snprintf(v->stun, sizeof v->stun, "%s", stun_default());
        v->expires_at = 0;
        v->has_password = 0;
        v->pw_unknown = 1;
        return 0;
    }

    char *p = work + 10;

    /* ------------------------------------------------------------- v2 */
    if (strncmp(p, "v2?", 3) == 0) {
        p += 3;
        char *frag = strchr(p, '#');
        if (frag) {
            *frag = '\0';
            frag++;
        }

        char sig[768] = "", stunbuf[768] = "", codein[128] = "";
        uint64_t exp = 0, pw = 0;
        int seen_c = 0;

        char *save = NULL;
        for (char *kv = strtok_r(p, "&", &save); kv; kv = strtok_r(NULL, "&", &save)) {
            char *eq = strchr(kv, '=');
            if (!eq) continue;
            *eq = '\0';
            char *k = kv, *val = eq + 1;
            url_decode_inplace(val);
            if (strcmp(k, "s") == 0) {
                snprintf(sig, sizeof sig, "%s", val);
            } else if (strcmp(k, "st") == 0) {
                snprintf(stunbuf, sizeof stunbuf, "%s", val);
            } else if (strcmp(k, "e") == 0) {
                parse_u64(val, &exp);
            } else if (strcmp(k, "pw") == 0) {
                parse_u64(val, &pw);
            }
        }
        if (frag) {
            save = NULL;
            for (char *kv = strtok_r(frag, "&", &save); kv; kv = strtok_r(NULL, "&", &save)) {
                char *eq = strchr(kv, '=');
                if (!eq) continue;
                *eq = '\0';
                char *k = kv, *val = eq + 1;
                url_decode_inplace(val);
                if (strcmp(k, "c") == 0) {
                    snprintf(codein, sizeof codein, "%s", val);
                    seen_c = 1;
                }
            }
        }
        if (!seen_c || invite_set_code(v, codein) != 0) {
            snprintf(err, errlen, "Code de partage manquant ou invalide dans le lien.");
            return -1;
        }
        invite_set_signal(v, sig[0] ? sig : signal_default());
        snprintf(v->stun, sizeof v->stun, "%s",
                 stunbuf[0] ? stunbuf : stun_default());
        v->expires_at = exp;
        v->has_password = pw ? 1 : 0;
        v->has_key = pw ? 0 : 1;
        return 0;
    }

    /* ------------------------------------------------------------- v1 */
    if (strncmp(p, "v1?", 3) != 0) {
        snprintf(err, errlen, "Version de lien non prise en charge.");
        return -1;
    }
    p += 3;

    char *frag = strchr(p, '#');
    if (frag) {
        *frag = '\0';
        frag++;
    }

    char host[256] = "";
    char idhex[128] = "", tokhex[128] = "", keyhex[256] = "";
    uint64_t port = 0, exp = 0, pw = 0;
    int seen_i = 0, seen_t = 0, seen_p = 0;

    char *save = NULL;
    for (char *kv = strtok_r(p, "&", &save); kv; kv = strtok_r(NULL, "&", &save)) {
        char *eq = strchr(kv, '=');
        if (!eq) continue;
        *eq = '\0';
        char *k = kv, *val = eq + 1;
        url_decode_inplace(val);
        if (strcmp(k, "i") == 0) {
            snprintf(idhex, sizeof idhex, "%s", val);
            seen_i = 1;
        } else if (strcmp(k, "h") == 0) {
            snprintf(host, sizeof host, "%s", val);
        } else if (strcmp(k, "p") == 0) {
            if (parse_u64(val, &port) == 0) seen_p = 1;
        } else if (strcmp(k, "e") == 0) {
            parse_u64(val, &exp);
        } else if (strcmp(k, "pw") == 0) {
            parse_u64(val, &pw);
        }
    }
    if (frag) {
        save = NULL;
        for (char *kv = strtok_r(frag, "&", &save); kv; kv = strtok_r(NULL, "&", &save)) {
            char *eq = strchr(kv, '=');
            if (!eq) continue;
            *eq = '\0';
            char *k = kv, *val = eq + 1;
            url_decode_inplace(val);
            if (strcmp(k, "t") == 0) {
                snprintf(tokhex, sizeof tokhex, "%s", val);
                seen_t = 1;
            } else if (strcmp(k, "k") == 0) {
                snprintf(keyhex, sizeof keyhex, "%s", val);
            }
        }
    }

    if (!seen_i || hex_decode(idhex, v->id, sizeof v->id) != 0) {
        snprintf(err, errlen, "Identifiant d'invitation manquant ou invalide.");
        return -1;
    }
    if (!seen_t || hex_decode(tokhex, v->token, sizeof v->token) != 0) {
        snprintf(err, errlen, "Jeton d'invitation manquant ou invalide.");
        return -1;
    }
    if (!seen_p || port == 0 || port > 65535) {
        snprintf(err, errlen, "Port invalide dans le lien.");
        return -1;
    }
    if (!host[0]) {
        snprintf(err, errlen, "Adresse d'hôte manquante.");
        return -1;
    }
    v->port = (int)port;
    v->expires_at = exp;
    v->has_password = pw ? 1 : 0;
    v->transport = TRANSPORT_TCP;
    copy_path(v->host, sizeof v->host, host);
    if (!v->has_password) {
        if (keyhex[0] == '\0' || hex_decode(keyhex, v->key, sizeof v->key) != 0) {
            snprintf(err, errlen, "Clé de déchiffrement manquante ou invalide.");
            return -1;
        }
        v->has_key = 1;
    }
    return 0;
}

/* ===================================================================== */
/*  Cryptographie                                                        */
/* ===================================================================== */

static void hmac_sha256(const uint8_t *key, size_t klen,
                        const uint8_t *msg, size_t mlen, uint8_t out[HMAC_LEN])
{
    unsigned int olen = HMAC_LEN;
    HMAC(EVP_sha256(), key, (int)klen, msg, mlen, out, &olen);
}

static int derive_password_key(const char *password, const uint8_t id[INVITE_ID_LEN],
                               uint8_t key[KEY_LEN], char *err, size_t errlen)
{
    static const char salt_prefix[] = "SILLAGE-TRANSFER-v1";
    uint8_t salt[sizeof salt_prefix - 1 + INVITE_ID_LEN];
    memcpy(salt, salt_prefix, sizeof salt_prefix - 1);
    memcpy(salt + sizeof salt_prefix - 1, id, INVITE_ID_LEN);
    if (!password || !*password) {
        snprintf(err, errlen, "Mot de passe vide.");
        return -1;
    }
    int ok = EVP_PBE_scrypt(password, strlen(password), salt, sizeof salt,
                            1u << 15, 8, 1, 64u * 1024u * 1024u, key, KEY_LEN);
    if (ok != 1) {
        snprintf(err, errlen, "Dérivation de clé impossible (OpenSSL).");
        return -1;
    }
    return 0;
}

static void make_nonce(uint8_t nonce[NONCE_LEN], const uint8_t prefix[NONCE_PREFIX_LEN], uint64_t index)
{
    memcpy(nonce, prefix, NONCE_PREFIX_LEN);
    for (int i = 0; i < 8; i++)
        nonce[NONCE_PREFIX_LEN + i] = (uint8_t)(index >> (56 - i * 8));
}

static void make_aad(uint8_t aad[40], const uint8_t id[INVITE_ID_LEN],
                     uint64_t index, uint32_t len, uint64_t total)
{
    memcpy(aad, "SLT1", 4);
    memcpy(aad + 4, id, INVITE_ID_LEN);
    for (int i = 0; i < 8; i++) aad[20 + i] = (uint8_t)(index >> (56 - i * 8));
    aad[28] = (uint8_t)(len >> 24);
    aad[29] = (uint8_t)(len >> 16);
    aad[30] = (uint8_t)(len >> 8);
    aad[31] = (uint8_t)len;
    for (int i = 0; i < 8; i++) aad[32 + i] = (uint8_t)(total >> (56 - i * 8));
}

static void put_u32(uint8_t out[4], uint32_t v)
{
    out[0] = (uint8_t)(v >> 24); out[1] = (uint8_t)(v >> 16);
    out[2] = (uint8_t)(v >> 8);  out[3] = (uint8_t)v;
}

static uint32_t get_u32(const uint8_t in[4])
{
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) |
           ((uint32_t)in[2] << 8) | (uint32_t)in[3];
}

static void put_u64(uint8_t out[8], uint64_t v)
{
    for (int i = 0; i < 8; i++) out[i] = (uint8_t)(v >> (56 - i * 8));
}

static uint64_t get_u64(const uint8_t in[8])
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | in[i];
    return v;
}

/* ===================================================================== */
/*  Sockets                                                              */
/* ===================================================================== */

static bool wait_fd(int fd, short events, int timeout_ms, Job *job)
{
    double deadline = mono_now() + (double)timeout_ms / 1000.0;
    for (;;) {
        if (job && job_cancelled(job))
            return false;
        double left = deadline - mono_now();
        if (left <= 0)
            return false;
        int slice = (int)(left * 1000.0);
        if (slice > 200) slice = 200;
        struct pollfd p = { .fd = fd, .events = events, .revents = 0 };
        int r = poll(&p, 1, slice);
        if (r > 0) {
            if (p.revents & (events | POLLERR | POLLHUP | POLLNVAL))
                return true;
        } else if (r < 0 && errno != EINTR) {
            return false;
        }
    }
}

static bool send_all(int fd, const void *buf, size_t len, Job *job)
{
    const uint8_t *p = (const uint8_t *)buf;
    size_t off = 0;
    while (off < len) {
        if (job && job_cancelled(job))
            return false;
        ssize_t n = send(fd, p + off, len - off, MSG_NOSIGNAL);
        if (n > 0) {
            off += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (!wait_fd(fd, POLLOUT, SOCK_IO_TIMEOUT_MS, job))
                return false;
            continue;
        }
        return false;
    }
    return true;
}

static bool recv_all(int fd, void *buf, size_t len, Job *job)
{
    uint8_t *p = (uint8_t *)buf;
    size_t off = 0;
    while (off < len) {
        if (job && job_cancelled(job))
            return false;
        ssize_t n = recv(fd, p + off, len - off, 0);
        if (n > 0) {
            off += (size_t)n;
            continue;
        }
        if (n == 0)
            return false;
        if (errno == EINTR)
            continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            if (!wait_fd(fd, POLLIN, SOCK_IO_TIMEOUT_MS, job))
                return false;
            continue;
        }
        return false;
    }
    return true;
}

static void set_socket_opts(int fd)
{
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof one);
}

static int sock_listen(int port, int *out_port, char *err, size_t errlen)
{
    int fd = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd >= 0) {
        int zero = 0, one = 1;
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof zero);
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        struct sockaddr_in6 a6;
        memset(&a6, 0, sizeof a6);
        a6.sin6_family = AF_INET6;
        a6.sin6_addr = in6addr_any;
        a6.sin6_port = htons((uint16_t)port);
        if (bind(fd, (struct sockaddr *)&a6, sizeof a6) == 0 && listen(fd, 8) == 0) {
            socklen_t sl = sizeof a6;
            if (getsockname(fd, (struct sockaddr *)&a6, &sl) == 0) {
                *out_port = ntohs(a6.sin6_port);
                return fd;
            }
        }
        close(fd);
    }
    fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        snprintf(err, errlen, "Impossible de créer le socket.");
        return -1;
    }
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a4;
    memset(&a4, 0, sizeof a4);
    a4.sin_family = AF_INET;
    a4.sin_addr.s_addr = htonl(INADDR_ANY);
    a4.sin_port = htons((uint16_t)port);
    if (bind(fd, (struct sockaddr *)&a4, sizeof a4) != 0 || listen(fd, 8) != 0) {
        snprintf(err, errlen, "Port %d indisponible (%s).", port, strerror(errno));
        close(fd);
        return -1;
    }
    socklen_t sl = sizeof a4;
    if (getsockname(fd, (struct sockaddr *)&a4, &sl) == 0)
        *out_port = ntohs(a4.sin_port);
    return fd;
}

/* Écoute la signalisation locale sur 127.0.0.1 uniquement.
 * Utilisé quand l'utilisateur laisse le serveur par défaut : on ne veut pas
 * exposer le port sur le réseau sans action explicite. */
static int sock_listen_loopback(int port, int *out_port, char *err, size_t errlen)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        snprintf(err, errlen, "Impossible de créer le socket.");
        return -1;
    }
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons((uint16_t)port);
    if (bind(fd, (struct sockaddr *)&a, sizeof a) != 0 || listen(fd, 8) != 0) {
        snprintf(err, errlen, "Port %d indisponible (%s).", port, strerror(errno));
        close(fd);
        return -1;
    }
    socklen_t sl = sizeof a;
    if (getsockname(fd, (struct sockaddr *)&a, &sl) == 0)
        *out_port = ntohs(a.sin_port);
    return fd;
}

static int sock_accept(int lfd, int timeout_ms, Job *job, char *peer, size_t peercap)
{
    double deadline = mono_now() + (double)timeout_ms / 1000.0;
    for (;;) {
        if (job && job_cancelled(job))
            return -1;
        double left = deadline - mono_now();
        if (left <= 0)
            return -1;
        int slice = (int)(left * 1000.0);
        if (slice > 250) slice = 250;
        struct pollfd p = { .fd = lfd, .events = POLLIN, .revents = 0 };
        int r = poll(&p, 1, slice);
        if (r <= 0)
            continue;
        if (!(p.revents & POLLIN))
            continue;
        struct sockaddr_storage ss;
        socklen_t sl = sizeof ss;
        int fd = accept4(lfd, (struct sockaddr *)&ss, &sl, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                continue;
            return -1;
        }
        set_socket_opts(fd);
        if (peer && peercap) {
            char host[NI_MAXHOST], serv[NI_MAXSERV];
            if (getnameinfo((struct sockaddr *)&ss, sl, host, sizeof host,
                            serv, sizeof serv, NI_NUMERICHOST | NI_NUMERICSERV) == 0)
                snprintf(peer, peercap, "%.100s:%.16s", host, serv);
            else
                snprintf(peer, peercap, "inconnu");
        }
        return fd;
    }
}

static int tcp_connect(const char *host, int port, Job *job, char *err, size_t errlen)
{
    char portstr[16];
    snprintf(portstr, sizeof portstr, "%d", port);
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    int gai = getaddrinfo(host, portstr, &hints, &res);
    if (gai != 0) {
        snprintf(err, errlen, "Adresse « %.140s » introuvable (%.40s).", host, gai_strerror(gai));
        return -1;
    }
    int result = -1;
    snprintf(err, errlen, "Connexion impossible à %.200s:%d.", host, port);
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        int fd = socket(ai->ai_family, ai->ai_socktype | SOCK_NONBLOCK | SOCK_CLOEXEC, ai->ai_protocol);
        if (fd < 0)
            continue;
        int rc = connect(fd, ai->ai_addr, ai->ai_addrlen);
        if (rc < 0 && errno == EINPROGRESS) {
            if (!wait_fd(fd, POLLOUT, 10000, job)) {
                close(fd);
                if (job && job_cancelled(job)) break;
                continue;
            }
            int soerr = 0;
            socklen_t sl = sizeof soerr;
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl) < 0 || soerr != 0) {
                close(fd);
                continue;
            }
            rc = 0;
        }
        if (rc == 0) {
            set_socket_opts(fd);
            result = fd;
            break;
        }
        close(fd);
    }
    freeaddrinfo(res);
    return result;
}

/* ===================================================================== */
/*  Flux octet uniforme : socket TCP ou DataChannel WebRTC               */
/* ===================================================================== */

typedef struct {
    int fd;
    int dc;
    int pc;
    Job *job;
    pthread_mutex_t mu;
    pthread_cond_t cv;
    uint8_t *ring;
    size_t cap, off, len;
    int opened;
    int closed;
    int error;
    int gathering;
    int pc_failed;
    char errmsg[256];
} Stream;

static void ts_add_ms(struct timespec *ts, int ms)
{
    clock_gettime(CLOCK_REALTIME, ts);
    ts->tv_sec += ms / 1000;
    ts->tv_nsec += (long)(ms % 1000) * 1000000L;
    if (ts->tv_nsec >= 1000000000L) {
        ts->tv_sec++;
        ts->tv_nsec -= 1000000000L;
    }
}

static Stream *stream_new(Job *job)
{
    Stream *s = calloc(1, sizeof *s);
    if (!s) return NULL;
    s->fd = -1;
    s->dc = -1;
    s->pc = -1;
    s->job = job;
    s->opened = 1;             /* vrai par défaut pour TCP */
    pthread_mutex_init(&s->mu, NULL);
    pthread_cond_init(&s->cv, NULL);
    return s;
}

static Stream *stream_tcp(int fd, Job *job)
{
    Stream *s = stream_new(job);
    if (!s) {
        close(fd);
        return NULL;
    }
    s->fd = fd;
    return s;
}

static void stream_destroy(Stream *s)
{
    if (!s) return;
    pthread_mutex_lock(&s->mu);
    s->closed = 1;
    int pc = s->pc;
    s->pc = -1;
    pthread_cond_broadcast(&s->cv);
    pthread_mutex_unlock(&s->mu);

    if (pc > 0)
        rtcDeletePeerConnection(pc);
    if (s->fd >= 0)
        close(s->fd);

    free(s->ring);
    pthread_mutex_destroy(&s->mu);
    pthread_cond_destroy(&s->cv);
    free(s);
}

static void stream_push(Stream *s, const char *data, int size)
{
    if (!s || size <= 0) return;
    pthread_mutex_lock(&s->mu);
    if (!s->ring) {
        s->ring = malloc(STREAM_RING_CAP);
        if (!s->ring) {
            s->error = 1;
            pthread_cond_broadcast(&s->cv);
            pthread_mutex_unlock(&s->mu);
            return;
        }
        s->cap = STREAM_RING_CAP;
        s->off = s->len = 0;
    }
    while (s->len + (size_t)size > s->cap && !s->closed && !s->error) {
        if (s->off > 0 && s->off + s->len <= s->cap) {
            memmove(s->ring, s->ring + s->off, s->len);
            s->off = 0;
        }
        if (s->len + (size_t)size <= s->cap)
            break;
        struct timespec ts;
        ts_add_ms(&ts, 100);
        pthread_cond_timedwait(&s->cv, &s->mu, &ts);
        if (s->job && job_cancelled(s->job)) {
            s->closed = 1;
            break;
        }
    }
    if (!s->closed && !s->error) {
        if (s->off > 0 && s->off + s->len + (size_t)size > s->cap) {
            memmove(s->ring, s->ring + s->off, s->len);
            s->off = 0;
        }
        memcpy(s->ring + s->off + s->len, data, (size_t)size);
        s->len += (size_t)size;
    }
    pthread_cond_broadcast(&s->cv);
    pthread_mutex_unlock(&s->mu);
}

static bool stream_write(Stream *s, const void *buf, size_t len)
{
    if (!s || len == 0) return true;
    if (s->fd >= 0)
        return send_all(s->fd, buf, len, s->job);

    const uint8_t *p = (const uint8_t *)buf;
    size_t off = 0;
    int cap = s->dc > 0 ? rtcMaxMessageSize(s->dc) : 64 * 1024;
    if (cap <= 0 || cap > 256 * 1024)
        cap = 256 * 1024;

    double deadline = mono_now() + (double)SOCK_IO_TIMEOUT_MS / 1000.0;
    while (off < len) {
        if (s->job && job_cancelled(s->job))
            return false;
        pthread_mutex_lock(&s->mu);
        int bad = s->closed || s->error;
        pthread_mutex_unlock(&s->mu);
        if (bad)
            return false;

        int buffered = rtcGetBufferedAmount(s->dc);
        if (buffered > 4 * 1024 * 1024) {
            if (mono_now() > deadline)
                return false;
            struct timespec ts = { .tv_sec = 0, .tv_nsec = 2000000 };
            nanosleep(&ts, NULL);
            continue;
        }

        size_t n = len - off;
        if (n > (size_t)cap)
            n = (size_t)cap;
        int rc = rtcSendMessage(s->dc, (const char *)(p + off), (int)n);
        if (rc >= 0) {
            off += n;
            deadline = mono_now() + (double)SOCK_IO_TIMEOUT_MS / 1000.0;
            continue;
        }
        if (mono_now() > deadline)
            return false;
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 5000000 };
        nanosleep(&ts, NULL);
    }
    return true;
}

static bool stream_read(Stream *s, void *buf, size_t len)
{
    if (!s || len == 0) return true;
    if (s->fd >= 0)
        return recv_all(s->fd, buf, len, s->job);

    uint8_t *p = (uint8_t *)buf;
    size_t got = 0;
    double deadline = mono_now() + (double)SOCK_IO_TIMEOUT_MS / 1000.0;

    pthread_mutex_lock(&s->mu);
    while (got < len) {
        if (s->len > 0) {
            size_t n = s->len;
            if (n > len - got)
                n = len - got;
            memcpy(p + got, s->ring + s->off, n);
            s->off += n;
            s->len -= n;
            got += n;
            if (s->len == 0)
                s->off = 0;
            pthread_cond_broadcast(&s->cv);
            continue;
        }
        if (s->closed || s->error) {
            pthread_mutex_unlock(&s->mu);
            return false;
        }
        if (s->job && job_cancelled(s->job)) {
            pthread_mutex_unlock(&s->mu);
            return false;
        }
        if (mono_now() > deadline) {
            pthread_mutex_unlock(&s->mu);
            return false;
        }
        struct timespec ts;
        ts_add_ms(&ts, 100);
        pthread_cond_timedwait(&s->cv, &s->mu, &ts);
    }
    pthread_mutex_unlock(&s->mu);
    return true;
}

static bool stream_wait_open(Stream *s, int timeout_ms)
{
    double deadline = mono_now() + (double)timeout_ms / 1000.0;
    pthread_mutex_lock(&s->mu);
    while (!s->opened && !s->closed && !s->error) {
        if (mono_now() > deadline)
            break;
        if (s->job && job_cancelled(s->job))
            break;
        struct timespec ts;
        ts_add_ms(&ts, 100);
        pthread_cond_timedwait(&s->cv, &s->mu, &ts);
    }
    int ok = s->opened && !s->closed && !s->error;
    pthread_mutex_unlock(&s->mu);
    return ok;
}

static bool stream_wait_gather(Stream *s, int timeout_ms)
{
    double deadline = mono_now() + (double)timeout_ms / 1000.0;
    pthread_mutex_lock(&s->mu);
    while (!s->gathering && !s->closed && !s->error && !s->pc_failed) {
        if (mono_now() > deadline)
            break;
        if (s->job && job_cancelled(s->job))
            break;
        struct timespec ts;
        ts_add_ms(&ts, 100);
        pthread_cond_timedwait(&s->cv, &s->mu, &ts);
    }
    int ok = (s->gathering || s->opened) && !s->closed && !s->error && !s->pc_failed;
    pthread_mutex_unlock(&s->mu);
    return ok;
}

static void stream_on_open(int id, void *ptr)
{
    (void)id;
    Stream *s = (Stream *)ptr;
    pthread_mutex_lock(&s->mu);
    s->opened = 1;
    pthread_cond_broadcast(&s->cv);
    pthread_mutex_unlock(&s->mu);
}

static void stream_on_closed(int id, void *ptr)
{
    (void)id;
    Stream *s = (Stream *)ptr;
    pthread_mutex_lock(&s->mu);
    s->closed = 1;
    pthread_cond_broadcast(&s->cv);
    pthread_mutex_unlock(&s->mu);
}

static void stream_on_error(int id, const char *error, void *ptr)
{
    (void)id;
    Stream *s = (Stream *)ptr;
    pthread_mutex_lock(&s->mu);
    s->error = 1;
    if (error)
        snprintf(s->errmsg, sizeof s->errmsg, "%s", error);
    pthread_cond_broadcast(&s->cv);
    pthread_mutex_unlock(&s->mu);
}

static void stream_on_message(int id, const char *message, int size, void *ptr)
{
    (void)id;
    stream_push((Stream *)ptr, message, size);
}

static void stream_on_gather(int pc, rtcGatheringState state, void *ptr)
{
    (void)pc;
    Stream *s = (Stream *)ptr;
    if (state != RTC_GATHERING_COMPLETE)
        return;
    pthread_mutex_lock(&s->mu);
    s->gathering = 1;
    pthread_cond_broadcast(&s->cv);
    pthread_mutex_unlock(&s->mu);
}

static void stream_on_pc_state(int pc, rtcState state, void *ptr)
{
    (void)pc;
    Stream *s = (Stream *)ptr;
    if (state != RTC_FAILED)
        return;
    pthread_mutex_lock(&s->mu);
    s->pc_failed = 1;
    s->error = 1;
    pthread_cond_broadcast(&s->cv);
    pthread_mutex_unlock(&s->mu);
}

static void stream_bind_dc(Stream *s, int dc)
{
    s->dc = dc;
    rtcSetUserPointer(dc, s);
    rtcSetOpenCallback(dc, stream_on_open);
    rtcSetClosedCallback(dc, stream_on_closed);
    rtcSetErrorCallback(dc, stream_on_error);
    rtcSetMessageCallback(dc, stream_on_message);
}

static void rtc_incoming_dc(int pc, int dc, void *ptr)
{
    (void)pc;
    stream_bind_dc((Stream *)ptr, dc);
}

/* ===================================================================== */
/*  Signalisation : salle opaque, aucun contenu ni clé                   */
/* ===================================================================== */

typedef struct {
    uint8_t room[INVITE_ID_LEN];
    int used;
    uint8_t blob[2][SIGNAL_MAX_BLOB];
    size_t len[2];
    double updated;
} SignalRoom;

static SignalRoom g_rooms[SIGNAL_ROOMS];
static pthread_mutex_t g_rooms_mu = PTHREAD_MUTEX_INITIALIZER;

static bool sig_write_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    size_t off = 0;
    while (off < len) {
        ssize_t n = send(fd, p + off, len - off, MSG_NOSIGNAL);
        if (n > 0) { off += (size_t)n; continue; }
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd pp = { .fd = fd, .events = POLLOUT, .revents = 0 };
            if (poll(&pp, 1, 5000) <= 0) return false;
            continue;
        }
        return false;
    }
    return true;
}

static bool sig_read_all(int fd, void *buf, size_t len)
{
    uint8_t *p = (uint8_t *)buf;
    size_t off = 0;
    while (off < len) {
        ssize_t n = recv(fd, p + off, len - off, 0);
        if (n > 0) { off += (size_t)n; continue; }
        if (n == 0) return false;
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            struct pollfd pp = { .fd = fd, .events = POLLIN, .revents = 0 };
            if (poll(&pp, 1, 5000) <= 0) return false;
            continue;
        }
        return false;
    }
    return true;
}

static int signal_call(const Invite *inv, const uint8_t *req, size_t reqlen,
                       uint8_t *resp, size_t respcap, size_t *resplen,
                       Job *job, char *err, size_t errlen)
{
    int fd = tcp_connect(inv->signal_host, inv->signal_port, job, err, errlen);
    if (fd < 0) {
        snprintf(err, errlen,
                 "Serveur de signalisation injoignable sur %.80s:%d. "
                 "Lancez « ./sillage-transfer --signal-server » ou indiquez "
                 "un serveur joignable dans le champ prévu.",
                 inv->signal_host, inv->signal_port);
        return -1;
    }
    uint8_t hdr[4];
    put_u32(hdr, (uint32_t)reqlen);
    bool ok = sig_write_all(fd, hdr, sizeof hdr) &&
              sig_write_all(fd, req, reqlen);
    if (!ok) {
        close(fd);
        snprintf(err, errlen, "Serveur de signalisation injoignable.");
        return -1;
    }
    if (!sig_read_all(fd, hdr, sizeof hdr)) {
        close(fd);
        snprintf(err, errlen, "Serveur de signalisation muet.");
        return -1;
    }
    uint32_t n = get_u32(hdr);
    if (n > respcap) {
        close(fd);
        snprintf(err, errlen, "Réponse de signalisation trop volumineuse.");
        return -1;
    }
    if (n > 0 && !sig_read_all(fd, resp, n)) {
        close(fd);
        snprintf(err, errlen, "Réponse de signalisation interrompue.");
        return -1;
    }
    close(fd);
    if (n < 5) {
        snprintf(err, errlen, "Réponse de signalisation invalide.");
        return -1;
    }
    *resplen = n;
    return 0;
}

static int signal_publish(const Invite *inv, int role,
                          const uint8_t *blob, size_t blen,
                          Job *job, char *err, size_t errlen)
{
    if (blen > SIGNAL_MAX_BLOB) {
        snprintf(err, errlen, "Description de session trop volumineuse.");
        return -1;
    }
    size_t reqlen = 1 + INVITE_ID_LEN + 1 + 4 + blen;
    uint8_t *req = malloc(reqlen);
    if (!req) {
        snprintf(err, errlen, "Mémoire insuffisante.");
        return -1;
    }
    size_t o = 0;
    req[o++] = 1;                          /* PUB */
    memcpy(req + o, inv->room, INVITE_ID_LEN); o += INVITE_ID_LEN;
    req[o++] = (uint8_t)(role & 1);
    put_u32(req + o, (uint32_t)blen); o += 4;
    memcpy(req + o, blob, blen); o += blen;

    uint8_t resp[16];
    size_t rlen = 0;
    int rc = signal_call(inv, req, o, resp, sizeof resp, &rlen, job, err, errlen);
    free(req);
    if (rc != 0)
        return -1;
    if (resp[0] != 0) {
        snprintf(err, errlen, "Le serveur de signalisation a refusé la session.");
        return -1;
    }
    return 0;
}

/* 1 = blob reçu, 0 = pas encore disponible, -1 = erreur */
static int signal_fetch(const Invite *inv, int role,
                        uint8_t *blob, size_t cap, size_t *blen,
                        Job *job, char *err, size_t errlen)
{
    uint8_t req[1 + INVITE_ID_LEN + 1];
    req[0] = 2;                            /* GET */
    memcpy(req + 1, inv->room, INVITE_ID_LEN);
    req[1 + INVITE_ID_LEN] = (uint8_t)(role & 1);

    uint8_t *resp = malloc(cap + 8);
    if (!resp) {
        snprintf(err, errlen, "Mémoire insuffisante.");
        return -1;
    }
    size_t rlen = 0;
    int rc = signal_call(inv, req, sizeof req, resp, cap + 8, &rlen, job, err, errlen);
    if (rc != 0) {
        free(resp);
        return -1;
    }
    uint8_t status = resp[0];
    uint32_t n = get_u32(resp + 1);
    if (status == 0) {
        free(resp);
        return 0;
    }
    if (status != 1 || n > cap || rlen < 5u + n) {
        free(resp);
        snprintf(err, errlen, "Réponse de signalisation incohérente.");
        return -1;
    }
    memcpy(blob, resp + 5, n);
    *blen = n;
    free(resp);
    return 1;
}

static SignalRoom *signal_room_find(const uint8_t room[INVITE_ID_LEN], int create)
{
    double now = mono_now();
    SignalRoom *free_slot = NULL;
    SignalRoom *oldest = NULL;

    for (int i = 0; i < SIGNAL_ROOMS; i++) {
        SignalRoom *r = &g_rooms[i];
        if (r->used && now - r->updated > SIGNAL_ROOM_TTL) {
            memset(r, 0, sizeof *r);
        }
        if (r->used && memcmp(r->room, room, INVITE_ID_LEN) == 0)
            return r;
        if (!r->used && !free_slot)
            free_slot = r;
        if (r->used && (!oldest || r->updated < oldest->updated))
            oldest = r;
    }
    if (!create)
        return NULL;
    SignalRoom *r = free_slot ? free_slot : oldest;
    if (!r)
        return NULL;
    memset(r, 0, sizeof *r);
    memcpy(r->room, room, INVITE_ID_LEN);
    r->used = 1;
    r->updated = now;
    return r;
}

static void *signal_conn_thread(void *vp)
{
    int fd = (int)(intptr_t)vp;
    uint8_t hdr[4];
    uint8_t *req = NULL;
    uint8_t *resp = NULL;

    if (!sig_read_all(fd, hdr, sizeof hdr))
        goto out;
    uint32_t reqlen = get_u32(hdr);
    if (reqlen < 18 || reqlen > SIGNAL_MAX_BLOB + 64)
        goto out;
    req = malloc(reqlen);
    if (!req || !sig_read_all(fd, req, reqlen))
        goto out;

    int type = req[0];
    const uint8_t *room = req + 1;
    int role = req[1 + INVITE_ID_LEN] & 1;

    resp = malloc(5 + SIGNAL_MAX_BLOB);
    if (!resp)
        goto out;

    pthread_mutex_lock(&g_rooms_mu);
    if (type == 1) {                       /* PUB */
        if (reqlen < 1 + INVITE_ID_LEN + 1 + 4)
            goto unlock_bad;
        uint32_t blen = get_u32(req + 1 + INVITE_ID_LEN + 1);
        if (blen > SIGNAL_MAX_BLOB ||
            reqlen != 1 + INVITE_ID_LEN + 1 + 4 + blen)
            goto unlock_bad;
        SignalRoom *r = signal_room_find(room, 1);
        if (!r)
            goto unlock_bad;
        memcpy(r->blob[role], req + 1 + INVITE_ID_LEN + 1 + 4, blen);
        r->len[role] = blen;
        r->updated = mono_now();
        put_u32(resp + 1, 0);
        resp[0] = 0;
    } else if (type == 2) {                /* GET */
        SignalRoom *r = signal_room_find(room, 0);
        /* Le client demande explicitement le rôle qu'il veut lire. */
        int other = role;
        if (r && r->len[other] > 0) {
            size_t n = r->len[other];
            resp[0] = 1;
            put_u32(resp + 1, (uint32_t)n);
            memcpy(resp + 5, r->blob[other], n);
        } else {
            resp[0] = 0;
            put_u32(resp + 1, 0);
        }
    } else {
        goto unlock_bad;
    }
    pthread_mutex_unlock(&g_rooms_mu);

    {
        size_t n = 5 + (resp[0] == 1 ? (size_t)get_u32(resp + 1) : 0);
        put_u32(hdr, (uint32_t)n);
        (void)sig_write_all(fd, hdr, sizeof hdr);
        (void)sig_write_all(fd, resp, n);
    }
    goto out;

unlock_bad:
    pthread_mutex_unlock(&g_rooms_mu);
    resp[0] = 2;
    put_u32(resp + 1, 0);
    put_u32(hdr, 5);
    (void)sig_write_all(fd, hdr, sizeof hdr);
    (void)sig_write_all(fd, resp, 5);

out:
    free(req);
    free(resp);
    close(fd);
    return NULL;
}

static void signal_accept_loop(int lfd, atomic_int *stop)
{
    while (!(stop && atomic_load_explicit(stop, memory_order_relaxed))) {
        struct pollfd p = { .fd = lfd, .events = POLLIN, .revents = 0 };
        int r = poll(&p, 1, 100);
        if (r <= 0)
            continue;
        int fd = accept4(lfd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0)
            continue;
        pthread_t th;
        if (pthread_create(&th, NULL, signal_conn_thread, (void *)(intptr_t)fd) == 0)
            pthread_detach(th);
        else
            close(fd);
    }
}

static int signal_host_is_local(const char *host)
{
    return host && (!strcmp(host, "127.0.0.1") ||
                    !strcmp(host, "localhost") ||
                    !strcmp(host, "::1"));
}

/* Vérifie qu'un serveur écoute déjà, sans bloquer longtemps. */
static int signal_probe(const char *host, int port)
{
    char portstr[16];
    snprintf(portstr, sizeof portstr, "%d", port);
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, portstr, &hints, &res) != 0)
        return 0;

    int open = 0;
    for (struct addrinfo *ai = res; ai && !open; ai = ai->ai_next) {
        int fd = socket(ai->ai_family, ai->ai_socktype | SOCK_NONBLOCK | SOCK_CLOEXEC,
                        ai->ai_protocol);
        if (fd < 0)
            continue;
        int rc = connect(fd, ai->ai_addr, ai->ai_addrlen);
        if (rc == 0) {
            open = 1;
        } else if (errno == EINPROGRESS) {
            struct pollfd p = { .fd = fd, .events = POLLOUT, .revents = 0 };
            if (poll(&p, 1, 250) > 0) {
                int soerr = 0;
                socklen_t sl = sizeof soerr;
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl) == 0 && soerr == 0)
                    open = 1;
            }
        }
        close(fd);
    }
    freeaddrinfo(res);
    return open;
}

static void *local_signal_thread(void *vp)
{
    signal_accept_loop((int)(intptr_t)vp, NULL);
    return NULL;
}

/*
 * Démarre automatiquement le serveur de signalisation intégré quand le champ
 * pointe vers la machine locale et que rien n'écoute déjà. C'est le cas par
 * défaut (127.0.0.1:8787) : l'utilisateur n'a pas à lancer un second terminal.
 * Pour un partage entre deux machines, il faut explicitement un serveur
 * joignable (--signal-server sur une machine du réseau, ou adresse dédiée).
 */
static void ensure_local_signal_server(const Invite *inv)
{
    if (!inv || !signal_host_is_local(inv->signal_host))
        return;
    if (!strcmp(inv->signal_host, "::1"))
        return;                       /* auto-démarrage IPv4 seulement */
    if (signal_probe(inv->signal_host, inv->signal_port))
        return;                       /* un serveur écoute déjà */

    char err[128] = "";
    int lport = 0;
    int lfd = sock_listen_loopback(inv->signal_port, &lport, err, sizeof err);
    if (lfd < 0)
        return;                       /* déjà pris : on tentera la connexion */

    pthread_t th;
    if (pthread_create(&th, NULL, local_signal_thread, (void *)(intptr_t)lfd) == 0)
        pthread_detach(th);
    else
        close(lfd);
}

static int run_signal_server(int port)
{
    char err[256] = "";
    int lport = 0;
    int lfd = sock_listen(port, &lport, err, sizeof err);
    if (lfd < 0) {
        fprintf(stderr, "Serveur de signalisation : %s\n", err);
        return 1;
    }
    printf("Serveur de signalisation SILLAGE sur 0.0.0.0:%d\n", lport);
    printf("Il ne relaie que les descriptions de session (SDP) et aucun fichier.\n");
    printf("Les clés et le code de partage ne quittent jamais les machines.\n");
    fflush(stdout);
    signal_accept_loop(lfd, NULL);
    close(lfd);
    return 0;
}

/* ===================================================================== */
/*  PeerConnection WebRTC et échange SDP authentifié                     */
/* ===================================================================== */

static pthread_once_t g_rtc_once = PTHREAD_ONCE_INIT;

static void rtc_global_init(void)
{
    rtcInitLogger(RTC_LOG_WARNING, NULL);

    /* WebRTC/DataChannel sur Internet : les fenêtres SCTP par défaut (1 Mio)
     * brident le débit dès que le RTT dépasse quelques dizaines de ms. On
     * élargit les tampons et on active HSTCP, prévu pour les liens à fort
     * produit bande passante × délai. Réglage global, appliqué aux nouvelles
     * PeerConnections. */
    rtcSctpSettings sctp;
    memset(&sctp, 0, sizeof sctp);
    sctp.recvBufferSize = 8 * 1024 * 1024;
    sctp.sendBufferSize = 8 * 1024 * 1024;
    sctp.maxChunksOnQueue = 32 * 1024;
    sctp.initialCongestionWindow = 32;
    sctp.maxBurst = 32;
    sctp.congestionControlModule = 1;   /* HSTCP */
    sctp.delayedSackTimeMs = 10;
    (void)rtcSetSctpSettings(&sctp);
}

static int rtc_create_pc(Stream *s, const Invite *inv, int receiver,
                         char *err, size_t errlen)
{
    pthread_once(&g_rtc_once, rtc_global_init);

    char stun_url[300];
    const char *url = NULL;
    if (inv->stun[0]) {
        if (strncmp(inv->stun, "stun:", 5) == 0 ||
            strncmp(inv->stun, "turn:", 5) == 0)
            snprintf(stun_url, sizeof stun_url, "%s", inv->stun);
        else
            snprintf(stun_url, sizeof stun_url, "stun:%s", inv->stun);
        url = stun_url;
    }

    rtcConfiguration cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.iceServers = url ? &url : NULL;
    cfg.iceServersCount = url ? 1 : 0;
    cfg.certificateType = RTC_CERTIFICATE_ECDSA;
    cfg.disableAutoNegotiation = true;
    /* Messages DataChannel plus grands : moins d'appels SCTP par trame de
     * 1 Mio. La valeur est annoncée dans le SDP et négociée avec le pair. */
    cfg.maxMessageSize = 256 * 1024;

    int pc = rtcCreatePeerConnection(&cfg);
    if (pc <= 0) {
        snprintf(err, errlen, "Impossible de créer la connexion WebRTC.");
        return -1;
    }
    rtcSetUserPointer(pc, s);
    rtcSetGatheringStateChangeCallback(pc, stream_on_gather);
    rtcSetStateChangeCallback(pc, stream_on_pc_state);
    if (receiver)
        rtcSetDataChannelCallback(pc, rtc_incoming_dc);
    return pc;
}

/* Le SDP est signé avec une clé dérivée du code : même un serveur de
 * signalisation malveillant ne peut pas le remplacer sans être détecté. */
static int blob_seal(const Invite *inv, int role, const char *sdp,
                     uint8_t *out, size_t cap, size_t *outlen)
{
    size_t n = strlen(sdp);
    if (n + 5 + HMAC_LEN > cap)
        return -1;
    out[0] = (uint8_t)(role & 1);
    put_u32(out + 1, (uint32_t)n);
    memcpy(out + 5, sdp, n);

    uint8_t *msg = malloc(n + 1);
    if (!msg)
        return -1;
    msg[0] = (uint8_t)(role & 1);
    memcpy(msg + 1, sdp, n);
    uint8_t mac[HMAC_LEN];
    hmac_sha256(inv->auth, sizeof inv->auth, msg, n + 1, mac);
    free(msg);
    memcpy(out + 5 + n, mac, HMAC_LEN);
    *outlen = 5 + n + HMAC_LEN;
    return 0;
}

static int blob_open(const Invite *inv, int role, const uint8_t *in, size_t len,
                     char *sdp, size_t cap)
{
    if (len < 5 + HMAC_LEN || in[0] != (uint8_t)(role & 1))
        return -1;
    uint32_t n = get_u32(in + 1);
    if ((size_t)n + 5 + HMAC_LEN != len || (size_t)n + 1 > cap)
        return -1;

    uint8_t *msg = malloc((size_t)n + 1);
    if (!msg)
        return -1;
    msg[0] = (uint8_t)(role & 1);
    memcpy(msg + 1, in + 5, n);
    uint8_t mac[HMAC_LEN];
    hmac_sha256(inv->auth, sizeof inv->auth, msg, (size_t)n + 1, mac);
    free(msg);
    if (CRYPTO_memcmp(mac, in + 5 + n, HMAC_LEN) != 0)
        return -1;

    memcpy(sdp, in + 5, n);
    sdp[n] = '\0';
    return 0;
}

static double invite_wait_seconds(const Invite *inv, double fallback)
{
    if (inv->expires_at) {
        int64_t left = (int64_t)inv->expires_at - (int64_t)wall_now();
        if (left <= 0)
            return 0;
        return (double)left + 10.0;
    }
    return fallback;
}

static int rtc_offer_legacy(const Invite *inv, Job *job, Stream **out,
                            char *err, size_t errlen)
{
    ensure_local_signal_server(inv);
    Stream *s = stream_new(job);
    if (!s) {
        snprintf(err, errlen, "Mémoire insuffisante.");
        return -1;
    }
    s->opened = 0;

    int pc = rtc_create_pc(s, inv, 0, err, errlen);
    if (pc < 0) {
        stream_destroy(s);
        return -1;
    }
    s->pc = pc;

    int dc = rtcCreateDataChannel(pc, "sillage");
    if (dc <= 0) {
        snprintf(err, errlen, "Impossible d'ouvrir le canal de données.");
        stream_destroy(s);
        return -1;
    }
    stream_bind_dc(s, dc);

    if (rtcSetLocalDescription(pc, "offer") < 0 ||
        !stream_wait_gather(s, 15000)) {
        snprintf(err, errlen, "Échec de la collecte des candidats ICE (STUN).");
        stream_destroy(s);
        return -1;
    }

    uint8_t *sdp = malloc(SIGNAL_MAX_BLOB);
    uint8_t *blob = malloc(SIGNAL_MAX_BLOB);
    uint8_t *resp = malloc(SIGNAL_MAX_BLOB);
    if (!sdp || !blob || !resp) {
        free(sdp); free(blob); free(resp);
        snprintf(err, errlen, "Mémoire insuffisante.");
        stream_destroy(s);
        return -1;
    }

    int n = rtcGetLocalDescription(pc, (char *)sdp, SIGNAL_MAX_BLOB);
    size_t blen = 0;
    if (n <= 0 || blob_seal(inv, 0, (const char *)sdp, blob, SIGNAL_MAX_BLOB, &blen) != 0) {
        free(sdp); free(blob); free(resp);
        snprintf(err, errlen, "Description de session locale indisponible.");
        stream_destroy(s);
        return -1;
    }

    if (signal_publish(inv, 0, blob, blen, job, err, errlen) != 0) {
        free(sdp); free(blob); free(resp);
        stream_destroy(s);
        return -1;
    }

    double deadline = mono_now() + invite_wait_seconds(inv, 900.0);
    int got = 0;
    size_t rlen = 0;
    while (mono_now() < deadline) {
        if (job && job_cancelled(job))
            break;
        int rc = signal_fetch(inv, 1, resp, SIGNAL_MAX_BLOB, &rlen, job, err, errlen);
        if (rc == 1) { got = 1; break; }
        if (rc < 0 && job && job_cancelled(job))
            break;
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 400000000 };
        nanosleep(&ts, NULL);
    }
    if (!got) {
        free(sdp); free(blob); free(resp);
        snprintf(err, errlen, job && job_cancelled(job)
                 ? "Partage annulé." : "Aucun destinataire ne s'est connecté.");
        stream_destroy(s);
        return -1;
    }

    int ok = blob_open(inv, 1, resp, rlen, (char *)sdp, SIGNAL_MAX_BLOB);
    if (ok == 0)
        ok = rtcSetRemoteDescription(pc, (const char *)sdp, "answer") >= 0 ? 0 : -1;
    free(sdp);
    free(blob);
    free(resp);

    if (ok != 0) {
        snprintf(err, errlen, "Réponse de session invalide ou altérée.");
        stream_destroy(s);
        return -1;
    }
    if (!stream_wait_open(s, 60000)) {
        pthread_mutex_lock(&s->mu);
        snprintf(err, errlen, "%s", s->errmsg[0] ? s->errmsg :
                 "La connexion directe n'a pas pu s'établir (NAT restrictif).");
        pthread_mutex_unlock(&s->mu);
        stream_destroy(s);
        return -1;
    }
    *out = s;
    return 0;
}

static int rtc_answer_legacy(const Invite *inv, Job *job, Stream **out,
                             char *err, size_t errlen)
{
    ensure_local_signal_server(inv);
    Stream *s = stream_new(job);
    if (!s) {
        snprintf(err, errlen, "Mémoire insuffisante.");
        return -1;
    }
    s->opened = 0;

    int pc = rtc_create_pc(s, inv, 1, err, errlen);
    if (pc < 0) {
        stream_destroy(s);
        return -1;
    }
    s->pc = pc;

    uint8_t *offer = malloc(SIGNAL_MAX_BLOB);
    uint8_t *sdp = malloc(SIGNAL_MAX_BLOB);
    uint8_t *blob = malloc(SIGNAL_MAX_BLOB);
    if (!offer || !sdp || !blob) {
        free(offer); free(sdp); free(blob);
        snprintf(err, errlen, "Mémoire insuffisante.");
        stream_destroy(s);
        return -1;
    }

    double deadline = mono_now() + invite_wait_seconds(inv, 120.0);
    int got = 0;
    size_t olen = 0;
    while (mono_now() < deadline) {
        if (job && job_cancelled(job))
            break;
        int rc = signal_fetch(inv, 0, offer, SIGNAL_MAX_BLOB, &olen, job, err, errlen);
        if (rc == 1) { got = 1; break; }
        if (rc < 0 && job && job_cancelled(job))
            break;
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 400000000 };
        nanosleep(&ts, NULL);
    }
    if (!got) {
        free(offer); free(sdp); free(blob);
        snprintf(err, errlen, "Partage introuvable ou expiré sur le serveur de signalisation.");
        stream_destroy(s);
        return -1;
    }
    if (blob_open(inv, 0, offer, olen, (char *)sdp, SIGNAL_MAX_BLOB) != 0) {
        free(offer); free(sdp); free(blob);
        snprintf(err, errlen, "Offre de session invalide ou altérée.");
        stream_destroy(s);
        return -1;
    }
    if (rtcSetRemoteDescription(pc, (const char *)sdp, "offer") < 0) {
        free(offer); free(sdp); free(blob);
        snprintf(err, errlen, "Offre de session refusée.");
        stream_destroy(s);
        return -1;
    }
    if (rtcSetLocalDescription(pc, "answer") < 0 ||
        !stream_wait_gather(s, 15000)) {
        free(offer); free(sdp); free(blob);
        snprintf(err, errlen, "Échec de la collecte des candidats ICE (STUN).");
        stream_destroy(s);
        return -1;
    }
    int n = rtcGetLocalDescription(pc, (char *)sdp, SIGNAL_MAX_BLOB);
    size_t blen = 0;
    if (n <= 0 || blob_seal(inv, 1, (const char *)sdp, blob, SIGNAL_MAX_BLOB, &blen) != 0) {
        free(offer); free(sdp); free(blob);
        snprintf(err, errlen, "Description de session locale indisponible.");
        stream_destroy(s);
        return -1;
    }
    int pub = signal_publish(inv, 1, blob, blen, job, err, errlen);
    free(offer);
    free(sdp);
    free(blob);
    if (pub != 0) {
        stream_destroy(s);
        return -1;
    }
    if (!stream_wait_open(s, 60000)) {
        pthread_mutex_lock(&s->mu);
        snprintf(err, errlen, "%s", s->errmsg[0] ? s->errmsg :
                 "La connexion directe n'a pas pu s'établir (NAT restrictif).");
        pthread_mutex_unlock(&s->mu);
        stream_destroy(s);
        return -1;
    }
    *out = s;
    return 0;
}

/* ===================================================================== */
/*  Signalisation PeerJS Cloud (WebSocket, compatible PeerServer)        */
/*                                                                       */
/*  PeerJS Cloud ne sert qu'à échanger des descriptions de session. Les  */
/*  SDP restent signés par une clé dérivée du code de partage, et le     */
/*  fichier reste chiffré de bout en bout par BRUME-512. PeerJS ne voit  */
/*  ni le code, ni les clés, ni le contenu.                              */
/* ===================================================================== */

#define PEERJS_QUEUE_MAX 32
#define PEERJS_VERSION   "1.5.4"

typedef struct {
    pthread_mutex_t mu;
    pthread_cond_t cv;
    int ws;
    int open;
    int closed;
    int failed;
    int destroying;
    char error[256];
    char *queue[PEERJS_QUEUE_MAX];
    int qhead, qtail, qcount;
    double last_ping;
} PeerJS;

static void pj_on_open(int ws, void *ptr)
{
    (void)ws;
    PeerJS *p = (PeerJS *)ptr;
    pthread_mutex_lock(&p->mu);
    p->open = 1;
    pthread_cond_broadcast(&p->cv);
    pthread_mutex_unlock(&p->mu);
}

static void pj_on_closed(int ws, void *ptr)
{
    (void)ws;
    PeerJS *p = (PeerJS *)ptr;
    pthread_mutex_lock(&p->mu);
    p->open = 0;
    p->closed = 1;
    pthread_cond_broadcast(&p->cv);
    pthread_mutex_unlock(&p->mu);
}

static void pj_on_error(int ws, const char *error, void *ptr)
{
    (void)ws;
    PeerJS *p = (PeerJS *)ptr;
    pthread_mutex_lock(&p->mu);
    if (!p->destroying) {
        p->failed = 1;
        snprintf(p->error, sizeof p->error, "%s", error ? error : "Erreur WebSocket");
    }
    pthread_cond_broadcast(&p->cv);
    pthread_mutex_unlock(&p->mu);
}

static void pj_on_message(int ws, const char *message, int size, void *ptr)
{
    (void)ws;
    if (size >= 0 || !message)          /* PeerJS utilise des messages texte */
        return;
    int n = -size - 1;                  /* la taille inclut le zéro final */
    if (n <= 0)
        return;
    char *copy = malloc((size_t)n + 1);
    if (!copy)
        return;
    memcpy(copy, message, (size_t)n);
    copy[n] = '\0';

    PeerJS *p = (PeerJS *)ptr;
    pthread_mutex_lock(&p->mu);
    if (p->destroying) {
        pthread_mutex_unlock(&p->mu);
        free(copy);
        return;
    }
    if (p->qcount == PEERJS_QUEUE_MAX) {
        free(p->queue[p->qhead]);
        p->queue[p->qhead] = NULL;
        p->qhead = (p->qhead + 1) % PEERJS_QUEUE_MAX;
        p->qcount--;
    }
    p->queue[p->qtail] = copy;
    p->qtail = (p->qtail + 1) % PEERJS_QUEUE_MAX;
    p->qcount++;
    pthread_cond_broadcast(&p->cv);
    pthread_mutex_unlock(&p->mu);
}

static void pj_destroy(PeerJS *p)
{
    if (!p)
        return;
    pthread_mutex_lock(&p->mu);
    p->destroying = 1;
    int ws = p->ws;
    p->ws = 0;
    p->open = 0;
    p->closed = 1;
    for (int i = 0; i < PEERJS_QUEUE_MAX; i++) {
        free(p->queue[i]);
        p->queue[i] = NULL;
    }
    p->qhead = p->qtail = p->qcount = 0;
    pthread_cond_broadcast(&p->cv);
    pthread_mutex_unlock(&p->mu);

    if (ws > 0) {
        rtcSetMessageCallback(ws, NULL);
        rtcSetOpenCallback(ws, NULL);
        rtcSetClosedCallback(ws, NULL);
        rtcSetErrorCallback(ws, NULL);
        rtcDeleteWebSocket(ws);
    }
    pthread_mutex_destroy(&p->mu);
    pthread_cond_destroy(&p->cv);
    memset(p, 0, sizeof *p);
}

static int pj_send(PeerJS *p, const char *json, char *err, size_t errlen)
{
    int ws, open;
    pthread_mutex_lock(&p->mu);
    ws = p->ws;
    open = p->open && !p->closed && !p->destroying;
    pthread_mutex_unlock(&p->mu);
    if (!open || ws <= 0) {
        snprintf(err, errlen, "Connexion PeerJS fermée.");
        return -1;
    }
    if (rtcSendMessage(ws, json, -1) != 0) {
        snprintf(err, errlen, "Impossible d'envoyer le message PeerJS.");
        return -1;
    }
    return 0;
}

static void pj_heartbeat(PeerJS *p)
{
    double now = mono_now();
    int ws = 0;
    pthread_mutex_lock(&p->mu);
    if (now - p->last_ping >= 5.0 && p->open && !p->closed && !p->destroying) {
        p->last_ping = now;
        ws = p->ws;
    }
    pthread_mutex_unlock(&p->mu);
    if (ws > 0)
        (void)rtcSendMessage(ws, "{\"type\":\"HEARTBEAT\"}", -1);
}

static char *pj_pop(PeerJS *p, double timeout_s)
{
    struct timespec ts;
    ts_add_ms(&ts, (int)(timeout_s * 1000.0));
    pthread_mutex_lock(&p->mu);
    double deadline = mono_now() + timeout_s;
    while (p->qcount == 0 && !p->failed && !p->closed && !p->destroying) {
        if (mono_now() >= deadline)
            break;
        if (pthread_cond_timedwait(&p->cv, &p->mu, &ts) == ETIMEDOUT)
            break;
    }
    char *msg = NULL;
    if (p->qcount > 0) {
        msg = p->queue[p->qhead];
        p->queue[p->qhead] = NULL;
        p->qhead = (p->qhead + 1) % PEERJS_QUEUE_MAX;
        p->qcount--;
    }
    pthread_mutex_unlock(&p->mu);
    return msg;
}

static int pj_connect(const Invite *inv, const char *id, const char *token,
                      PeerJS *p, Job *job, char *err, size_t errlen)
{
    memset(p, 0, sizeof *p);
    pthread_mutex_init(&p->mu, NULL);
    pthread_cond_init(&p->cv, NULL);
    p->last_ping = mono_now();

    const char *key = getenv("SILLAGE_PEERJS_KEY");
    if (!key || !*key)
        key = "peerjs";
    int secure = (inv->signal_port == 443);
    char url[1200];
    snprintf(url, sizeof url,
             "%s://%s:%d/peerjs?key=%s&id=%s&token=%s&version=%s",
             secure ? "wss" : "ws", inv->signal_host, inv->signal_port,
             key, id, token, PEERJS_VERSION);

    int ws = rtcCreateWebSocket(url);
    if (ws <= 0) {
        snprintf(err, errlen, "Impossible d'ouvrir la connexion PeerJS Cloud.");
        pthread_mutex_destroy(&p->mu);
        pthread_cond_destroy(&p->cv);
        return -1;
    }
    p->ws = ws;
    rtcSetUserPointer(ws, p);
    rtcSetOpenCallback(ws, pj_on_open);
    rtcSetClosedCallback(ws, pj_on_closed);
    rtcSetErrorCallback(ws, pj_on_error);
    rtcSetMessageCallback(ws, pj_on_message);

    double deadline = mono_now() + 25.0;
    pthread_mutex_lock(&p->mu);
    while (!p->open && !p->failed && !p->closed && mono_now() < deadline) {
        if (job && job_cancelled(job))
            break;
        struct timespec ts;
        ts_add_ms(&ts, 200);
        pthread_cond_timedwait(&p->cv, &p->mu, &ts);
    }
    int open = p->open;
    int failed = p->failed || p->closed;
    char detail[256];
    snprintf(detail, sizeof detail, "%s", p->error);
    pthread_mutex_unlock(&p->mu);

    if (!open) {
        if (job && job_cancelled(job))
            snprintf(err, errlen, "Partage annulé.");
        else if (detail[0])
            snprintf(err, errlen, "PeerJS Cloud : %.200s", detail);
        else
            snprintf(err, errlen,
                     "Impossible de joindre PeerJS Cloud (%.120s:%d). "
                     "Vérifiez la connexion Internet.",
                     inv->signal_host, inv->signal_port);
        (void)failed;
        pj_destroy(p);
        return -1;
    }
    return 0;
}

/* Extrait le type d'un message PeerJS. Les types du serveur sont en
 * majuscules, ceux du SDP (« offer », « answer ») en minuscules : pas de
 * confusion possible. */
static int pj_message_type(const char *json, char *out, size_t cap)
{
    static const char *const types[] = {
        "OPEN", "OFFER", "ANSWER", "CANDIDATE", "LEAVE",
        "EXPIRE", "HEARTBEAT", "ID-TAKEN", "ERROR"
    };
    for (size_t i = 0; i < sizeof types / sizeof types[0]; i++) {
        char pat[40];
        snprintf(pat, sizeof pat, "\"type\":\"%s\"", types[i]);
        if (strstr(json, pat)) {
            snprintf(out, cap, "%s", types[i]);
            return 0;
        }
    }
    return -1;
}

static int pj_wait_type(PeerJS *p, const char *wanted, char **out,
                        Job *job, double deadline, char *err, size_t errlen)
{
    *out = NULL;
    while (mono_now() < deadline) {
        if (job && job_cancelled(job)) {
            snprintf(err, errlen, "Partage annulé.");
            return -1;
        }
        pj_heartbeat(p);
        char *msg = pj_pop(p, 0.25);
        if (!msg) {
            pthread_mutex_lock(&p->mu);
            int failed = p->failed;
            int closed = p->closed;
            char detail[256];
            snprintf(detail, sizeof detail, "%s", p->error);
            pthread_mutex_unlock(&p->mu);
            if (failed) {
                snprintf(err, errlen, "PeerJS Cloud : %.200s",
                         detail[0] ? detail : "connexion interrompue");
                return -1;
            }
            if (closed) {
                snprintf(err, errlen, "Connexion PeerJS Cloud fermée.");
                return -1;
            }
            continue;
        }

        char type[32];
        if (pj_message_type(msg, type, sizeof type) != 0) {
            free(msg);
            continue;
        }
        if (strcmp(type, "ERROR") == 0 || strcmp(type, "ID-TAKEN") == 0) {
            snprintf(err, errlen,
                     strcmp(type, "ID-TAKEN") == 0
                         ? "Ce code de partage est déjà utilisé. Réessayez dans un instant."
                         : "PeerJS Cloud a refusé la session.");
            free(msg);
            return -1;
        }
        if (strcmp(type, "LEAVE") == 0 || strcmp(type, "EXPIRE") == 0) {
            snprintf(err, errlen,
                     strcmp(type, "EXPIRE") == 0
                         ? "Partage introuvable ou expiré sur PeerJS Cloud."
                         : "Le destinataire s'est déconnecté.");
            free(msg);
            return -1;
        }
        if (strcmp(type, wanted) == 0) {
            *out = msg;
            return 0;
        }
        free(msg);
    }
    snprintf(err, errlen, "Délai de signalisation PeerJS dépassé.");
    return -1;
}

static int pj_valid_id(const char *s)
{
    if (!s || !*s || strlen(s) > 120)
        return 0;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (!((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') ||
              (*p >= '0' && *p <= '9') || *p == '-' || *p == '_'))
            return 0;
    }
    return 1;
}

/* Échappe une chaîne pour JSON. Renvoie une allocation à libérer. */
static char *json_escape_alloc(const char *s)
{
    if (!s)
        s = "";
    size_t n = strlen(s);
    char *out = malloc(n * 6 + 1);
    if (!out)
        return NULL;
    size_t o = 0;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        switch (*p) {
        case '"':  out[o++] = '\\'; out[o++] = '"';  break;
        case '\\': out[o++] = '\\'; out[o++] = '\\'; break;
        case '\n': out[o++] = '\\'; out[o++] = 'n';  break;
        case '\r': out[o++] = '\\'; out[o++] = 'r';  break;
        case '\t': out[o++] = '\\'; out[o++] = 't';  break;
        case '\b': out[o++] = '\\'; out[o++] = 'b';  break;
        case '\f': out[o++] = '\\'; out[o++] = 'f';  break;
        default:
            if (*p < 0x20) {
                o += (size_t)snprintf(out + o, 7, "\\u%04X", *p);
            } else {
                out[o++] = (char)*p;
            }
            break;
        }
    }
    out[o] = '\0';
    return out;
}

static int json_decode_into(const char *p, char *out, size_t cap)
{
    size_t o = 0;
    while (*p) {
        unsigned char c = (unsigned char)*p++;
        if (c == '"') {
            if (o >= cap)
                return -1;
            out[o] = '\0';
            return 0;
        }
        if (c == '\\') {
            unsigned char e = (unsigned char)*p++;
            switch (e) {
            case '"':  c = '"';  break;
            case '\\': c = '\\'; break;
            case '/':  c = '/';  break;
            case 'n':  c = '\n'; break;
            case 'r':  c = '\r'; break;
            case 't':  c = '\t'; break;
            case 'b':  c = '\b'; break;
            case 'f':  c = '\f'; break;
            case 'u': {
                unsigned int cp = 0;
                for (int i = 0; i < 4; i++) {
                    unsigned char h = (unsigned char)*p++;
                    cp <<= 4;
                    if (h >= '0' && h <= '9') cp |= h - '0';
                    else if (h >= 'a' && h <= 'f') cp |= h - 'a' + 10;
                    else if (h >= 'A' && h <= 'F') cp |= h - 'A' + 10;
                    else return -1;
                }
                if (cp >= 0xD800 && cp <= 0xDBFF) {
                    if (p[0] != '\\' || p[1] != 'u')
                        return -1;
                    p += 2;
                    unsigned int lo = 0;
                    for (int i = 0; i < 4; i++) {
                        unsigned char h = (unsigned char)*p++;
                        lo <<= 4;
                        if (h >= '0' && h <= '9') lo |= h - '0';
                        else if (h >= 'a' && h <= 'f') lo |= h - 'a' + 10;
                        else if (h >= 'A' && h <= 'F') lo |= h - 'A' + 10;
                        else return -1;
                    }
                    cp = 0x10000u + ((cp - 0xD800u) << 10) + (lo - 0xDC00u);
                }
                if (cp < 0x80) {
                    if (o + 1 >= cap) return -1;
                    out[o++] = (char)cp;
                } else if (cp < 0x800) {
                    if (o + 2 >= cap) return -1;
                    out[o++] = (char)(0xC0 | (cp >> 6));
                    out[o++] = (char)(0x80 | (cp & 0x3F));
                } else if (cp < 0x10000) {
                    if (o + 3 >= cap) return -1;
                    out[o++] = (char)(0xE0 | (cp >> 12));
                    out[o++] = (char)(0x80 | ((cp >> 6) & 0x3F));
                    out[o++] = (char)(0x80 | (cp & 0x3F));
                } else {
                    if (o + 4 >= cap) return -1;
                    out[o++] = (char)(0xF0 | (cp >> 18));
                    out[o++] = (char)(0x80 | ((cp >> 12) & 0x3F));
                    out[o++] = (char)(0x80 | ((cp >> 6) & 0x3F));
                    out[o++] = (char)(0x80 | (cp & 0x3F));
                }
                continue;
            }
            default:
                return -1;
            }
        }
        if (o + 1 >= cap)
            return -1;
        out[o++] = (char)c;
    }
    return -1;
}

/* Cherche `"clé":"valeur"` et décode la valeur. */
static int json_get_string(const char *json, const char *pattern,
                           char *out, size_t cap)
{
    const char *p = strstr(json, pattern);
    if (!p)
        return -1;
    return json_decode_into(p + strlen(pattern), out, cap);
}

static void sdp_sign_hex(const Invite *inv, int role, const char *sdp,
                         char out[HMAC_LEN * 2 + 1])
{
    size_t n = strlen(sdp);
    uint8_t *msg = malloc(n + 1);
    uint8_t mac[HMAC_LEN];
    if (!msg) {
        out[0] = '\0';
        return;
    }
    msg[0] = (uint8_t)(role & 1);
    memcpy(msg + 1, sdp, n);
    hmac_sha256(inv->auth, sizeof inv->auth, msg, n + 1, mac);
    free(msg);
    hex_encode(mac, HMAC_LEN, out);
}

static int sdp_verify_hex(const Invite *inv, int role, const char *sdp,
                          const char *sig)
{
    if (!sig || strlen(sig) != HMAC_LEN * 2)
        return -1;
    char expect[HMAC_LEN * 2 + 1];
    sdp_sign_hex(inv, role, sdp, expect);
    if (strlen(expect) != HMAC_LEN * 2)
        return -1;
    return CRYPTO_memcmp(expect, sig, HMAC_LEN * 2) == 0 ? 0 : -1;
}

static char *peerjs_build_sdp(const char *type, const char *dst,
                              const char *sdp_type, const char *sdp,
                              const char *sig)
{
    char *esc = json_escape_alloc(sdp);
    if (!esc)
        return NULL;
    size_t cap = strlen(esc) + strlen(dst) + strlen(sig) + 512;
    char *out = malloc(cap);
    if (out)
        snprintf(out, cap,
                 "{\"type\":\"%s\",\"dst\":\"%s\",\"payload\":{"
                 "\"sdp\":{\"type\":\"%s\",\"sdp\":\"%s\"},"
                 "\"type\":\"data\",\"connectionId\":\"sillage\","
                 "\"label\":\"sillage\",\"reliable\":true,"
                 "\"serialization\":\"raw\",\"sillage_sig\":\"%s\"}}",
                 type, dst, sdp_type, esc, sig);
    free(esc);
    return out;
}

static void peerjs_sender_peer_id(const Invite *inv, char *out, size_t cap)
{
    char h[INVITE_ID_LEN * 2 + 1];
    hex_encode(inv->room, sizeof inv->room, h);
    snprintf(out, cap, "sillage-%s", h);
}

/* Callee : le destinataire initie l'offre, l'émetteur répond. */
static int peerjs_sender_session(const Invite *inv, Job *job, Stream **out,
                                 char *err, size_t errlen)
{
    char peer_id[80], token[80];
    char h[INVITE_ID_LEN * 2 + 1];
    peerjs_sender_peer_id(inv, peer_id, sizeof peer_id);
    hex_encode(inv->token, sizeof inv->token, h);
    snprintf(token, sizeof token, "%s", h);

    PeerJS pj;
    if (pj_connect(inv, peer_id, token, &pj, job, err, errlen) != 0)
        return -1;
    char *open_msg = NULL;
    int rc = pj_wait_type(&pj, "OPEN", &open_msg, job,
                          mono_now() + 15.0, err, errlen);
    free(open_msg);
    if (rc != 0) {
        pj_destroy(&pj);
        return -1;
    }

    Stream *s = stream_new(job);
    if (!s) {
        snprintf(err, errlen, "Mémoire insuffisante.");
        pj_destroy(&pj);
        return -1;
    }
    s->opened = 0;

    int pc = rtc_create_pc(s, inv, 1, err, errlen);
    if (pc < 0) {
        stream_destroy(s);
        pj_destroy(&pj);
        return -1;
    }
    s->pc = pc;

    char *offer = NULL;
    rc = pj_wait_type(&pj, "OFFER", &offer, job,
                      mono_now() + invite_wait_seconds(inv, 900.0),
                      err, errlen);
    if (rc != 0) {
        if (!(job && job_cancelled(job)) && err[0] &&
            strstr(err, "Délai de signalisation"))
            snprintf(err, errlen, "Aucun destinataire ne s'est connecté.");
        stream_destroy(s);
        pj_destroy(&pj);
        return -1;
    }

    char src[160] = "", sig[128] = "";
    char *sdp = malloc(SIGNAL_MAX_BLOB);
    if (!sdp ||
        json_get_string(offer, "\"src\":\"", src, sizeof src) != 0 ||
        json_get_string(offer, "\"sdp\":\"", sdp, SIGNAL_MAX_BLOB) != 0 ||
        json_get_string(offer, "\"sillage_sig\":\"", sig, sizeof sig) != 0 ||
        !pj_valid_id(src)) {
        free(offer);
        free(sdp);
        snprintf(err, errlen, "Offre PeerJS incomplète ou invalide.");
        stream_destroy(s);
        pj_destroy(&pj);
        return -1;
    }
    free(offer);

    if (sdp_verify_hex(inv, 0, sdp, sig) != 0) {
        free(sdp);
        snprintf(err, errlen, "Offre de session invalide ou altérée.");
        stream_destroy(s);
        pj_destroy(&pj);
        return -1;
    }
    if (rtcSetRemoteDescription(pc, sdp, "offer") < 0) {
        free(sdp);
        snprintf(err, errlen, "Offre de session refusée.");
        stream_destroy(s);
        pj_destroy(&pj);
        return -1;
    }
    if (rtcSetLocalDescription(pc, "answer") < 0 ||
        !stream_wait_gather(s, 15000)) {
        free(sdp);
        snprintf(err, errlen, "Échec de la collecte des candidats ICE (STUN).");
        stream_destroy(s);
        pj_destroy(&pj);
        return -1;
    }
    int n = rtcGetLocalDescription(pc, sdp, SIGNAL_MAX_BLOB);
    if (n <= 0) {
        free(sdp);
        snprintf(err, errlen, "Description de session locale indisponible.");
        stream_destroy(s);
        pj_destroy(&pj);
        return -1;
    }
    sdp_sign_hex(inv, 1, sdp, sig);
    char *json = peerjs_build_sdp("ANSWER", src, "answer", sdp, sig);
    free(sdp);
    if (!json) {
        snprintf(err, errlen, "Mémoire insuffisante.");
        stream_destroy(s);
        pj_destroy(&pj);
        return -1;
    }
    rc = pj_send(&pj, json, err, errlen);
    free(json);
    if (rc != 0) {
        stream_destroy(s);
        pj_destroy(&pj);
        return -1;
    }

    if (!stream_wait_open(s, 60000)) {
        pthread_mutex_lock(&s->mu);
        snprintf(err, errlen, "%s", s->errmsg[0] ? s->errmsg :
                 "La connexion directe n'a pas pu s'établir (NAT restrictif).");
        pthread_mutex_unlock(&s->mu);
        stream_destroy(s);
        pj_destroy(&pj);
        return -1;
    }
    pj_destroy(&pj);
    *out = s;
    return 0;
}

/* Caller : le destinataire se connecte à l'émetteur et envoie l'offre. */
static int peerjs_receiver_session(const Invite *inv, Job *job, Stream **out,
                                   char *err, size_t errlen)
{
    uint8_t rnd[16];
    char rh[sizeof rnd * 2 + 1], th[sizeof rnd * 2 + 1];
    if (sys_random(rnd, sizeof rnd) != 0) {
        snprintf(err, errlen, "Générateur aléatoire indisponible.");
        return -1;
    }
    hex_encode(rnd, sizeof rnd, rh);
    if (sys_random(rnd, sizeof rnd) != 0) {
        snprintf(err, errlen, "Générateur aléatoire indisponible.");
        return -1;
    }
    hex_encode(rnd, sizeof rnd, th);
    secure_zero(rnd, sizeof rnd);

    char peer_id[80], token[80], sender_id[80];
    snprintf(peer_id, sizeof peer_id, "sillage-r-%s", rh);
    snprintf(token, sizeof token, "%s", th);
    peerjs_sender_peer_id(inv, sender_id, sizeof sender_id);

    PeerJS pj;
    if (pj_connect(inv, peer_id, token, &pj, job, err, errlen) != 0)
        return -1;
    char *open_msg = NULL;
    int rc = pj_wait_type(&pj, "OPEN", &open_msg, job,
                          mono_now() + 15.0, err, errlen);
    free(open_msg);
    if (rc != 0) {
        pj_destroy(&pj);
        return -1;
    }

    Stream *s = stream_new(job);
    if (!s) {
        snprintf(err, errlen, "Mémoire insuffisante.");
        pj_destroy(&pj);
        return -1;
    }
    s->opened = 0;

    int pc = rtc_create_pc(s, inv, 0, err, errlen);
    if (pc < 0) {
        stream_destroy(s);
        pj_destroy(&pj);
        return -1;
    }
    s->pc = pc;

    int dc = rtcCreateDataChannel(pc, "sillage");
    if (dc <= 0) {
        snprintf(err, errlen, "Impossible d'ouvrir le canal de données.");
        stream_destroy(s);
        pj_destroy(&pj);
        return -1;
    }
    stream_bind_dc(s, dc);

    if (rtcSetLocalDescription(pc, "offer") < 0 ||
        !stream_wait_gather(s, 15000)) {
        snprintf(err, errlen, "Échec de la collecte des candidats ICE (STUN).");
        stream_destroy(s);
        pj_destroy(&pj);
        return -1;
    }

    char *sdp = malloc(SIGNAL_MAX_BLOB);
    char sig[HMAC_LEN * 2 + 1];
    if (!sdp) {
        snprintf(err, errlen, "Mémoire insuffisante.");
        stream_destroy(s);
        pj_destroy(&pj);
        return -1;
    }
    int n = rtcGetLocalDescription(pc, sdp, SIGNAL_MAX_BLOB);
    if (n <= 0) {
        free(sdp);
        snprintf(err, errlen, "Description de session locale indisponible.");
        stream_destroy(s);
        pj_destroy(&pj);
        return -1;
    }
    sdp_sign_hex(inv, 0, sdp, sig);
    char *json = peerjs_build_sdp("OFFER", sender_id, "offer", sdp, sig);
    free(sdp);
    if (!json) {
        snprintf(err, errlen, "Mémoire insuffisante.");
        stream_destroy(s);
        pj_destroy(&pj);
        return -1;
    }
    rc = pj_send(&pj, json, err, errlen);
    free(json);
    if (rc != 0) {
        stream_destroy(s);
        pj_destroy(&pj);
        return -1;
    }

    char *answer = NULL;
    rc = pj_wait_type(&pj, "ANSWER", &answer, job,
                      mono_now() + invite_wait_seconds(inv, 120.0),
                      err, errlen);
    if (rc != 0) {
        stream_destroy(s);
        pj_destroy(&pj);
        return -1;
    }

    char src[160] = "";
    sdp = malloc(SIGNAL_MAX_BLOB);
    if (!sdp ||
        json_get_string(answer, "\"src\":\"", src, sizeof src) != 0 ||
        json_get_string(answer, "\"sdp\":\"", sdp, SIGNAL_MAX_BLOB) != 0 ||
        json_get_string(answer, "\"sillage_sig\":\"", sig, sizeof sig) != 0 ||
        strcmp(src, sender_id) != 0) {
        free(answer);
        free(sdp);
        snprintf(err, errlen, "Réponse PeerJS incomplète ou invalide.");
        stream_destroy(s);
        pj_destroy(&pj);
        return -1;
    }
    free(answer);

    if (sdp_verify_hex(inv, 1, sdp, sig) != 0) {
        free(sdp);
        snprintf(err, errlen, "Réponse de session invalide ou altérée.");
        stream_destroy(s);
        pj_destroy(&pj);
        return -1;
    }
    if (rtcSetRemoteDescription(pc, sdp, "answer") < 0) {
        free(sdp);
        snprintf(err, errlen, "Réponse de session refusée.");
        stream_destroy(s);
        pj_destroy(&pj);
        return -1;
    }
    free(sdp);

    if (!stream_wait_open(s, 60000)) {
        pthread_mutex_lock(&s->mu);
        snprintf(err, errlen, "%s", s->errmsg[0] ? s->errmsg :
                 "La connexion directe n'a pas pu s'établir (NAT restrictif).");
        pthread_mutex_unlock(&s->mu);
        stream_destroy(s);
        pj_destroy(&pj);
        return -1;
    }
    pj_destroy(&pj);
    *out = s;
    return 0;
}

static int rtc_offer(const Invite *inv, Job *job, Stream **out,
                     char *err, size_t errlen)
{
    if (inv->sig_peerjs)
        return peerjs_sender_session(inv, job, out, err, errlen);
    return rtc_offer_legacy(inv, job, out, err, errlen);
}

static int rtc_answer(const Invite *inv, Job *job, Stream **out,
                      char *err, size_t errlen)
{
    if (inv->sig_peerjs)
        return peerjs_receiver_session(inv, job, out, err, errlen);
    return rtc_answer_legacy(inv, job, out, err, errlen);
}

/* ===================================================================== */
/*  Trames AEAD                                                          */
/* ===================================================================== */

static bool frame_send(Stream *st, Job *job, const uint8_t key[KEY_LEN],
                       const uint8_t prefix[NONCE_PREFIX_LEN], const uint8_t id[INVITE_ID_LEN],
                       uint64_t index, uint64_t total, const uint8_t *pt, uint32_t len,
                       uint8_t *scratch)
{
    (void)job;
    uint8_t nonce[NONCE_LEN], aad[40], tag[TAG_LEN], hdr[4];
    make_nonce(nonce, prefix, index);
    make_aad(aad, id, index, len, total);
    if (sl_aead_encrypt(AEAD_PROFILE, key, nonce, aad, sizeof aad, pt, len, scratch, tag) != 0)
        return false;
    memcpy(scratch + len, tag, TAG_LEN);
    put_u32(hdr, len);
    return stream_write(st, hdr, sizeof hdr) &&
           stream_write(st, scratch, (size_t)len + TAG_LEN);
}

/* 0 = ok, -1 = io, -2 = trame invalide / tag incorrect */
static int frame_recv(Stream *st, Job *job, const uint8_t key[KEY_LEN],
                      const uint8_t prefix[NONCE_PREFIX_LEN], const uint8_t id[INVITE_ID_LEN],
                      uint64_t index, uint64_t total, uint8_t *out, uint32_t maxlen,
                      uint32_t *outlen, uint8_t *scratch)
{
    (void)job;
    uint8_t hdr[4];
    if (!stream_read(st, hdr, sizeof hdr))
        return -1;
    uint32_t len = get_u32(hdr);
    if (len > maxlen)
        return -2;
    if (!stream_read(st, scratch, (size_t)len + TAG_LEN))
        return -1;
    uint8_t nonce[NONCE_LEN], aad[40];
    make_nonce(nonce, prefix, index);
    make_aad(aad, id, index, len, total);
    int rc = sl_aead_decrypt(AEAD_PROFILE, key, nonce, aad, sizeof aad,
                             scratch, len, scratch + len, out);
    if (rc != 0)
        return -2;
    *outlen = len;
    return 0;
}

/* ===================================================================== */
/*  Protocole                                                            */
/* ===================================================================== */

static void build_auth_message(uint8_t msg[8 + INVITE_ID_LEN + CHALLENGE_LEN],
                               const uint8_t id[INVITE_ID_LEN], const uint8_t challenge[CHALLENGE_LEN])
{
    memcpy(msg, "SLT1AUTH", 8);
    memcpy(msg + 8, id, INVITE_ID_LEN);
    memcpy(msg + 8 + INVITE_ID_LEN, challenge, CHALLENGE_LEN);
}

static int server_handshake(Stream *st, Job *job, const Invite *inv, uint64_t total,
                            uint8_t prefix[NONCE_PREFIX_LEN], char *err, size_t errlen)
{
    (void)job;
    uint8_t hdr[5], id[INVITE_ID_LEN];
    if (!stream_read(st, hdr, sizeof hdr))
        goto io;
    if (memcmp(hdr, "HELO", 4) != 0 || hdr[4] != 1) {
        snprintf(err, errlen, "Poignée de main invalide.");
        return -1;
    }
    if (!stream_read(st, id, sizeof id))
        goto io;
    if (CRYPTO_memcmp(id, inv->id, sizeof id) != 0) {
        (void)stream_write(st, "NOPE", 4);
        snprintf(err, errlen, "Invitation inconnue.");
        return -1;
    }

    uint8_t challenge[CHALLENGE_LEN];
    if (sys_random(challenge, sizeof challenge) != 0 ||
        sys_random(prefix, NONCE_PREFIX_LEN) != 0) {
        snprintf(err, errlen, "Générateur aléatoire indisponible.");
        return -1;
    }
    uint8_t out[4 + CHALLENGE_LEN + NONCE_PREFIX_LEN];
    memcpy(out, "CHAL", 4);
    memcpy(out + 4, challenge, CHALLENGE_LEN);
    memcpy(out + 4 + CHALLENGE_LEN, prefix, NONCE_PREFIX_LEN);
    if (!stream_write(st, out, sizeof out))
        goto io;

    uint8_t auth[4], mac[HMAC_LEN], expect[HMAC_LEN], msg[8 + INVITE_ID_LEN + CHALLENGE_LEN];
    if (!stream_read(st, auth, sizeof auth) || memcmp(auth, "AUTH", 4) != 0)
        goto io;
    if (!stream_read(st, mac, sizeof mac))
        goto io;
    build_auth_message(msg, inv->id, challenge);
    hmac_sha256(inv->token, TOKEN_LEN, msg, sizeof msg, expect);
    if (CRYPTO_memcmp(mac, expect, HMAC_LEN) != 0) {
        (void)stream_write(st, "NOPE", 4);
        snprintf(err, errlen, "Jeton d'authentification incorrect.");
        return -1;
    }

    uint8_t okay[4 + 8 + 4];
    memcpy(okay, "OKAY", 4);
    put_u64(okay + 4, total);
    put_u32(okay + 12, CHUNK_SIZE);
    if (!stream_write(st, okay, sizeof okay))
        goto io;

    uint8_t ready[4];
    if (!stream_read(st, ready, sizeof ready) || memcmp(ready, "READY", 4) != 0)
        goto io;
    return 0;

io:
    snprintf(err, errlen, "Connexion interrompue pendant l'authentification.");
    return -2;
}

static int server_send_file(Stream *st, Job *job, const Invite *inv, const uint8_t key[KEY_LEN],
                            const uint8_t prefix[NONCE_PREFIX_LEN], const char *path,
                            const char *name, uint64_t size, char *err, size_t errlen)
{
    int in = open(path, O_RDONLY | O_CLOEXEC);
    if (in < 0) {
        snprintf(err, errlen, "Impossible de lire le fichier source.");
        return -1;
    }
    size_t name_len = strlen(name);
    if (name_len > MAX_NAME)
        name_len = MAX_NAME;
    uint8_t meta[3 + MAX_NAME + 8];
    size_t meta_len = 0;
    meta[meta_len++] = 0;
    meta[meta_len++] = (uint8_t)(name_len >> 8);
    meta[meta_len++] = (uint8_t)name_len;
    memcpy(meta + meta_len, name, name_len);
    meta_len += name_len;
    for (int i = 0; i < 8; i++)
        meta[meta_len++] = (uint8_t)(size >> (56 - i * 8));

    uint8_t *chunk = malloc(CHUNK_SIZE);
    uint8_t *scratch = malloc(CHUNK_SIZE + TAG_LEN);
    if (!chunk || !scratch) {
        free(chunk);
        free(scratch);
        close(in);
        snprintf(err, errlen, "Mémoire insuffisante.");
        return -1;
    }

    uint8_t mscratch[3 + MAX_NAME + 8 + TAG_LEN];
    if (!frame_send(st, job, key, prefix, inv->id, 0, size, meta, (uint32_t)meta_len, mscratch)) {
        snprintf(err, errlen, "Connexion perdue avant les métadonnées.");
        goto fail;
    }
    uint8_t resp[4];
    if (!stream_read(st, resp, sizeof resp) || memcmp(resp, "REDY", 4) != 0) {
        snprintf(err, errlen, "Le destinataire a refusé le fichier.");
        goto fail;
    }

    uint64_t sent = 0;
    uint64_t index = 1;
    while (sent < size) {
        if (job_cancelled(job)) {
            snprintf(err, errlen, "Transfert annulé.");
            goto fail;
        }
        uint64_t remaining = size - sent;
        if (remaining > CHUNK_SIZE)
            remaining = CHUNK_SIZE;
        size_t want = (size_t)remaining;
        if (want == 0 || want > CHUNK_SIZE) {
            snprintf(err, errlen, "Taille de lecture incohérente.");
            goto fail;
        }
        size_t got = 0;
        while (got < want) {
            ssize_t r = read(in, chunk + got, want - got);
            if (r > 0) { got += (size_t)r; continue; }
            if (r < 0 && errno == EINTR) continue;
            snprintf(err, errlen, "Lecture du fichier source impossible.");
            goto fail;
        }
        if (!frame_send(st, job, key, prefix, inv->id, index, size, chunk, (uint32_t)got, scratch)) {
            snprintf(err, errlen, "Connexion interrompue pendant l'envoi.");
            goto fail;
        }
        sent += got;
        index++;
        job_prog(job, sent, size);
    }

    if (!stream_write(st, "END!", 4)) {
        snprintf(err, errlen, "Connexion interrompue à la fin du transfert.");
        goto fail;
    }
    uint8_t done[4];
    if (!stream_read(st, done, sizeof done) || memcmp(done, "DONE", 4) != 0) {
        snprintf(err, errlen, "Le destinataire n'a pas confirmé la réception.");
        goto fail;
    }
    free(chunk);
    free(scratch);
    close(in);
    job_prog(job, size, size);
    return 0;

fail:
    free(chunk);
    free(scratch);
    close(in);
    return -1;
}

static int client_handshake(Stream *st, Job *job, const Invite *inv, const uint8_t key[KEY_LEN],
                            uint8_t prefix[NONCE_PREFIX_LEN], uint64_t *total,
                            uint32_t *chunk, char *err, size_t errlen)
{
    (void)job;
    uint8_t helo[5 + INVITE_ID_LEN];
    memcpy(helo, "HELO", 4);
    helo[4] = 1;
    memcpy(helo + 5, inv->id, INVITE_ID_LEN);
    if (!stream_write(st, helo, sizeof helo))
        goto io;

    uint8_t chal[4 + CHALLENGE_LEN + NONCE_PREFIX_LEN];
    if (!stream_read(st, chal, sizeof chal))
        goto io;
    if (memcmp(chal, "CHAL", 4) != 0) {
        snprintf(err, errlen, "Réponse du serveur invalide.");
        return -1;
    }
    const uint8_t *challenge = chal + 4;
    memcpy(prefix, chal + 4 + CHALLENGE_LEN, NONCE_PREFIX_LEN);

    uint8_t msg[8 + INVITE_ID_LEN + CHALLENGE_LEN], mac[HMAC_LEN];
    build_auth_message(msg, inv->id, challenge);
    hmac_sha256(inv->token, TOKEN_LEN, msg, sizeof msg, mac);
    if (!stream_write(st, "AUTH", 4) || !stream_write(st, mac, sizeof mac))
        goto io;

    uint8_t head[4], tail[12];
    if (!stream_read(st, head, sizeof head))
        goto io;
    if (memcmp(head, "NOPE", 4) == 0) {
        snprintf(err, errlen, "Invitation refusée ou expirée.");
        return -1;
    }
    if (memcmp(head, "OKAY", 4) != 0) {
        snprintf(err, errlen, "Réponse du serveur invalide.");
        return -1;
    }
    if (!stream_read(st, tail, sizeof tail))
        goto io;
    *total = get_u64(tail);
    *chunk = get_u32(tail + 8);
    if (*total > MAX_FILE_SIZE) {
        snprintf(err, errlen, "Fichier annoncé trop volumineux.");
        return -1;
    }
    if (*chunk < MIN_CHUNK || *chunk > MAX_CHUNK) {
        snprintf(err, errlen, "Taille de trame invalide.");
        return -1;
    }
    if (!stream_write(st, "READY", 4))
        goto io;
    (void)key;
    return 0;

io:
    snprintf(err, errlen, "Connexion interrompue pendant l'authentification.");
    return -2;
}

static int client_receive_file(Stream *st, Job *job, const Invite *inv, const uint8_t key[KEY_LEN],
                               const uint8_t prefix[NONCE_PREFIX_LEN], const char *destdir,
                               uint64_t total, uint32_t chunk, char *err, size_t errlen)
{
    uint8_t meta[2 + MAX_NAME + 8 + 8];
    uint8_t mscratch[2 + MAX_NAME + 8 + 8 + TAG_LEN];
    uint32_t meta_len = 0;
    int rc = frame_recv(st, job, key, prefix, inv->id, 0, total, meta, sizeof meta, &meta_len, mscratch);
    if (rc == -2) {
        snprintf(err, errlen, "Déchiffrement impossible : mot de passe incorrect ou lien altéré.");
        return -1;
    }
    if (rc != 0) {
        snprintf(err, errlen, "Connexion interrompue avant les métadonnées.");
        return -1;
    }
    if (meta_len < 11 || meta[0] != 0) {
        snprintf(err, errlen, "Métadonnées invalides.");
        return -1;
    }
    size_t name_len = ((size_t)meta[1] << 8) | meta[2];
    if (name_len == 0 || name_len > MAX_NAME || meta_len != 3 + name_len + 8) {
        snprintf(err, errlen, "Nom de fichier invalide.");
        return -1;
    }
    char raw_name[MAX_NAME + 1];
    memcpy(raw_name, meta + 3, name_len);
    raw_name[name_len] = '\0';
    uint64_t announced = get_u64(meta + 3 + name_len);
    if (announced != total) {
        snprintf(err, errlen, "Taille de fichier incohérente.");
        return -1;
    }

    char name[MAX_NAME + 1];
    sanitize_filename(raw_name, name, sizeof name);
    if (ensure_dir(destdir) != 0) {
        snprintf(err, errlen, "Impossible de créer le dossier de destination.");
        return -1;
    }
    char save[PATH_MAX], part[PATH_MAX];
    unique_path(destdir, name, save, sizeof save);
    copy_path(part, sizeof part, save);
    str_append(part, sizeof part, ".part");

    int out = open(part, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (out < 0) {
        snprintf(err, errlen, "Impossible d'écrire dans le dossier de destination.");
        return -1;
    }

    job_lock(job);
    snprintf(job->filename, sizeof job->filename, "%s", name);
    snprintf(job->savepath, sizeof job->savepath, "%s", save);
    job_unlock(job);
    job_detail(job, "Enregistrement vers %s", save);

    if (!stream_write(st, "REDY", 4)) {
        snprintf(err, errlen, "Connexion interrompue.");
        close(out);
        unlink(part);
        return -1;
    }

    uint8_t *buf = malloc(chunk);
    uint8_t *scratch = malloc((size_t)chunk + TAG_LEN);
    if (!buf || !scratch) {
        free(buf);
        free(scratch);
        snprintf(err, errlen, "Mémoire insuffisante.");
        close(out);
        unlink(part);
        return -1;
    }

    uint64_t received = 0, index = 1;
    int failed = 0;
    while (received < total) {
        if (job_cancelled(job)) {
            snprintf(err, errlen, "Réception annulée.");
            failed = 1;
            break;
        }
        uint32_t got = 0;
        rc = frame_recv(st, job, key, prefix, inv->id, index, total, buf, chunk, &got, scratch);
        if (rc != 0) {
            snprintf(err, errlen, rc == -2 ? "Trame corrompue ou altérée." :
                                              "Connexion interrompue pendant la réception.");
            failed = 1;
            break;
        }
        if (got == 0) {
            snprintf(err, errlen, "Trame vide inattendue.");
            failed = 1;
            break;
        }
        size_t off = 0;
        while (off < got) {
            ssize_t w = write(out, buf + off, got - off);
            if (w > 0) { off += (size_t)w; continue; }
            if (w < 0 && errno == EINTR) continue;
            snprintf(err, errlen, "Écriture sur le disque impossible.");
            failed = 1;
            break;
        }
        if (failed) break;
        received += got;
        index++;
        job_prog(job, received, total);
    }
    free(buf);
    free(scratch);

    if (!failed) {
        uint8_t end[4];
        if (!stream_read(st, end, sizeof end) || memcmp(end, "END!", 4) != 0) {
            snprintf(err, errlen, "Fin de transfert manquante.");
            failed = 1;
        }
    }
    if (!failed && received != total) {
        snprintf(err, errlen, "Le fichier reçu est incomplet.");
        failed = 1;
    }
    if (!failed) {
        if (fdatasync(out) != 0) {
            snprintf(err, errlen, "Synchronisation disque impossible.");
            failed = 1;
        }
    }
    if (close(out) != 0 && !failed) {
        snprintf(err, errlen, "Fermeture du fichier impossible.");
        failed = 1;
    }
    if (failed) {
        unlink(part);
        return -1;
    }
    if (rename(part, save) != 0) {
        snprintf(err, errlen, "Impossible de finaliser le fichier reçu.");
        unlink(part);
        return -1;
    }
    chmod(save, 0600);
    if (!stream_write(st, "DONE", 4))
        return 0; /* fichier complet : une confirmation perdue n'est pas fatale */
    job_prog(job, total, total);
    return 0;
}

/* ===================================================================== */
/*  Threads de transfert                                                 */
/* ===================================================================== */

typedef struct {
    Job *job;
    char filepath[PATH_MAX];
    char filename[256];
    uint64_t size;
    Invite inv;
    char password[256];
    int port;
    int single_attempt;
} SendArgs;

typedef struct {
    Job *job;
    Invite inv;
    char password[256];
    char destdir[PATH_MAX];
} RecvArgs;

static void send_finish_error(Job *job, const char *err)
{
    job_set(job, JOB_ERROR, "%s", err[0] ? err : "Le transfert a échoué.");
    job_lock(job);
    job->result = -1;
    job_unlock(job);
}

static void *send_worker(void *vp)
{
    SendArgs *a = (SendArgs *)vp;
    Job *job = a->job;
    uint8_t key[KEY_LEN];
    memset(key, 0, sizeof key);
    char err[256] = "";
    int success = 0;
    int failed = 0;

    if (a->inv.has_password) {
        job_set(job, JOB_PREPARING, "Dérivation de la clé (scrypt)…");
        if (derive_password_key(a->password, a->inv.id, key, err, sizeof err) != 0)
            failed = 1;
    } else {
        memcpy(key, a->inv.key, KEY_LEN);
    }

    if (!failed && a->inv.transport == TRANSPORT_WEBRTC) {
        Stream *st = NULL;
        job_set(job, JOB_CONNECTING, "Négociation WebRTC (STUN)…");
        if (rtc_offer(&a->inv, job, &st, err, sizeof err) != 0) {
            failed = 1;
        } else {
            job_lock(job);
            snprintf(job->remote, sizeof job->remote, "WebRTC DataChannel");
            job_unlock(job);
            job_set(job, JOB_HANDSHAKE, "Canal direct établi — authentification…");
            uint8_t prefix[NONCE_PREFIX_LEN];
            int hs = server_handshake(st, job, &a->inv, a->size, prefix, err, sizeof err);
            if (hs != 0) {
                failed = 1;
            } else {
                job_set(job, JOB_TRANSFER, "Envoi de « %s »…", a->filename);
                if (server_send_file(st, job, &a->inv, key, prefix, a->filepath,
                                     a->filename, a->size, err, sizeof err) == 0)
                    success = 1;
                else
                    failed = 1;
            }
            stream_destroy(st);
        }
    } else if (!failed) {
        job_set(job, JOB_PREPARING, "Ouverture du port d'écoute…");
        int lport = 0;
        int lfd = sock_listen(a->port, &lport, err, sizeof err);
        if (lfd < 0) {
            failed = 1;
        } else {
            job_lock(job);
            job->listen_port = lport;
            job->expires_at = a->inv.expires_at;
            job_unlock(job);

            int fails = 0;
            while (!job_cancelled(job)) {
                time_t now = wall_now();
                if ((uint64_t)now > a->inv.expires_at) {
                    snprintf(err, sizeof err,
                             "Lien expiré : aucun destinataire ne s'est connecté.");
                    break;
                }
                char peer[128] = "";
                int cfd = sock_accept(lfd, 300, job, peer, sizeof peer);
                if (cfd < 0)
                    continue;
                Stream *st = stream_tcp(cfd, job);
                if (!st) {
                    snprintf(err, sizeof err, "Mémoire insuffisante.");
                    break;
                }
                job_lock(job);
                snprintf(job->remote, sizeof job->remote, "%s", peer);
                job_unlock(job);
                job_set(job, JOB_HANDSHAKE, "Connexion de %s — authentification…", peer);

                uint8_t prefix[NONCE_PREFIX_LEN];
                int hs = server_handshake(st, job, &a->inv, a->size, prefix, err, sizeof err);
                if (hs != 0) {
                    stream_destroy(st);
                    if (hs == -1) {
                        fails++;
                        if (fails >= MAX_AUTH_FAILS) {
                            snprintf(err, sizeof err, "Trop de tentatives d'authentification.");
                            break;
                        }
                        job_set(job, JOB_WAITING, "Tentative refusée — en attente…");
                        struct timespec ts = { .tv_sec = 0, .tv_nsec = 500000000 };
                        nanosleep(&ts, NULL);
                    }
                    continue;
                }

                job_set(job, JOB_TRANSFER, "Envoi de « %s »…", a->filename);
                int rc = server_send_file(st, job, &a->inv, key, prefix, a->filepath,
                                          a->filename, a->size, err, sizeof err);
                stream_destroy(st);
                if (rc == 0) {
                    success = 1;
                    break;
                }
                if (job_cancelled(job))
                    break;
                if (a->single_attempt)
                    break;
                job_set(job, JOB_WAITING, "Connexion interrompue — de nouveau en attente…");
            }
            close(lfd);
        }
    }

    if (success) {
        job_set(job, JOB_DONE, "Transfert terminé");
        job_lock(job);
        job->result = 1;
        job_unlock(job);
    } else if (job_cancelled(job)) {
        job_set(job, JOB_CANCELLED, "Partage annulé");
        job_lock(job);
        job->result = -2;
        job_unlock(job);
    } else {
        send_finish_error(job, err);
    }
    secure_zero(key, sizeof key);
    secure_zero(a->password, sizeof a->password);
    secure_zero(a, sizeof *a);
    free(a);
    job_end(job);
    return NULL;
}

static void *recv_worker(void *vp)
{
    RecvArgs *a = (RecvArgs *)vp;
    Job *job = a->job;
    uint8_t key[KEY_LEN];
    memset(key, 0, sizeof key);
    char err[256] = "";
    int failed = 0;
    Stream *st = NULL;
    uint64_t total = 0;
    uint32_t chunk = 0;
    uint8_t prefix[NONCE_PREFIX_LEN];

    if (a->inv.has_password) {
        job_set(job, JOB_PREPARING, "Dérivation de la clé (scrypt)…");
        if (derive_password_key(a->password, a->inv.id, key, err, sizeof err) != 0)
            failed = 1;
    } else {
        memcpy(key, a->inv.key, KEY_LEN);
    }

    if (!failed && a->inv.transport == TRANSPORT_WEBRTC) {
        job_set(job, JOB_CONNECTING, "Recherche du partage sur le serveur de signalisation…");
        if (rtc_answer(&a->inv, job, &st, err, sizeof err) != 0) {
            failed = 1;
        } else {
            job_lock(job);
            snprintf(job->remote, sizeof job->remote, "WebRTC DataChannel");
            job_unlock(job);
            job_set(job, JOB_HANDSHAKE, "Canal direct établi — authentification…");
            if (client_handshake(st, job, &a->inv, key, prefix, &total, &chunk,
                                 err, sizeof err) != 0)
                failed = 1;
        }
    } else if (!failed) {
        job_set(job, JOB_CONNECTING, "Connexion à %s:%d…", a->inv.host, a->inv.port);
        int fd = tcp_connect(a->inv.host, a->inv.port, job, err, sizeof err);
        if (fd < 0) {
            failed = 1;
        } else {
            char peer[128] = "";
            struct sockaddr_storage ss;
            socklen_t sl = sizeof ss;
            if (getpeername(fd, (struct sockaddr *)&ss, &sl) == 0) {
                char h[NI_MAXHOST], sv[NI_MAXSERV];
                if (getnameinfo((struct sockaddr *)&ss, sl, h, sizeof h, sv, sizeof sv,
                                NI_NUMERICHOST | NI_NUMERICSERV) == 0)
                    snprintf(peer, sizeof peer, "%.100s:%.16s", h, sv);
            }
            job_lock(job);
            snprintf(job->remote, sizeof job->remote, "%s", peer);
            job_unlock(job);

            st = stream_tcp(fd, job);
            if (!st) {
                snprintf(err, sizeof err, "Mémoire insuffisante.");
                failed = 1;
            } else {
                job_set(job, JOB_HANDSHAKE, "Authentification avec le serveur…");
                if (client_handshake(st, job, &a->inv, key, prefix, &total, &chunk,
                                     err, sizeof err) != 0)
                    failed = 1;
            }
        }
    }

    if (!failed) {
        job_set(job, JOB_TRANSFER, "Réception du fichier…");
        job_lock(job);
        job->total = total;
        job_unlock(job);
        job_prog(job, 0, total);
        if (client_receive_file(st, job, &a->inv, key, prefix, a->destdir,
                                total, chunk, err, sizeof err) != 0)
            failed = 1;
    }

    if (st) {
        stream_destroy(st);
        st = NULL;
    }

    if (!failed) {
        job_set(job, JOB_DONE, "Fichier reçu");
        job_lock(job);
        job->result = 1;
        job->done = total;
        job->total = total;
        job_unlock(job);
    } else if (job_cancelled(job)) {
        job_set(job, JOB_CANCELLED, "Réception annulée");
        job_lock(job);
        job->result = -2;
        job_unlock(job);
    } else {
        send_finish_error(job, err);
    }
    secure_zero(key, sizeof key);
    secure_zero(a->password, sizeof a->password);
    secure_zero(a, sizeof *a);
    free(a);
    job_end(job);
    return NULL;
}

static int start_send_job(Job *job, const char *filepath, const Invite *inv,
                          const char *password, int port, int single_attempt)
{
    struct stat st;
    if (stat(filepath, &st) != 0 || !S_ISREG(st.st_mode))
        return -1;
    if ((uint64_t)st.st_size > MAX_FILE_SIZE)
        return -2;
    SendArgs *a = calloc(1, sizeof *a);
    if (!a) return -3;
    a->job = job;
    copy_path(a->filepath, sizeof a->filepath, filepath);
    sanitize_filename(filepath, a->filename, sizeof a->filename);
    a->size = (uint64_t)st.st_size;
    a->inv = *inv;
    a->port = port;
    a->single_attempt = single_attempt;
    if (password) snprintf(a->password, sizeof a->password, "%.255s", password);
    job_begin(job, 1);
    job_lock(job);
    snprintf(job->filename, sizeof job->filename, "%s", a->filename);
    job->total = a->size;
    job_unlock(job);
    pthread_t th;
    if (pthread_create(&th, NULL, send_worker, a) != 0) {
        free(a);
        job_lock(job);
        job->phase = JOB_ERROR;
        job->result = -1;
        snprintf(job->status, sizeof job->status, "Impossible de créer le thread d'envoi.");
        job_unlock(job);
        job_end(job);
        return -4;
    }
    pthread_detach(th);
    return 0;
}

static int start_recv_job(Job *job, const Invite *inv, const char *password, const char *destdir)
{
    RecvArgs *a = calloc(1, sizeof *a);
    if (!a) return -1;
    a->job = job;
    a->inv = *inv;
    if (password) snprintf(a->password, sizeof a->password, "%.255s", password);
    copy_path(a->destdir, sizeof a->destdir, destdir);
    job_begin(job, 0);
    pthread_t th;
    if (pthread_create(&th, NULL, recv_worker, a) != 0) {
        free(a);
        job_lock(job);
        job->phase = JOB_ERROR;
        job->result = -1;
        snprintf(job->status, sizeof job->status, "Impossible de créer le thread de réception.");
        job_unlock(job);
        job_end(job);
        return -2;
    }
    pthread_detach(th);
    return 0;
}

/* ===================================================================== */
/*  Autotest (--selftest)                                                */
/* ===================================================================== */

static int wait_for(int (*fn)(void *), void *ctx, int timeout_ms)
{
    double deadline = mono_now() + (double)timeout_ms / 1000.0;
    while (mono_now() < deadline) {
        if (fn(ctx)) return 1;
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 20000000 };
        nanosleep(&ts, NULL);
    }
    return 0;
}

struct selftest_wait_ctx {
    Job *job;
    int want_port;
};

static int selftest_ready(void *vp)
{
    struct selftest_wait_ctx *c = (struct selftest_wait_ctx *)vp;
    job_lock(c->job);
    int port = c->job->listen_port;
    JobPhase ph = c->job->phase;
    job_unlock(c->job);
    if (c->want_port) return port > 0 || ph == JOB_ERROR;
    return ph == JOB_DONE || ph == JOB_ERROR || ph == JOB_CANCELLED;
}

static int files_equal(const char *a, const char *b)
{
    FILE *fa = fopen(a, "rb");
    FILE *fb = fopen(b, "rb");
    if (!fa || !fb) {
        if (fa) fclose(fa);
        if (fb) fclose(fb);
        return 0;
    }
    uint8_t ba[65536], bb[65536];
    int equal = 1;
    for (;;) {
        size_t na = fread(ba, 1, sizeof ba, fa);
        size_t nb = fread(bb, 1, sizeof bb, fb);
        if (na != nb || memcmp(ba, bb, na) != 0) {
            equal = 0;
            break;
        }
        if (na < sizeof ba) break;
    }
    fclose(fa);
    fclose(fb);
    return equal;
}

static atomic_int g_sig_stop;

static void *selftest_signal_thread(void *vp)
{
    signal_accept_loop((int)(intptr_t)vp, &g_sig_stop);
    return NULL;
}

static int selftest_transfer(int password_mode, int transport, int auto_signal)
{
    static const char *pwd = "Sillage-selftest-2026";
    const char *tmpbase = getenv("TMPDIR");
    if (!tmpbase || !*tmpbase)
        tmpbase = "/tmp";

    char tdir[PATH_MAX] = "", outdir[PATH_MAX] = "", src[PATH_MAX] = "";
    char savepath[PATH_MAX] = "";
    char serr[256] = "", rstatus[256] = "";
    int sig_started = 0, sig_lfd = -1, sig_port = 0;
    pthread_t sig_th;
    pthread_t sth;
    int sender_started = 0;
    Job sj, rj;
    int jobs_ready = 0;
    int ok = 0;

    snprintf(tdir, sizeof tdir, "%s/sillage-selftest-XXXXXX", tmpbase);
    if (!mkdtemp(tdir)) {
        printf("[ÉCHEC] mkdtemp : %s\n", strerror(errno));
        return 0;
    }
    join_path(outdir, sizeof outdir, tdir, "out");
    join_path(src, sizeof src, tdir, "source.bin");
    mkdir(outdir, 0755);

    uint64_t src_size = 2u * 1024u * 1024u + 333u;
    uint8_t *data = malloc((size_t)src_size);
    FILE *f = fopen(src, "wb");
    int prep_ok = data && f && sys_random(data, (size_t)src_size) == 0 &&
                  fwrite(data, 1, (size_t)src_size, f) == (size_t)src_size;
    if (f) fclose(f);
    free(data);
    if (!prep_ok) {
        printf("[ÉCHEC] impossible de préparer le fichier de test\n");
        goto cleanup;
    }

    Invite inv;
    invite_random(&inv);
    inv.expires_at = (uint64_t)wall_now() + 30;
    inv.has_password = password_mode ? 1 : 0;
    inv.has_key = password_mode ? 0 : 1;

    if (transport == TRANSPORT_WEBRTC) {
        char err[256] = "";
        if (auto_signal == 2) {
            /* Signalisation réelle via PeerJS Cloud. */
        } else if (auto_signal) {
            /* Port libre réservé puis relâché : rtc_offer doit démarrer le
             * serveur intégré lui-même, comme dans l'interface graphique. */
            int probe_fd = sock_listen(0, &sig_port, err, sizeof err);
            if (probe_fd < 0) {
                printf("[ÉCHEC] port de signalisation libre : %s\n", err);
                goto cleanup;
            }
            close(probe_fd);
        } else {
            sig_lfd = sock_listen(0, &sig_port, err, sizeof err);
            if (sig_lfd < 0) {
                printf("[ÉCHEC] serveur de signalisation : %s\n", err);
                goto cleanup;
            }
            atomic_store_explicit(&g_sig_stop, 0, memory_order_relaxed);
            if (pthread_create(&sig_th, NULL, selftest_signal_thread,
                               (void *)(intptr_t)sig_lfd) != 0) {
                printf("[ÉCHEC] thread de signalisation\n");
                goto cleanup;
            }
            sig_started = 1;
        }

        char code[CODE_LEN + 1], srv[64];
        code_random(code);
        inv.transport = TRANSPORT_WEBRTC;
        if (invite_set_code(&inv, code) != 0) {
            printf("[ÉCHEC] dérivation du code de partage\n");
            goto cleanup;
        }
        inv.sig_peerjs = (auto_signal == 2) ? 1 : 0;
        if (auto_signal == 2) {
            invite_set_signal(&inv, signal_default());
        } else {
            snprintf(srv, sizeof srv, "127.0.0.1:%d", sig_port);
            invite_set_signal(&inv, srv);
        }
        inv.stun[0] = '\0';
    } else {
        copy_path(inv.host, sizeof inv.host, "127.0.0.1");
        inv.port = 45871;
        inv.transport = TRANSPORT_TCP;
    }

    job_init(&sj);
    job_init(&rj);
    jobs_ready = 1;

    SendArgs *sa = calloc(1, sizeof *sa);
    if (!sa) {
        printf("[ÉCHEC] allocation émetteur\n");
        goto cleanup;
    }
    sa->job = &sj;
    copy_path(sa->filepath, sizeof sa->filepath, src);
    sanitize_filename(src, sa->filename, sizeof sa->filename);
    sa->size = src_size;
    sa->inv = inv;
    sa->inv.port = 0;
    sa->port = 0;
    sa->single_attempt = 1;
    if (password_mode)
        snprintf(sa->password, sizeof sa->password, "%s", pwd);
    job_begin(&sj, 1);

    if (pthread_create(&sth, NULL, send_worker, sa) != 0) {
        printf("[ÉCHEC] création du thread émetteur\n");
        free(sa);
        goto cleanup;
    }
    sender_started = 1;

    if (transport == TRANSPORT_TCP) {
        struct selftest_wait_ctx wc = { .job = &sj, .want_port = 1 };
        int ready = wait_for(selftest_ready, &wc, 8000);
        job_lock(&sj);
        int lport = sj.listen_port;
        JobPhase sh = sj.phase;
        snprintf(serr, sizeof serr, "%.200s", sj.status);
        job_unlock(&sj);
        if (!ready || lport == 0 || sh == JOB_ERROR) {
            printf("[ÉCHEC] le serveur de test n'écoute pas (%.200s)\n", serr);
            goto cleanup;
        }
        inv.port = lport;
    }

    char link[2048], perr[256];
    invite_build_link(&inv, link, sizeof link);
    Invite rinv;
    if (invite_parse(link, &rinv, perr, sizeof perr) != 0) {
        printf("[ÉCHEC] lien de test : %.200s\n", perr);
        goto cleanup;
    }
    rinv.sig_peerjs = inv.sig_peerjs;

    if (auto_signal == 2) {
        struct timespec ts = { .tv_sec = 1, .tv_nsec = 0 };
        nanosleep(&ts, NULL);
    }

    RecvArgs *ra = calloc(1, sizeof *ra);
    if (!ra) {
        printf("[ÉCHEC] allocation récepteur\n");
        goto cleanup;
    }
    ra->job = &rj;
    ra->inv = rinv;
    copy_path(ra->destdir, sizeof ra->destdir, outdir);
    if (password_mode)
        snprintf(ra->password, sizeof ra->password, "%s", pwd);
    job_begin(&rj, 0);
    pthread_t rth;
    if (pthread_create(&rth, NULL, recv_worker, ra) != 0) {
        printf("[ÉCHEC] création du thread récepteur\n");
        free(ra);
        goto cleanup;
    }
    pthread_join(rth, NULL);
    pthread_join(sth, NULL);
    sender_started = 0;

    job_lock(&sj);
    JobPhase sp = sj.phase;
    int sres = sj.result;
    job_unlock(&sj);
    job_lock(&rj);
    JobPhase rp = rj.phase;
    int rres = rj.result;
    copy_path(savepath, sizeof savepath, rj.savepath);
    snprintf(rstatus, sizeof rstatus, "%.200s", rj.status);
    job_unlock(&rj);

    ok = sp == JOB_DONE && sres == 1 && rp == JOB_DONE && rres == 1 &&
         savepath[0] && files_equal(src, savepath);
    printf("[%s] Transfert P2P boucle locale, %s (%s%s, %.1f Mio)\n",
           ok ? "ok" : "ÉCHEC",
           password_mode ? "mot de passe scrypt" : "clé dans le lien",
           transport == TRANSPORT_WEBRTC ? "WebRTC/DataChannel" :
                                            "TCP direct",
           auto_signal == 2 ? ", PeerJS Cloud" :
           auto_signal ? ", signalisation locale auto" : "",
           (double)src_size / (1024.0 * 1024.0));
    if (!ok) {
        job_lock(&sj);
        snprintf(serr, sizeof serr, "%.200s", sj.status);
        job_unlock(&sj);
        printf("        émetteur=%d (%s) receveur=%d (%.200s)\n",
               (int)sp, serr, (int)rp, rstatus);
    }

cleanup:
    if (sender_started) {
        job_request_cancel(&sj);
        pthread_join(sth, NULL);
    }
    if (sig_started) {
        atomic_store_explicit(&g_sig_stop, 1, memory_order_relaxed);
        pthread_join(sig_th, NULL);
        close(sig_lfd);
    }
    if (savepath[0]) unlink(savepath);
    if (src[0]) unlink(src);
    if (outdir[0]) rmdir(outdir);
    if (tdir[0]) rmdir(tdir);
    if (jobs_ready) {
        pthread_mutex_destroy(&sj.mu);
        pthread_mutex_destroy(&rj.mu);
    }
    return ok;
}

static int run_selftest(void)
{
    printf("SILLAGE Transfer %s — autotest\n", APP_VERSION);
    printf("Profil AEAD : BRUME-512 (clé 64 o, nonce 24 o, tag 16 o)\n\n");
    int fails = 0;
    sl_init();

    /* --- AEAD ------------------------------------------------------- */
    {
        uint8_t key[KEY_LEN], nonce[NONCE_LEN], aad[40], tag[TAG_LEN];
        uint8_t ct[128], pt[128];
        const char *msg = "SILLAGE BRUME-512 autotest";
        size_t len = strlen(msg);
        sys_random(key, sizeof key);
        sys_random(nonce, sizeof nonce);
        sys_random(aad, sizeof aad);
        int e = sl_aead_encrypt(AEAD_PROFILE, key, nonce, aad, sizeof aad,
                                (const uint8_t *)msg, len, ct, tag);
        int d = sl_aead_decrypt(AEAD_PROFILE, key, nonce, aad, sizeof aad,
                                ct, len, tag, pt);
        int ok = e == 0 && d == 0 && memcmp(pt, msg, len) == 0;
        tag[0] ^= 1;
        int bad = sl_aead_decrypt(AEAD_PROFILE, key, nonce, aad, sizeof aad,
                                  ct, len, tag, pt);
        ok = ok && bad != 0;
        printf("[%s] AEAD : chiffrement, déchiffrement, rejet d'un tag altéré\n", ok ? "ok" : "ÉCHEC");
        if (!ok) fails++;
    }

    /* --- Dérivation de mot de passe --------------------------------- */
    {
        uint8_t id[INVITE_ID_LEN], k1[KEY_LEN], k2[KEY_LEN], k3[KEY_LEN];
        char err[128];
        sys_random(id, sizeof id);
        int a = derive_password_key("mot de passe de test", id, k1, err, sizeof err);
        int b = derive_password_key("mot de passe de test", id, k2, err, sizeof err);
        int c = derive_password_key("autre mot de passe", id, k3, err, sizeof err);
        int ok = a == 0 && b == 0 && c == 0 &&
                 memcmp(k1, k2, KEY_LEN) == 0 && memcmp(k1, k3, KEY_LEN) != 0;
        printf("[%s] scrypt : dérivation déterministe et sensible au mot de passe\n", ok ? "ok" : "ÉCHEC");
        if (!ok) fails++;
    }

    /* --- Lien ------------------------------------------------------- */
    Invite inv;
    invite_random(&inv);
    snprintf(inv.host, sizeof inv.host, "127.0.0.1");
    inv.port = 45871;
    inv.expires_at = (uint64_t)wall_now() + 600;
    inv.has_password = 0;
    inv.has_key = 1;
    char link[2048];
    invite_build_link(&inv, link, sizeof link);
    Invite parsed;
    char perr[256];
    int pok = invite_parse(link, &parsed, perr, sizeof perr) == 0 &&
              memcmp(parsed.id, inv.id, INVITE_ID_LEN) == 0 &&
              memcmp(parsed.token, inv.token, TOKEN_LEN) == 0 &&
              memcmp(parsed.key, inv.key, KEY_LEN) == 0 &&
              strcmp(parsed.host, inv.host) == 0 &&
              parsed.port == inv.port && parsed.expires_at == inv.expires_at &&
              !parsed.has_password && parsed.has_key;
    printf("[%s] Lien sillage:// : génération et analyse\n", pok ? "ok" : "ÉCHEC");
    if (!pok) fails++;

    /* --- QR --------------------------------------------------------- */
    {
        uint8_t *temp = malloc(qrcodegen_BUFFER_LEN_MAX);
        uint8_t *qr = malloc(qrcodegen_BUFFER_LEN_MAX);
        int ok = temp && qr && qrcodegen_encodeText(link, temp, qr, qrcodegen_Ecc_MEDIUM,
                                                    qrcodegen_VERSION_MIN, qrcodegen_VERSION_MAX,
                                                    qrcodegen_Mask_AUTO, true);
        int size = ok ? qrcodegen_getSize(qr) : 0;
        ok = ok && size >= 21 && qrcodegen_getModule(qr, 0, 0);
        printf("[%s] QR code : encodage du lien (%d × %d modules)\n", ok ? "ok" : "ÉCHEC", size, size);
        if (!ok) fails++;
        free(temp);
        free(qr);
    }

    /* --- Transferts boucle locale ---------------------------------- */
    if (!selftest_transfer(0, TRANSPORT_TCP, 0))
        fails++;
    if (!selftest_transfer(1, TRANSPORT_TCP, 0))
        fails++;
    if (!selftest_transfer(0, TRANSPORT_WEBRTC, 0))
        fails++;
    if (!selftest_transfer(1, TRANSPORT_WEBRTC, 0))
        fails++;
    if (!selftest_transfer(0, TRANSPORT_WEBRTC, 1))
        fails++;

    printf("\n%s (%d échec%s)\n", fails ? "AUTOTEST EN ÉCHEC" : "AUTOTEST RÉUSSI",
           fails, fails > 1 ? "s" : "");
    return fails ? 1 : 0;
}

/* Test réseau optionnel : utilise réellement PeerJS Cloud. */
static int run_selftest_peerjs(void)
{
    printf("%s %s — test PeerJS Cloud\n\n", APP_NAME, APP_VERSION);
    int fails = 0;
    if (!selftest_transfer(0, TRANSPORT_WEBRTC, 2))
        fails++;
    if (!selftest_transfer(1, TRANSPORT_WEBRTC, 2))
        fails++;
    printf("\n%s (%d échec%s)\n",
           fails ? "TEST PEERJS EN ÉCHEC" : "TEST PEERJS RÉUSSI",
           fails, fails > 1 ? "s" : "");
    return fails ? 1 : 0;
}

/* ===================================================================== */
/*  Interface : état global, polices, primitives de dessin               */
/* ===================================================================== */

#define FONT_CACHE_MAX 32

typedef struct {
    int px;
    Font font;
} FontSlot;

typedef struct {
    /* Repères de graisse : seuls leurs identifiants de texture sont utilisés. */
    Font f12, f14, f16, f18, f22, f28, f36;
    FontSlot regular[FONT_CACHE_MAX];
    FontSlot bold[FONT_CACHE_MAX];
    int regular_n, bold_n;
    char regular_path[PATH_MAX];
    char bold_path[PATH_MAX];
    int fallback;
    int loaded;
} Fonts;

typedef struct {
    char name[256];
    int is_dir;
    uint64_t size;
} DirEntry;

typedef struct {
    char name[256];
    uint64_t size;
    int send;
    int ok;
    time_t when;
    char status[128];
    char remote[128];
} HistoryItem;

typedef enum {
    PAGE_SEND = 0,
    PAGE_RECV,
    PAGE_HISTORY,
    PAGE_ABOUT
} Page;

typedef struct {
    JobPhase phase;
    int running;
    int result;
    int is_send;
    char status[256];
    char detail[256];
    char filename[256];
    char savepath[PATH_MAX];
    char remote[128];
    uint64_t total;
    uint64_t done;
    uint64_t speed;
    uint64_t expires_at;
    int listen_port;
    int history_logged;
} JobView;

typedef struct {
    Page page;
    Fonts fonts;

    Job job;
    JobView view;

    char send_path[PATH_MAX];
    int send_has_file;
    char send_name[256];
    uint64_t send_size;
    TextField send_pw;
    int send_pw_on;
    int send_reveal;
    int expiry_idx;
    TextField send_port;
    TextField send_host;
    int transport;                 /* TRANSPORT_WEBRTC par défaut */
    TextField send_signal;
    TextField send_stun;
    char share_code[CODE_LEN + 1];
    Invite send_inv;
    int share_visible;
    char share_link[2048];
    Texture2D qr;
    int qr_px;

    TextField recv_link;
    TextField recv_pw;
    int recv_reveal;
    TextField recv_dir;
    Invite recv_inv;
    int recv_parsed;
    int recv_last_len;
    char recv_error[256];

    int browser_open;
    int browser_dir_mode;
    char browser_dir[PATH_MAX];
    DirEntry browser_entries[512];
    int browser_count;
    float browser_scroll;
    char browser_note[128];

    HistoryItem hist[32];
    int hist_count;
    float hist_scroll;

    char toast[256];
    double toast_until;
    int qr_zoom;

    int first_frame;
} App;

static App g_app;
static bool g_block_input = false;

/* Curseur souris.
 *
 * SetMouseCursor() est une opération coûteuse côté serveur graphique : sous
 * XWayland, l'appeler à chaque image (flèche en début de frame, main au
 * survol) fait clignoter le pointeur à la fréquence d'affichage. On accumule
 * donc le curseur voulu pendant le dessin, puis on ne l'applique qu'une fois,
 * et seulement s'il a changé. */
static int g_cursor_want = MOUSE_CURSOR_DEFAULT;
static int g_cursor_applied = -1;

static int cursor_rank(int c)
{
    if (c == MOUSE_CURSOR_IBEAM) return 3;
    if (c == MOUSE_CURSOR_POINTING_HAND) return 2;
    return 1;
}

static void want_cursor(int cursor)
{
    if (cursor_rank(cursor) > cursor_rank(g_cursor_want))
        g_cursor_want = cursor;
}

/* Agrandissement global du texte, sans toucher à la géométrie des cartes.
 * Les tailles sont arrondies au pixel par le cache de polices. */
#define UI_TEXT_SCALE 1.16f

#define F12   (g_app.fonts.f12)
#define F14   (g_app.fonts.f14)
#define F16   (g_app.fonts.f16)
#define F18   (g_app.fonts.f18)
#define F22   (g_app.fonts.f22)
#define F28   (g_app.fonts.f28)
#define F36   (g_app.fonts.f36)

static Color mix_color(Color a, Color b, float t)
{
    if (t < 0) t = 0;
    if (t > 1) t = 1;
    return (Color){
        (unsigned char)((float)a.r + ((float)b.r - (float)a.r) * t),
        (unsigned char)((float)a.g + ((float)b.g - (float)a.g) * t),
        (unsigned char)((float)a.b + ((float)b.b - (float)a.b) * t),
        (unsigned char)((float)a.a + ((float)b.a - (float)a.a) * t)
    };
}

static int g_font_cps[256];
static int g_font_cps_n;

static int font_readable(const char *path)
{
    return path && *path && access(path, R_OK) == 0;
}

static int font_pick(const char *const *candidates, char *out, size_t cap)
{
    for (int i = 0; candidates[i]; i++) {
        if (font_readable(candidates[i])) {
            snprintf(out, cap, "%s", candidates[i]);
            return 0;
        }
    }
    return -1;
}

/*
 * Recherche une police via fontconfig, utilisée en dernier recours.
 * Fontconfig est présent sur Ubuntu comme sur Fedora ; cela évite de dépendre
 * d'un chemin d'installation particulier (Lato n'est pas toujours installé).
 */
static int font_fc_match(const char *query, char *out, size_t cap)
{
    char cmd[256];
    snprintf(cmd, sizeof cmd, "fc-match -f '%%{file}' '%s' 2>/dev/null", query);
    FILE *fp = popen(cmd, "r");
    if (!fp)
        return -1;
    char buf[PATH_MAX];
    size_t n = fread(buf, 1, sizeof buf - 1, fp);
    int rc = pclose(fp);
    if (rc != 0 || n == 0)
        return -1;
    buf[n] = '\0';
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r' ||
                     buf[n - 1] == ' ' || buf[n - 1] == '\t'))
        buf[--n] = '\0';
    if (!font_readable(buf))
        return -1;
    snprintf(out, cap, "%s", buf);
    return 0;
}

static int font_resolve_family(const char *const *reg_paths,
                               const char *const *bold_paths,
                               char *reg, size_t reg_cap,
                               char *bold, size_t bold_cap)
{
    if (font_pick(reg_paths, reg, reg_cap) != 0)
        return -1;
    if (font_pick(bold_paths, bold, bold_cap) != 0)
        snprintf(bold, bold_cap, "%s", reg);
    return 0;
}

static void font_resolve(char *reg, size_t reg_cap, char *bold, size_t bold_cap)
{
    reg[0] = '\0';
    bold[0] = '\0';

    /* Surcharge explicite, utile pour tester ou pour un poste exotique. */
    const char *env_reg = getenv("SILLAGE_FONT");
    if (font_readable(env_reg)) {
        snprintf(reg, reg_cap, "%s", env_reg);
        const char *env_bold = getenv("SILLAGE_FONT_BOLD");
        snprintf(bold, bold_cap, "%s", font_readable(env_bold) ? env_bold : env_reg);
        return;
    }

    static const char *const lato_reg[] = {
        "/usr/share/fonts/truetype/lato/Lato-Regular.ttf",
        "/usr/share/fonts/lato/Lato-Regular.ttf",
        "/usr/share/fonts/google-lato/Lato-Regular.ttf",
        "/usr/share/fonts/TTF/Lato-Regular.ttf",
        "/usr/local/share/fonts/Lato-Regular.ttf",
        NULL
    };
    static const char *const lato_bold[] = {
        "/usr/share/fonts/truetype/lato/Lato-Bold.ttf",
        "/usr/share/fonts/lato/Lato-Bold.ttf",
        "/usr/share/fonts/google-lato/Lato-Bold.ttf",
        "/usr/share/fonts/TTF/Lato-Bold.ttf",
        "/usr/local/share/fonts/Lato-Bold.ttf",
        NULL
    };
    static const char *const dejavu_reg[] = {
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/dejavu-sans-fonts/DejaVuSans.ttf",
        "/usr/share/fonts/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/TTF/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/DejaVuSans.ttf",
        NULL
    };
    static const char *const dejavu_bold[] = {
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/dejavu-sans-fonts/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/TTF/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/truetype/DejaVuSans-Bold.ttf",
        NULL
    };
    static const char *const liberation_reg[] = {
        "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
        "/usr/share/fonts/liberation-sans/LiberationSans-Regular.ttf",
        "/usr/share/fonts/liberation/LiberationSans-Regular.ttf",
        "/usr/share/fonts/TTF/LiberationSans-Regular.ttf",
        NULL
    };
    static const char *const liberation_bold[] = {
        "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
        "/usr/share/fonts/liberation-sans/LiberationSans-Bold.ttf",
        "/usr/share/fonts/liberation/LiberationSans-Bold.ttf",
        "/usr/share/fonts/TTF/LiberationSans-Bold.ttf",
        NULL
    };
    static const char *const noto_reg[] = {
        "/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf",
        "/usr/share/fonts/google-noto/NotoSans-Regular.ttf",
        "/usr/share/fonts/noto/NotoSans-Regular.ttf",
        "/usr/share/fonts/truetype/NotoSans-Regular.ttf",
        NULL
    };
    static const char *const noto_bold[] = {
        "/usr/share/fonts/truetype/noto/NotoSans-Bold.ttf",
        "/usr/share/fonts/google-noto/NotoSans-Bold.ttf",
        "/usr/share/fonts/noto/NotoSans-Bold.ttf",
        "/usr/share/fonts/truetype/NotoSans-Bold.ttf",
        NULL
    };

    if (font_resolve_family(lato_reg, lato_bold, reg, reg_cap, bold, bold_cap) == 0)
        return;
    if (font_resolve_family(dejavu_reg, dejavu_bold, reg, reg_cap, bold, bold_cap) == 0)
        return;
    if (font_resolve_family(liberation_reg, liberation_bold, reg, reg_cap, bold, bold_cap) == 0)
        return;
    if (font_resolve_family(noto_reg, noto_bold, reg, reg_cap, bold, bold_cap) == 0)
        return;

    if (font_fc_match("sans-serif", reg, reg_cap) == 0) {
        if (font_fc_match("sans-serif:bold", bold, bold_cap) != 0)
            snprintf(bold, bold_cap, "%s", reg);
        return;
    }

    /* Dernier recours : police bitmap intégrée à raylib. */
    reg[0] = '\0';
    bold[0] = '\0';
}

/*
 * Charge une police à la taille exacte demandée (arrondie au pixel).
 *
 * Dessiner une police chargée en 12 px à 9 px, comme le faisait la version
 * précédente, passe par un redimensionnement bilinéaire : le texte devient
 * flou. Ici chaque taille réellement utilisée possède son propre atlas, donc
 * le rendu est toujours à l'échelle 1:1.
 */
static Font *font_cache_get(int bold, float size)
{
    int px = (int)lroundf(size * UI_TEXT_SCALE);
    if (px < 8) px = 8;
    if (px > 64) px = 64;

    FontSlot *slots = bold ? g_app.fonts.bold : g_app.fonts.regular;
    int *count = bold ? &g_app.fonts.bold_n : &g_app.fonts.regular_n;

    for (int i = 0; i < *count; i++) {
        if (slots[i].px == px)
            return &slots[i].font;
    }

    if (g_app.fonts.fallback || *count >= FONT_CACHE_MAX) {
        static Font def;
        def = GetFontDefault();
        return &def;
    }

    const char *path = bold ? g_app.fonts.bold_path : g_app.fonts.regular_path;
    Font f = LoadFontEx(path, px, g_font_cps, g_font_cps_n);
    if (f.texture.id == 0) {
        f = GetFontDefault();
        g_app.fonts.fallback = 1;
    } else {
        SetTextureFilter(f.texture, TEXTURE_FILTER_BILINEAR);
    }
    slots[*count].px = px;
    slots[*count].font = f;
    (*count)++;
    return &slots[*count - 1].font;
}

static int font_is_bold(Font f)
{
    Font def = GetFontDefault();
    if (f.texture.id == def.texture.id)
        return 0;
    return f.texture.id == g_app.fonts.f18.texture.id ||
           f.texture.id == g_app.fonts.f22.texture.id ||
           f.texture.id == g_app.fonts.f28.texture.id ||
           f.texture.id == g_app.fonts.f36.texture.id;
}

static void load_fonts(void)
{
    g_font_cps_n = 0;
    for (int c = 32; c <= 126; c++) g_font_cps[g_font_cps_n++] = c;
    for (int c = 160; c <= 255; c++) g_font_cps[g_font_cps_n++] = c;
    static const int extra[] = {
        0x0152, 0x0153, 0x0178, 0x017D, 0x017E, 0x20AC,
        0x2013, 0x2014, 0x2018, 0x2019, 0x201C, 0x201D,
        0x2022, 0x2026, 0x2190, 0x2191, 0x2192, 0x2193, 0x00B7
    };
    for (size_t i = 0; i < sizeof extra / sizeof extra[0]; i++)
        g_font_cps[g_font_cps_n++] = extra[i];

    font_resolve(g_app.fonts.regular_path, sizeof g_app.fonts.regular_path,
                 g_app.fonts.bold_path, sizeof g_app.fonts.bold_path);
    g_app.fonts.fallback = (g_app.fonts.regular_path[0] == '\0');

    g_app.fonts.regular_n = 0;
    g_app.fonts.bold_n = 0;

    /* Repères utilisés par les macros F12…F36 et la détection de graisse. */
    g_app.fonts.f12 = *font_cache_get(0, 12);
    g_app.fonts.f14 = *font_cache_get(0, 14);
    g_app.fonts.f16 = *font_cache_get(0, 16);
    g_app.fonts.f18 = *font_cache_get(1, 18);
    g_app.fonts.f22 = *font_cache_get(1, 22);
    g_app.fonts.f28 = *font_cache_get(1, 28);
    g_app.fonts.f36 = *font_cache_get(1, 36);
    g_app.fonts.loaded = 1;
}

static void unload_fonts(void)
{
    if (!g_app.fonts.loaded) return;
    Font def = GetFontDefault();
    FontSlot *families[] = { g_app.fonts.regular, g_app.fonts.bold };
    int counts[] = { g_app.fonts.regular_n, g_app.fonts.bold_n };
    for (int k = 0; k < 2; k++) {
        for (int i = 0; i < counts[k]; i++) {
            Font *f = &families[k][i].font;
            if (f->texture.id != 0 && f->texture.id != def.texture.id)
                UnloadFont(*f);
            f->texture.id = 0;
        }
    }
    g_app.fonts.regular_n = 0;
    g_app.fonts.bold_n = 0;
    g_app.fonts.loaded = 0;
}

static float font_draw_size(Font *font, float size)
{
    Font def = GetFontDefault();
    if (font->texture.id == def.texture.id) {
        float px = roundf(size * UI_TEXT_SCALE);
        return px < 8.0f ? 8.0f : px;
    }
    return (float)font->baseSize;
}

static void draw_text(Font f, const char *s, float x, float y, float size, Color c)
{
    if (!s || !*s) return;
    Font *font = font_cache_get(font_is_bold(f), size);
    DrawTextEx(*font, s, (Vector2){ roundf(x), roundf(y) },
               font_draw_size(font, size), 0.0f, c);
}

static void draw_text_c(Font f, const char *s, float cx, float y, float size, Color c)
{
    if (!s || !*s) return;
    Font *font = font_cache_get(font_is_bold(f), size);
    float fs = font_draw_size(font, size);
    float w = MeasureTextEx(*font, s, fs, 0.0f).x;
    DrawTextEx(*font, s, (Vector2){ roundf(cx - w * 0.5f), roundf(y) },
               fs, 0.0f, c);
}

static void draw_text_r(Font f, const char *s, float rx, float y, float size, Color c)
{
    if (!s || !*s) return;
    Font *font = font_cache_get(font_is_bold(f), size);
    float fs = font_draw_size(font, size);
    float w = MeasureTextEx(*font, s, fs, 0.0f).x;
    DrawTextEx(*font, s, (Vector2){ roundf(rx - w), roundf(y) },
               fs, 0.0f, c);
}

static float text_w(Font f, const char *s, float size)
{
    if (!s || !*s) return 0;
    Font *font = font_cache_get(font_is_bold(f), size);
    return MeasureTextEx(*font, s, font_draw_size(font, size), 0.0f).x;
}

static void elide_text(Font f, const char *src, float size, float maxw, char *out, size_t cap)
{
    if (!src) src = "";
    if (cap == 0) return;
    snprintf(out, cap, "%s", src);
    if (maxw <= 0) { out[0] = '\0'; return; }
    if (text_w(f, out, size) <= maxw) return;

    char tmp[2048];
    size_t n = strlen(out);
    while (n > 0) {
        n--;
        while (n > 0 && ((unsigned char)out[n] & 0xC0) == 0x80) n--;
        out[n] = '\0';
        snprintf(tmp, sizeof tmp, "%s…", out);
        if (text_w(f, tmp, size) <= maxw) {
            snprintf(out, cap, "%s", tmp);
            return;
        }
    }
    snprintf(out, cap, "…");
}

static void elide_path(Font f, const char *src, float size, float maxw, char *out, size_t cap)
{
    if (text_w(f, src, size) <= maxw) {
        snprintf(out, cap, "%s", src);
        return;
    }
    const char *p = src + strlen(src);
    while (p > src) {
        p--;
        while (p > src && ((unsigned char)*p & 0xC0) == 0x80) p--;
        if (*p == '/') {
            char tmp[2048];
            snprintf(tmp, sizeof tmp, "…%s", p);
            if (text_w(f, tmp, size) <= maxw) {
                snprintf(out, cap, "%s", tmp);
                return;
            }
        }
    }
    elide_text(f, src, size, maxw, out, cap);
}

static int draw_wrapped(Font f, const char *text, Rectangle box, float size, Color c, float lh)
{
    if (!text || !*text) return 0;
    char line[1024] = "";
    const char *p = text;
    float y = box.y;
    int lines = 0;
    while (*p && y + size <= box.y + box.height) {
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\n') { p++; continue; }
        const char *w = p;
        while (*p && *p != ' ' && *p != '\n' && *p != '\t') p++;
        size_t wl = (size_t)(p - w);
        if (wl > 500) wl = 500;
        char word[512];
        memcpy(word, w, wl);
        word[wl] = '\0';

        char test[1024];
        if (line[0])
            snprintf(test, sizeof test, "%s %s", line, word);
        else
            snprintf(test, sizeof test, "%s", word);

        if (text_w(f, test, size) <= box.width) {
            snprintf(line, sizeof line, "%s", test);
        } else {
            if (line[0]) {
                draw_text(f, line, box.x, y, size, c);
                y += lh;
                lines++;
                line[0] = '\0';
                if (y + size > box.y + box.height) break;
            }
            if (text_w(f, word, size) > box.width) {
                char cut[512];
                elide_text(f, word, size, box.width, cut, sizeof cut);
                draw_text(f, cut, box.x, y, size, c);
                y += lh;
                lines++;
            } else {
                snprintf(line, sizeof line, "%s", word);
            }
        }
        if (*p == '\n') {
            p++;
            if (line[0]) {
                draw_text(f, line, box.x, y, size, c);
                y += lh;
                lines++;
                line[0] = '\0';
            }
        }
    }
    if (line[0] && y + size <= box.y + box.height) {
        draw_text(f, line, box.x, y, size, c);
        lines++;
    }
    return lines;
}

static void rounded(Rectangle r, float roundness, Color fill, Color border, float border_w)
{
    DrawRectangleRounded(r, roundness, 12, fill);
    if (border.a)
        DrawRectangleRoundedLinesEx(r, roundness, 12, border_w, border);
}

static void card(Rectangle r)
{
    rounded(r, 0.055f, COLOR_PANEL, COLOR_BORDER, 1.0f);
}

static bool mouse_in(Rectangle r)
{
    return CheckCollisionPointRec(GetMousePosition(), r);
}

static void glow(float x, float y, float r, Color c)
{
    for (int i = 0; i < 4; i++) {
        float rr = r * (1.0f - (float)i * 0.18f);
        Color cc = Fade(c, 0.016f + 0.008f * (float)i);
        DrawCircleV((Vector2){ x, y }, rr, cc);
    }
}

/* ---------------- icônes ---------------- */

static void ico_arrow(Vector2 c, float s, int dir, Color col)
{
    (void)s;
    float d = (dir == 0) ? -1.0f : 1.0f;
    DrawLineEx((Vector2){ c.x, c.y + 7.0f * d }, (Vector2){ c.x, c.y - 7.0f * d }, 2.0f, col);
    Vector2 a = { c.x - 5.0f, c.y - 2.0f * d };
    Vector2 b = { c.x + 5.0f, c.y - 2.0f * d };
    Vector2 t = { c.x, c.y - 10.0f * d };
    DrawTriangle(a, b, t, col);
}

static void ico_send(Vector2 c, float s, Color col)
{
    (void)s;
    ico_arrow((Vector2){ c.x, c.y - 2.0f }, 0, 0, col);
    DrawLineEx((Vector2){ c.x - 8, c.y + 8 }, (Vector2){ c.x + 8, c.y + 8 }, 2.0f, col);
    DrawLineEx((Vector2){ c.x - 8, c.y + 4 }, (Vector2){ c.x - 8, c.y + 8 }, 2.0f, col);
    DrawLineEx((Vector2){ c.x + 8, c.y + 4 }, (Vector2){ c.x + 8, c.y + 8 }, 2.0f, col);
}

static void ico_recv(Vector2 c, float s, Color col)
{
    (void)s;
    ico_arrow((Vector2){ c.x, c.y - 2.0f }, 1, 0, col);
    DrawLineEx((Vector2){ c.x - 8, c.y + 8 }, (Vector2){ c.x + 8, c.y + 8 }, 2.0f, col);
    DrawLineEx((Vector2){ c.x - 8, c.y + 4 }, (Vector2){ c.x - 8, c.y + 8 }, 2.0f, col);
    DrawLineEx((Vector2){ c.x + 8, c.y + 4 }, (Vector2){ c.x + 8, c.y + 8 }, 2.0f, col);
}

static void ico_file(Vector2 c, float s, Color col)
{
    float w = s * 0.72f, h = s;
    Rectangle r = { c.x - w / 2, c.y - h / 2, w, h };
    DrawRectangleRounded(r, 0.16f, 8, Fade(col, 0.10f));
    DrawRectangleRoundedLinesEx(r, 0.16f, 8, 1.6f, col);
    DrawLineEx((Vector2){ c.x - w * 0.25f, c.y - 1 }, (Vector2){ c.x + w * 0.25f, c.y - 1 }, 1.4f, col);
    DrawLineEx((Vector2){ c.x - w * 0.25f, c.y + s * 0.18f }, (Vector2){ c.x + w * 0.25f, c.y + s * 0.18f }, 1.4f, col);
}

static void ico_folder(Vector2 c, float s, Color col)
{
    float w = s, h = s * 0.72f;
    Rectangle b = { c.x - w / 2, c.y - h / 2 + 2, w, h };
    DrawRectangleRounded(b, 0.20f, 8, Fade(col, 0.12f));
    DrawRectangleRoundedLinesEx(b, 0.20f, 8, 1.5f, col);
    Rectangle tab = { c.x - w / 2 + 3, c.y - h / 2 - 1, w * 0.42f, 6 };
    DrawRectangleRounded(tab, 0.5f, 6, col);
}

static void ico_clock(Vector2 c, float s, Color col)
{
    float r = s * 0.42f;
    DrawCircleLinesV(c, r, col);
    DrawLineEx(c, (Vector2){ c.x, c.y - r * 0.55f }, 1.7f, col);
    DrawLineEx(c, (Vector2){ c.x + r * 0.5f, c.y + r * 0.2f }, 1.7f, col);
}

static void ico_info(Vector2 c, float s, Color col)
{
    float r = s * 0.44f;
    DrawCircleLinesV(c, r, col);
    DrawCircleV((Vector2){ c.x, c.y - r * 0.45f }, 1.6f, col);
    DrawLineEx((Vector2){ c.x, c.y - r * 0.1f }, (Vector2){ c.x, c.y + r * 0.45f }, 1.8f, col);
}

static void ico_lock(Vector2 c, float s, Color col)
{
    float w = s * 0.66f, h = s * 0.52f;
    Rectangle b = { c.x - w / 2, c.y - h / 2 + 2, w, h };
    DrawRectangleRounded(b, 0.18f, 8, Fade(col, 0.12f));
    DrawRectangleRoundedLinesEx(b, 0.18f, 8, 1.5f, col);
    DrawRing((Vector2){ c.x, c.y - h / 2 + 1 }, s * 0.20f, s * 0.28f, 180, 360, 20, col);
    DrawCircleV((Vector2){ c.x, c.y + 1 }, 2.0f, col);
}

static void ico_link(Vector2 c, float s, Color col)
{
    (void)s;
    DrawLineEx((Vector2){ c.x - 6, c.y - 4 }, (Vector2){ c.x + 1, c.y - 4 }, 2.2f, col);
    DrawLineEx((Vector2){ c.x + 1, c.y - 4 }, (Vector2){ c.x + 6, c.y + 1 }, 2.2f, col);
    DrawLineEx((Vector2){ c.x + 6, c.y + 1 }, (Vector2){ c.x - 1, c.y + 1 }, 2.2f, col);
    DrawLineEx((Vector2){ c.x - 1, c.y + 1 }, (Vector2){ c.x - 6, c.y + 6 }, 2.2f, col);
    DrawLineEx((Vector2){ c.x - 6, c.y + 6 }, (Vector2){ c.x + 1, c.y + 6 }, 2.2f, col);
    DrawLineEx((Vector2){ c.x - 6, c.y - 4 }, (Vector2){ c.x - 6, c.y + 6 }, 2.2f, col);
    DrawLineEx((Vector2){ c.x + 1, c.y - 4 }, (Vector2){ c.x + 1, c.y + 1 }, 2.2f, col);
}

static void ico_copy(Vector2 c, float s, Color col)
{
    Rectangle a = { c.x - s * 0.32f, c.y - s * 0.28f, s * 0.54f, s * 0.54f };
    Rectangle b = { c.x - s * 0.12f, c.y - s * 0.08f, s * 0.54f, s * 0.54f };
    DrawRectangleRoundedLinesEx(a, 0.18f, 8, 1.6f, col);
    DrawRectangleRounded(b, 0.18f, 8, COLOR_PANEL);
    DrawRectangleRoundedLinesEx(b, 0.18f, 8, 1.6f, col);
}

static void ico_eye(Vector2 c, float s, Color col, bool open)
{
    float w = s * 0.92f, h = s * 0.52f;
    if (!open) {
        DrawLineEx((Vector2){ c.x - w / 2, c.y + h / 2 }, (Vector2){ c.x + w / 2, c.y - h / 2 }, 1.8f, col);
        return;
    }
    DrawEllipseLines((int)c.x, (int)c.y, w / 2, h / 2, col);
    DrawCircleV(c, 2.6f, col);
}

static void ico_check(Vector2 c, float s, Color col)
{
    DrawLineEx((Vector2){ c.x - s * 0.34f, c.y }, (Vector2){ c.x - s * 0.06f, c.y + s * 0.28f }, 2.4f, col);
    DrawLineEx((Vector2){ c.x - s * 0.06f, c.y + s * 0.28f }, (Vector2){ c.x + s * 0.38f, c.y - s * 0.30f }, 2.4f, col);
}

static void ico_x(Vector2 c, float s, Color col)
{
    float k = s * 0.35f;
    DrawLineEx((Vector2){ c.x - k, c.y - k }, (Vector2){ c.x + k, c.y + k }, 2.2f, col);
    DrawLineEx((Vector2){ c.x + k, c.y - k }, (Vector2){ c.x - k, c.y + k }, 2.2f, col);
}

static void ico_qr(Vector2 c, float s, Color col)
{
    float u = s * 0.26f, g = s * 0.12f, o = s * 0.5f - u - g * 0.5f;
    Rectangle a = { c.x - o, c.y - o, u, u };
    Rectangle b = { c.x + g * 0.5f, c.y - o, u, u };
    Rectangle d = { c.x - o, c.y + g * 0.5f, u, u };
    DrawRectangleRoundedLinesEx(a, 0.2f, 6, 1.6f, col);
    DrawRectangleRoundedLinesEx(b, 0.2f, 6, 1.6f, col);
    DrawRectangleRoundedLinesEx(d, 0.2f, 6, 1.6f, col);
    DrawRectangleV((Vector2){ c.x + g, c.y + g }, (Vector2){ 2.2f, 2.2f }, col);
    DrawRectangleV((Vector2){ c.x + g + 4, c.y + g + 4 }, (Vector2){ 2.2f, 2.2f }, col);
}

static void ico_shield(Vector2 c, float s, Color col)
{
    DrawTriangle((Vector2){ c.x, c.y - s * 0.45f },
                 (Vector2){ c.x + s * 0.36f, c.y - s * 0.25f },
                 (Vector2){ c.x, c.y + s * 0.45f }, Fade(col, 0.16f));
    DrawTriangle((Vector2){ c.x, c.y - s * 0.45f },
                 (Vector2){ c.x, c.y + s * 0.45f },
                 (Vector2){ c.x - s * 0.36f, c.y - s * 0.25f }, Fade(col, 0.16f));
    DrawTriangleLines((Vector2){ c.x, c.y - s * 0.45f },
                      (Vector2){ c.x + s * 0.36f, c.y - s * 0.25f },
                      (Vector2){ c.x, c.y + s * 0.45f }, col);
    DrawTriangleLines((Vector2){ c.x, c.y - s * 0.45f },
                      (Vector2){ c.x, c.y + s * 0.45f },
                      (Vector2){ c.x - s * 0.36f, c.y - s * 0.25f }, col);
    ico_check(c, s * 0.55f, col);
}

static void ico_up(Vector2 c, float s, Color col)
{
    DrawLineEx((Vector2){ c.x, c.y + s * 0.22f }, (Vector2){ c.x, c.y - s * 0.28f }, 2.0f, col);
    DrawLineEx((Vector2){ c.x - s * 0.26f, c.y - s * 0.02f }, (Vector2){ c.x, c.y - s * 0.28f }, 2.0f, col);
    DrawLineEx((Vector2){ c.x + s * 0.26f, c.y - s * 0.02f }, (Vector2){ c.x, c.y - s * 0.28f }, 2.0f, col);
}

static void ico_home(Vector2 c, float s, Color col)
{
    DrawLineEx((Vector2){ c.x - s * 0.36f, c.y + s * 0.06f }, (Vector2){ c.x, c.y - s * 0.3f }, 2.0f, col);
    DrawLineEx((Vector2){ c.x, c.y - s * 0.3f }, (Vector2){ c.x + s * 0.36f, c.y + s * 0.06f }, 2.0f, col);
    DrawLineEx((Vector2){ c.x - s * 0.28f, c.y + s * 0.04f }, (Vector2){ c.x - s * 0.28f, c.y + s * 0.34f }, 2.0f, col);
    DrawLineEx((Vector2){ c.x + s * 0.28f, c.y + s * 0.04f }, (Vector2){ c.x + s * 0.28f, c.y + s * 0.34f }, 2.0f, col);
    DrawLineEx((Vector2){ c.x - s * 0.28f, c.y + s * 0.34f }, (Vector2){ c.x + s * 0.28f, c.y + s * 0.34f }, 2.0f, col);
}

static void ico_chevron(Vector2 c, float s, Color col)
{
    DrawLineEx((Vector2){ c.x - s * 0.16f, c.y - s * 0.24f }, (Vector2){ c.x + s * 0.16f, c.y }, 2.0f, col);
    DrawLineEx((Vector2){ c.x + s * 0.16f, c.y }, (Vector2){ c.x - s * 0.16f, c.y + s * 0.24f }, 2.0f, col);
}

static void ico_activity(Vector2 c, float s, Color col)
{
    DrawLineEx((Vector2){ c.x - s * 0.42f, c.y }, (Vector2){ c.x - s * 0.16f, c.y }, 1.8f, col);
    DrawLineEx((Vector2){ c.x - s * 0.16f, c.y }, (Vector2){ c.x - s * 0.04f, c.y - s * 0.26f }, 1.8f, col);
    DrawLineEx((Vector2){ c.x - s * 0.04f, c.y - s * 0.26f }, (Vector2){ c.x + s * 0.10f, c.y + s * 0.24f }, 1.8f, col);
    DrawLineEx((Vector2){ c.x + s * 0.10f, c.y + s * 0.24f }, (Vector2){ c.x + s * 0.22f, c.y }, 1.8f, col);
    DrawLineEx((Vector2){ c.x + s * 0.22f, c.y }, (Vector2){ c.x + s * 0.42f, c.y }, 1.8f, col);
}

/* ---------------- widgets ---------------- */

enum {
    BTN_PRIMARY = 0,
    BTN_SECONDARY,
    BTN_GHOST,
    BTN_DANGER
};

static bool ui_button(Rectangle r, const char *label, int kind, bool enabled)
{
    bool hover = enabled && !g_block_input && mouse_in(r);
    Color bg, fg, border = { 0, 0, 0, 0 };
    if (kind == BTN_PRIMARY) {
        bg = enabled ? (hover ? mix_color(COLOR_ACCENT, COLOR_WHITE, 0.13f) : COLOR_ACCENT)
                     : (Color){ 35, 46, 68, 255 };
        fg = enabled ? COLOR_WHITE : COLOR_DIM;
    } else if (kind == BTN_SECONDARY) {
        bg = hover ? (Color){ 29, 40, 60, 255 } : COLOR_PANEL2;
        fg = enabled ? COLOR_TEXT : COLOR_DIM;
        border = hover ? COLOR_BORDER_HI : COLOR_BORDER;
    } else if (kind == BTN_DANGER) {
        bg = Fade(COLOR_DANGER, hover ? 0.18f : 0.10f);
        fg = enabled ? COLOR_DANGER : COLOR_DIM;
        border = Fade(COLOR_DANGER, 0.45f);
    } else {
        bg = hover ? COLOR_PANEL2 : (Color){ 0, 0, 0, 0 };
        fg = enabled ? COLOR_MUTED : COLOR_DIM;
    }
    if (bg.a)
        DrawRectangleRounded(r, 0.28f, 10, bg);
    if (border.a)
        DrawRectangleRoundedLinesEx(r, 0.28f, 10, 1.0f, border);
    float tw = text_w(F16, label, 15.0f);
    draw_text(F16, label, r.x + (r.width - tw) * 0.5f, r.y + (r.height - 15.0f) * 0.5f - 2.0f, 15.0f, fg);
    if (hover)
        want_cursor(MOUSE_CURSOR_POINTING_HAND);
    return hover && IsMouseButtonPressed(MOUSE_BUTTON_LEFT);
}

static bool ui_icon_button(Rectangle r, void (*icon)(Vector2, float, Color), int kind, bool enabled)
{
    bool hover = enabled && !g_block_input && mouse_in(r);
    Color bg = COLOR_PANEL2;
    Color fg = enabled ? COLOR_MUTED : COLOR_DIM;
    Color border = COLOR_BORDER;
    if (kind == BTN_GHOST) {
        bg = hover ? COLOR_PANEL2 : (Color){ 0, 0, 0, 0 };
        border = (Color){ 0, 0, 0, 0 };
    }
    if (hover) {
        fg = COLOR_TEXT;
        border = COLOR_BORDER_HI;
    }
    if (bg.a) DrawRectangleRounded(r, 0.28f, 10, bg);
    if (border.a) DrawRectangleRoundedLinesEx(r, 0.28f, 10, 1.0f, border);
    icon((Vector2){ r.x + r.width * 0.5f, r.y + r.height * 0.5f },
         r.height * 0.42f, fg);
    if (hover) want_cursor(MOUSE_CURSOR_POINTING_HAND);
    return hover && IsMouseButtonPressed(MOUSE_BUTTON_LEFT);
}

static bool ui_toggle(Rectangle r, int *value, bool enabled)
{
    bool hover = enabled && !g_block_input && mouse_in(r);
    Color track = *value ? COLOR_ACCENT : (Color){ 34, 45, 65, 255 };
    if (hover && enabled) track = mix_color(track, COLOR_WHITE, 0.08f);
    DrawRectangleRounded(r, 0.5f, 20, track);
    if (!*value) DrawRectangleRoundedLinesEx(r, 0.5f, 20, 1.0f, COLOR_BORDER);
    float kr = r.height * 0.5f - 3.0f;
    float kx = *value ? (r.x + r.width - kr - 3.0f) : (r.x + kr + 3.0f);
    DrawCircleV((Vector2){ kx, r.y + r.height * 0.5f }, kr, *value ? COLOR_WHITE : COLOR_MUTED);
    if (hover && enabled) want_cursor(MOUSE_CURSOR_POINTING_HAND);
    if (hover && enabled && IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
        *value = !*value;
        return true;
    }
    return false;
}

static void tf_click(TextField *t, Rectangle r)
{
    if (g_block_input) {
        t->focused = false;
        return;
    }
    if (IsMouseButtonPressed(MOUSE_BUTTON_LEFT))
        t->focused = mouse_in(r);
}

static void tf_draw(TextField *t, Rectangle r, const char *placeholder,
                    bool secret, bool reveal, bool enabled)
{
    Color border = t->focused ? COLOR_ACCENT : COLOR_BORDER;
    Color fill = enabled ? COLOR_FIELD : (Color){ 13, 18, 28, 255 };
    rounded(r, 0.24f, fill, border, t->focused ? 1.6f : 1.0f);

    char disp[TF_CAP * 3 + 1];
    if (secret && !reveal) {
        int count = utf8_count(t->buf, t->len);
        if (count > TF_CAP) count = TF_CAP;
        int o = 0;
        for (int i = 0; i < count; i++) {
            disp[o++] = (char)0xE2; disp[o++] = (char)0x80; disp[o++] = (char)0xA2;
        }
        disp[o] = '\0';
    } else {
        snprintf(disp, sizeof disp, "%s", t->buf);
    }

    int cursor_bytes = secret && !reveal ? utf8_count(t->buf, t->cursor) * 3 : t->cursor;
    char prefix[TF_CAP * 3 + 1];
    size_t pb = (size_t)cursor_bytes;
    if (pb >= sizeof prefix) pb = sizeof prefix - 1;
    memcpy(prefix, disp, pb);
    prefix[pb] = '\0';

    float inner = r.width - 24.0f;
    float cursor_px = text_w(F14, prefix, 14.0f);
    float offset = 0.0f;
    if (cursor_px > inner)
        offset = cursor_px - inner + 6.0f;

    Color fg = enabled ? COLOR_TEXT : COLOR_DIM;
    BeginScissorMode((int)r.x + 1, (int)r.y, (int)r.width - 2, (int)r.height);
    if (t->len == 0 && !t->focused) {
        draw_text(F14, placeholder, r.x + 12.0f, r.y + (r.height - 14.0f) * 0.5f - 2.0f, 14.0f, COLOR_DIM);
    } else {
        draw_text(F14, disp, r.x + 12.0f - offset, r.y + (r.height - 14.0f) * 0.5f - 2.0f, 14.0f, fg);
        if (t->focused && fmod((float)GetTime(), 1.0f) < 0.55f) {
            float cx = r.x + 12.0f + cursor_px - offset;
            DrawRectangle((int)cx, (int)(r.y + r.height * 0.5f - 8.0f), 2,
                          (int)(r.height * 0.5f), COLOR_ACCENT);
        }
    }
    EndScissorMode();

    if (!g_block_input && mouse_in(r)) {
        want_cursor(MOUSE_CURSOR_IBEAM);
    }
}

static int password_score(const char *s)
{
    int len = (int)strlen(s);
    if (len == 0) return 0;
    int classes = 0, lower = 0, upper = 0, digit = 0, other = 0;
    for (const char *p = s; *p; p++) {
        if (*p >= 'a' && *p <= 'z') lower = 1;
        else if (*p >= 'A' && *p <= 'Z') upper = 1;
        else if (*p >= '0' && *p <= '9') digit = 1;
        else other = 1;
    }
    classes = lower + upper + digit + other;
    int score = 0;
    if (len >= 8) score++;
    if (len >= 12) score++;
    if (classes >= 3 && len >= 8) score++;
    if (len >= 16 && classes >= 3) score++;
    if (score > 3) score = 3;
    return score;
}

static void draw_pw_strength(Rectangle r, const char *pw)
{
    int score = password_score(pw);
    Color cols[3] = { COLOR_DANGER, COLOR_WARN, COLOR_TEAL };
    float seg = (r.width - 8.0f) / 3.0f;
    for (int i = 0; i < 3; i++) {
        Rectangle s = { r.x + (seg + 4.0f) * (float)i, r.y, seg, r.height };
        Color c = i < score ? cols[score - 1] : (Color){ 33, 44, 63, 255 };
        DrawRectangleRounded(s, 0.5f, 8, c);
    }
}

/* ---------------- sidebar & chrome ---------------- */

static void job_snapshot(Job *j, JobView *v)
{
    job_lock(j);
    v->phase = j->phase;
    v->running = j->running;
    v->result = j->result;
    v->is_send = j->is_send;
    snprintf(v->status, sizeof v->status, "%s", j->status);
    snprintf(v->detail, sizeof v->detail, "%s", j->detail);
    snprintf(v->filename, sizeof v->filename, "%s", j->filename);
    snprintf(v->savepath, sizeof v->savepath, "%s", j->savepath);
    snprintf(v->remote, sizeof v->remote, "%s", j->remote);
    v->total = j->total;
    v->done = j->done;
    v->speed = j->speed;
    v->expires_at = j->expires_at;
    v->listen_port = j->listen_port;
    v->history_logged = j->history_logged;
    job_unlock(j);
}

static void toast_show(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(g_app.toast, sizeof g_app.toast, fmt, ap);
    va_end(ap);
    g_app.toast_until = mono_now() + 4.5;
}

static void draw_toast(void)
{
    if (!g_app.toast[0] || mono_now() > g_app.toast_until)
        return;
    float remain = (float)(g_app.toast_until - mono_now());
    float alpha = remain < 0.45f ? remain / 0.45f : 1.0f;
    float w = text_w(F14, g_app.toast, 14.0f) + 64.0f;
    if (w > (float)GetScreenWidth() - 80.0f) w = (float)GetScreenWidth() - 80.0f;
    Rectangle r = { ((float)GetScreenWidth() - w) * 0.5f, (float)GetScreenHeight() - 72.0f, w, 44.0f };
    Color bg = Fade((Color){ 24, 33, 50, 255 }, alpha);
    Color border = Fade(COLOR_ACCENT, 0.45f * alpha);
    DrawRectangleRounded(r, 0.5f, 20, bg);
    DrawRectangleRoundedLinesEx(r, 0.5f, 20, 1.0f, border);
    DrawCircleV((Vector2){ r.x + 24.0f, r.y + 22.0f }, 3.0f, Fade(COLOR_TEAL, alpha));
    char cut[512];
    elide_text(F14, g_app.toast, 14.0f, w - 52.0f, cut, sizeof cut);
    draw_text(F14, cut, r.x + 38.0f, r.y + 14.0f, 14.0f, Fade(COLOR_TEXT, alpha));
}

static void nav_item(Page page, const char *label, void (*icon)(Vector2, float, Color), float y)
{
    Rectangle r = { 16, y, SIDEBAR_W - 32, 44 };
    bool active = g_app.page == page;
    bool hover = !g_block_input && mouse_in(r);
    if (active) {
        DrawRectangleRounded(r, 0.30f, 10, (Color){ 24, 33, 50, 255 });
        DrawRectangleRounded((Rectangle){ r.x, r.y + 11, 3, 22 }, 0.5f, 6, COLOR_ACCENT);
    } else if (hover) {
        DrawRectangleRounded(r, 0.30f, 10, (Color){ 18, 25, 38, 255 });
    }
    Color ic = active ? COLOR_ACCENT : (hover ? COLOR_TEXT : COLOR_MUTED);
    icon((Vector2){ r.x + 25, r.y + 22 }, 18, ic);
    draw_text(F14, label, r.x + 45, r.y + 13, 14.0f, active ? COLOR_TEXT : (hover ? COLOR_TEXT : COLOR_MUTED));

    if (g_app.view.running && g_app.view.total > 0 && g_app.view.done > 0 &&
        ((page == PAGE_SEND && g_app.view.is_send) ||
         (page == PAGE_RECV && !g_app.view.is_send))) {
        float pct = g_app.view.total ? (float)g_app.view.done / (float)g_app.view.total : 0.0f;
        Rectangle bar = { r.x + 45, r.y + 32, r.width - 64, 3 };
        DrawRectangleRounded(bar, 0.5f, 6, (Color){ 34, 45, 65, 255 });
        bar.width *= pct;
        if (bar.width > 1) DrawRectangleRounded(bar, 0.5f, 6, COLOR_ACCENT);
    }

    if (hover) want_cursor(MOUSE_CURSOR_POINTING_HAND);
    if (hover && IsMouseButtonPressed(MOUSE_BUTTON_LEFT))
        g_app.page = page;
}

static void draw_sidebar(void)
{
    float h = (float)GetScreenHeight();
    DrawRectangle(0, 0, (int)SIDEBAR_W, (int)h, COLOR_SIDEBAR);
    DrawRectangle((int)SIDEBAR_W - 1, 0, 1, (int)h, COLOR_BORDER);

    Rectangle logo = { 22, 26, 40, 40 };
    DrawRectangleRounded(logo, 0.28f, 12, COLOR_ACCENT);
    DrawCircleV((Vector2){ 30, 38 }, 9.0f, Fade(COLOR_ACCENT2, 0.55f));
    ico_arrow((Vector2){ 42, 39 }, 0, 0, COLOR_WHITE);
    ico_arrow((Vector2){ 42, 49 }, 0, 1, COLOR_WHITE);

    draw_text(F18, "SILLAGE", 74, 28, 18.0f, COLOR_TEXT);
    draw_text(F12, "TRANSFER", 75, 52, 10.0f, COLOR_MUTED);

    nav_item(PAGE_SEND, "Envoyer", ico_send, 108);
    nav_item(PAGE_RECV, "Recevoir", ico_recv, 158);
    nav_item(PAGE_HISTORY, "Historique", ico_activity, 208);
    nav_item(PAGE_ABOUT, "À propos", ico_info, 258);

    Rectangle info = { 16, h - 142, SIDEBAR_W - 32, 110 };
    rounded(info, 0.10f, (Color){ 15, 21, 32, 255 }, COLOR_BORDER, 1.0f);
    draw_text(F12, "CHIFFREMENT", info.x + 14, info.y + 13, 10.0f, COLOR_DIM);
    draw_text(F18, "BRUME-512", info.x + 14, info.y + 32, 15.0f, COLOR_TEXT);
    DrawCircleV((Vector2){ info.x + 18, info.y + 61 }, 3.0f, COLOR_TEAL);
    draw_text(F12, "AEAD · 512 bits", info.x + 28, info.y + 54, 11.0f, COLOR_MUTED);
    DrawCircleV((Vector2){ info.x + 18, info.y + 79 }, 3.0f, COLOR_ACCENT);
    draw_text(F12, "Direct P2P · sans relais", info.x + 28, info.y + 72, 11.0f, COLOR_MUTED);
    draw_text(F12, "v" APP_VERSION, info.x + 14, info.y + 90, 10.0f, COLOR_DIM);
}

static void draw_background(void)
{
    int w = GetScreenWidth(), h = GetScreenHeight();
    DrawRectangleGradientV(0, 0, w, h, COLOR_BG, COLOR_BG2);
    glow((float)w - 150.0f, 80.0f, 330.0f, COLOR_ACCENT);
    glow(420.0f, (float)h - 60.0f, 300.0f, COLOR_ACCENT2);
}

static void draw_header(const char *title, const char *subtitle)
{
    float x = SIDEBAR_W + PAGE_PAD;
    draw_text(F28, title, x, 30, 28.0f, COLOR_TEXT);
    draw_text(F14, subtitle, x, 66, 14.0f, COLOR_MUTED);

    /* pastille d'état */
    bool active = g_app.view.running;
    const char *label = !active ? "Prêt" :
                        g_app.view.phase == JOB_WAITING     ? "En attente" :
                        g_app.view.phase == JOB_PREPARING   ? "Préparation" :
                        g_app.view.phase == JOB_CONNECTING  ? "Connexion" :
                        g_app.view.phase == JOB_HANDSHAKE   ? "Authentification" :
                                                              "Transfert en cours";
    float tw = text_w(F12, label, 12.0f);
    Rectangle pill = { (float)GetScreenWidth() - PAGE_PAD - tw - 50.0f, 40, tw + 38.0f, 28 };
    Color c = active ? COLOR_WARN : COLOR_TEAL;
    DrawRectangleRounded(pill, 0.5f, 16, Fade(c, 0.10f));
    DrawRectangleRoundedLinesEx(pill, 0.5f, 16, 1.0f, Fade(c, 0.30f));
    if (active) {
        float a = fmod((float)GetTime() * 260.0f, 360.0f);
        DrawRing((Vector2){ pill.x + 15, pill.y + 14 }, 4.0f, 6.0f, a, a + 110.0f, 14, c);
    } else {
        DrawCircleV((Vector2){ pill.x + 15, pill.y + 14 }, 3.5f, c);
    }
    draw_text(F12, label, pill.x + 26, pill.y + 7, 12.0f, c);
}

/* ---------------- QR ---------------- */

static void qr_destroy(void)
{
    if (g_app.qr.id != 0) {
        UnloadTexture(g_app.qr);
        g_app.qr = (Texture2D){ 0 };
        g_app.qr_px = 0;
    }
}

static int qr_build(const char *text)
{
    qr_destroy();
    uint8_t *temp = malloc(qrcodegen_BUFFER_LEN_MAX);
    uint8_t *qr = malloc(qrcodegen_BUFFER_LEN_MAX);
    if (!temp || !qr) {
        free(temp);
        free(qr);
        return -1;
    }
    bool ok = qrcodegen_encodeText(text, temp, qr, qrcodegen_Ecc_MEDIUM,
                                   qrcodegen_VERSION_MIN, qrcodegen_VERSION_MAX,
                                   qrcodegen_Mask_AUTO, true);
    if (!ok) {
        free(temp);
        free(qr);
        return -1;
    }
    int modules = qrcodegen_getSize(qr);
    int quiet = 4;
    int px = modules + quiet * 2;
    Image img = GenImageColor(px, px, WHITE);
    for (int y = 0; y < modules; y++) {
        for (int x = 0; x < modules; x++) {
            if (qrcodegen_getModule(qr, x, y))
                ImageDrawPixel(&img, x + quiet, y + quiet, (Color){ 8, 11, 17, 255 });
        }
    }
    Texture2D tex = LoadTextureFromImage(img);
    UnloadImage(img);
    free(temp);
    free(qr);
    if (tex.id == 0)
        return -1;
    SetTextureFilter(tex, TEXTURE_FILTER_POINT);
    g_app.qr = tex;
    g_app.qr_px = px;
    return 0;
}

static void draw_qr(Rectangle r)
{
    DrawRectangleRounded(r, 0.04f, 8, WHITE);
    if (g_app.qr.id == 0) {
        draw_text_c(F12, "QR indisponible", r.x + r.width * 0.5f, r.y + r.height * 0.5f - 6, 12.0f, COLOR_INK);
        return;
    }
    float pad = r.width * 0.035f;
    Rectangle dst = { r.x + pad, r.y + pad, r.width - pad * 2, r.height - pad * 2 };
    DrawTexturePro(g_app.qr, (Rectangle){ 0, 0, (float)g_app.qr_px, (float)g_app.qr_px },
                   dst, (Vector2){ 0, 0 }, 0.0f, WHITE);
}

static void qr_zoom_overlay(void)
{
    if (!g_app.qr_zoom)
        return;
    int sw = GetScreenWidth(), sh = GetScreenHeight();
    DrawRectangle(0, 0, sw, sh, Fade((Color){ 0, 0, 0, 255 }, 0.72f));
    float size = (float)sh - 220.0f;
    if (size > 500.0f) size = 500.0f;
    if (size < 260.0f) size = 260.0f;
    float cw = size + 80.0f;
    if (cw > (float)sw - 80.0f) cw = (float)sw - 80.0f;
    Rectangle c = { ((float)sw - cw) * 0.5f, ((float)sh - (size + 150.0f)) * 0.5f, cw, size + 150.0f };
    rounded(c, 0.06f, COLOR_PANEL, COLOR_BORDER, 1.0f);
    draw_text(F18, "Scanner pour recevoir", c.x + 28, c.y + 22, 18.0f, COLOR_TEXT);
    Rectangle q = { c.x + (cw - size) * 0.5f, c.y + 58, size, size };
    draw_qr(q);
    char cut[1024];
    elide_text(F12, g_app.share_link, 12.0f, c.width - 56.0f, cut, sizeof cut);
    draw_text(F12, cut, c.x + 28, c.y + size + 74, 12.0f, COLOR_MUTED);
    Rectangle close = { c.x + c.width - 46, c.y + 14, 32, 32 };
    if (ui_icon_button(close, ico_x, BTN_GHOST, true))
        g_app.qr_zoom = 0;
    if (!g_block_input && (IsMouseButtonPressed(MOUSE_BUTTON_LEFT) || IsKeyPressed(KEY_ESCAPE)) &&
        !mouse_in(c))
        g_app.qr_zoom = 0;
    if (IsKeyPressed(KEY_ESCAPE))
        g_app.qr_zoom = 0;
    g_block_input = false;
}

/* ===================================================================== */
/*  Pages Envoyer / Recevoir / Historique / À propos                     */
/* ===================================================================== */

static const int g_expiry_min[4] = { 5, 15, 60, 1440 };
static const char *g_expiry_lbl[4] = { "5 min", "15 min", "1 h", "24 h" };

static void ico_eye_on(Vector2 c, float s, Color col) { ico_eye(c, s, col, true); }
static void ico_eye_off(Vector2 c, float s, Color col) { ico_eye(c, s, col, false); }

static void job_reset_display(void)
{
    job_lock(&g_app.job);
    g_app.job.phase = JOB_IDLE;
    g_app.job.running = 0;
    g_app.job.result = 0;
    g_app.job.is_send = 0;
    g_app.job.done = 0;
    g_app.job.total = 0;
    g_app.job.speed = 0;
    g_app.job.status[0] = '\0';
    g_app.job.detail[0] = '\0';
    g_app.job.filename[0] = '\0';
    g_app.job.savepath[0] = '\0';
    g_app.job.remote[0] = '\0';
    g_app.job.expires_at = 0;
    g_app.job.listen_port = 0;
    g_app.job.history_logged = 0;
    job_unlock(&g_app.job);
    job_snapshot(&g_app.job, &g_app.view);
}

static void progress_bar(Rectangle r, float pct, Color c)
{
    if (pct < 0) pct = 0;
    if (pct > 1) pct = 1;
    DrawRectangleRounded(r, 0.5f, 12, (Color){ 31, 42, 61, 255 });
    Rectangle f = r;
    f.width *= pct;
    if (f.width >= 2.0f)
        DrawRectangleRounded(f, 0.5f, 12, c);
}

static void status_dot(Vector2 c, Color col, bool pulse)
{
    if (pulse) {
        float t = (float)(fmod(mono_now(), 1.4) / 1.4);
        DrawCircleV(c, 9.0f - 5.0f * t, Fade(col, 0.20f * (1.0f - t)));
    }
    DrawCircleV(c, 3.5f, col);
}

static void mask_text(const char *s, char *out, size_t cap)
{
    int n = utf8_count(s, (int)strlen(s));
    size_t o = 0;
    for (int i = 0; i < n && o + 4 < cap; i++) {
        out[o++] = (char)0xE2;
        out[o++] = (char)0x80;
        out[o++] = (char)0xA2;
    }
    out[o] = '\0';
}

static void copy_link(const char *link)
{
    if (!link || !*link) return;
    SetClipboardText(link);
    toast_show("Lien copié dans le presse-papiers");
}

static void select_send_file(const char *path)
{
    if (g_app.view.running) {
        toast_show("Annulez le partage en cours avant de changer de fichier");
        return;
    }
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
        toast_show("Ce n'est pas un fichier valide");
        return;
    }
    if ((uint64_t)st.st_size > MAX_FILE_SIZE) {
        toast_show("Fichier trop volumineux (limite : 1 Tio)");
        return;
    }
    if (g_app.share_visible)
        job_reset_display();
    qr_destroy();
    g_app.share_visible = 0;
    g_app.share_link[0] = '\0';
    snprintf(g_app.send_path, sizeof g_app.send_path, "%s", path);
    sanitize_filename(path, g_app.send_name, sizeof g_app.send_name);
    g_app.send_size = (uint64_t)st.st_size;
    g_app.send_has_file = 1;
    char b[48];
    fmt_bytes(g_app.send_size, b, sizeof b);
    toast_show("Fichier sélectionné · %s", b);
}

static void reset_share(void)
{
    if (g_app.view.running)
        return;
    qr_destroy();
    g_app.share_visible = 0;
    g_app.share_link[0] = '\0';
    g_app.share_code[0] = '\0';
    g_app.qr_zoom = 0;
    job_reset_display();
}

static void open_file_browser(int dir_mode);
static void open_folder_in_manager(const char *path);

static void create_share(void)
{
    if (!g_app.send_has_file) {
        toast_show("Sélectionnez d'abord un fichier");
        return;
    }
    if (g_app.send_pw_on && g_app.send_pw.len == 0) {
        toast_show("Saisissez un mot de passe ou désactivez l'option");
        return;
    }

    Invite v;
    invite_random(&v);
    v.has_password = g_app.send_pw_on ? 1 : 0;
    v.has_key = g_app.send_pw_on ? 0 : 1;
    v.expires_at = (uint64_t)wall_now() + (uint64_t)g_expiry_min[g_app.expiry_idx] * 60ull;
    int tcp_port = 0;

    if (g_app.transport == TRANSPORT_WEBRTC) {
        char code[CODE_LEN + 1];
        code_random(code);
        v.transport = TRANSPORT_WEBRTC;
        if (invite_set_code(&v, code) != 0) {
            toast_show("Impossible de générer le code de partage");
            return;
        }
        invite_set_signal(&v, g_app.send_signal.buf);
        snprintf(v.stun, sizeof v.stun, "%.*s", (int)sizeof v.stun - 1,
                 g_app.send_stun.buf);
        snprintf(g_app.share_code, sizeof g_app.share_code, "%s", v.code);
    } else {
        char *end = NULL;
        long port = strtol(g_app.send_port.buf, &end, 10);
        if (!g_app.send_port.buf[0] || (end && *end) || port < 1 || port > 65535) {
            toast_show("Port invalide (1 à 65535)");
            return;
        }
        if (!g_app.send_host.buf[0]) {
            toast_show("Indiquez l'adresse à mettre dans le lien");
            return;
        }
        if (strlen(g_app.send_host.buf) > 253) {
            toast_show("Adresse trop longue (253 caractères maximum)");
            return;
        }
        v.transport = TRANSPORT_TCP;
        copy_path(v.host, sizeof v.host, g_app.send_host.buf);
        v.port = (int)port;
        tcp_port = (int)port;
        g_app.share_code[0] = '\0';
    }

    invite_build_link(&v, g_app.share_link, sizeof g_app.share_link);
    if (qr_build(g_app.share_link) != 0)
        toast_show("QR code indisponible — le lien reste utilisable");
    g_app.send_inv = v;
    g_app.share_visible = 1;

    int rc = start_send_job(&g_app.job, g_app.send_path, &v,
                            g_app.send_pw_on ? g_app.send_pw.buf : NULL, tcp_port, 0);
    if (rc != 0) {
        g_app.share_visible = 0;
        g_app.share_link[0] = '\0';
        g_app.share_code[0] = '\0';
        qr_destroy();
        job_reset_display();
        toast_show("Impossible de démarrer le partage");
        return;
    }
    toast_show(g_app.transport == TRANSPORT_WEBRTC
               ? "Partage prêt — communiquez le code"
               : "Partage prêt — le lien peut être transmis");
}

static void start_receive(void)
{
    if (g_app.view.running) {
        toast_show("Un transfert est déjà en cours");
        return;
    }
    if (!g_app.recv_parsed) {
        toast_show("Collez un lien SILLAGE valide");
        return;
    }
    if (g_app.recv_inv.expires_at && (uint64_t)wall_now() > g_app.recv_inv.expires_at) {
        toast_show("Ce lien a expiré");
        return;
    }
    if (g_app.recv_inv.pw_unknown) {
        g_app.recv_inv.has_password = g_app.recv_pw.len > 0 ? 1 : 0;
        g_app.recv_inv.has_key = g_app.recv_pw.len > 0 ? 0 : 1;
    }
    if (g_app.recv_inv.has_password && g_app.recv_pw.len == 0) {
        toast_show("Ce partage demande un mot de passe");
        return;
    }
    if (!g_app.recv_dir.buf[0]) {
        char d[PATH_MAX];
        default_download_dir(d, sizeof d);
        tf_set(&g_app.recv_dir, d);
    }
    if (ensure_dir(g_app.recv_dir.buf) != 0) {
        toast_show("Dossier de destination inaccessible");
        return;
    }
    if (g_app.share_visible || g_app.qr.id != 0)
        reset_share();
    int rc = start_recv_job(&g_app.job, &g_app.recv_inv,
                            g_app.recv_inv.has_password ? g_app.recv_pw.buf : NULL,
                            g_app.recv_dir.buf);
    if (rc != 0) {
        job_reset_display();
        toast_show("Impossible de démarrer la réception");
        return;
    }
    toast_show("Connexion au partage…");
}

/* ---------------- page Envoyer ---------------- */

static void draw_busy_panel(Rectangle sc, void (*icon)(Vector2, float, Color), Color accent,
                            const char *title, const char *line1, const char *line2,
                            const char *button, Page target)
{
    float cx = sc.x + sc.width * 0.5f;
    float cy = sc.y + sc.height * 0.30f;
    DrawCircleV((Vector2){ cx, cy }, 48, Fade(accent, 0.08f));
    DrawCircleLinesV((Vector2){ cx, cy }, 48, Fade(accent, 0.22f));
    icon((Vector2){ cx, cy }, 30, Fade(accent, 0.90f));
    draw_text_c(F18, title, cx, cy + 72, 17.0f, COLOR_TEXT);
    draw_text_c(F12, line1, cx, cy + 100, 12.0f, COLOR_MUTED);
    draw_text_c(F12, line2, cx, cy + 118, 12.0f, COLOR_DIM);
    Rectangle b = { cx - 100, sc.y + sc.height - 72, 200, 42 };
    if (ui_button(b, button, BTN_SECONDARY, true))
        g_app.page = target;
}

static void idle_footer(Rectangle sc, const char *title, const char *l1, const char *l2,
                        void (*icon)(Vector2, float, Color), Color accent)
{
    Rectangle info = { sc.x + 16, sc.y + sc.height - 98, sc.width - 32, 78 };
    rounded(info, 0.10f, (Color){ 13, 19, 29, 255 }, COLOR_BORDER, 1.0f);
    DrawCircleV((Vector2){ info.x + 28, info.y + 39 }, 18, Fade(accent, 0.10f));
    icon((Vector2){ info.x + 28, info.y + 39 }, 17, accent);
    draw_text(F14, title, info.x + 56, info.y + 14, 13.0f, COLOR_TEXT);
    draw_text(F12, l1, info.x + 56, info.y + 36, 11.0f, COLOR_MUTED);
    draw_text(F12, l2, info.x + 56, info.y + 53, 11.0f, COLOR_MUTED);
}

static void draw_send_idle_panel(Rectangle sc)
{
    float cx = sc.x + sc.width * 0.5f;
    float y = sc.y + 66;
    Rectangle q = { cx - 46, y, 92, 92 };
    rounded(q, 0.10f, COLOR_FIELD, COLOR_BORDER, 1.0f);
    ico_qr((Vector2){ cx, y + 46 }, 40, Fade(COLOR_ACCENT, 0.75f));

    draw_text_c(F18, "Prêt à partager ?", cx, y + 118, 18.0f, COLOR_TEXT);
    draw_text_c(F12, "Choisissez un fichier, puis créez un lien.", cx, y + 148, 12.0f, COLOR_MUTED);
    draw_text_c(F12, "Le QR code et le lien apparaîtront ici.", cx, y + 166, 12.0f, COLOR_DIM);

    float sy = y + 214;
    const char *steps[3] = {
        "Sélectionnez le fichier à envoyer",
        "Protégez-le avec un mot de passe (optionnel)",
        "Partagez le lien ou laissez scanner le QR code"
    };
    for (int i = 0; i < 3; i++) {
        Rectangle num = { sc.x + 28, sy + i * 48, 24, 24 };
        DrawCircleV((Vector2){ num.x + 12, num.y + 12 }, 12, Fade(COLOR_ACCENT, 0.15f));
        char n[4];
        snprintf(n, sizeof n, "%d", i + 1);
        draw_text_c(F12, n, num.x + 12, num.y + 6, 12.0f, COLOR_ACCENT);
        draw_text(F12, steps[i], sc.x + 62, sy + i * 48 + 4, 12.0f, COLOR_MUTED);
    }

    idle_footer(sc, "Chiffré de bout en bout",
                "Aucun relais de données : le fichier passe directement",
                "de votre machine à celle du destinataire.",
                ico_shield, COLOR_TEAL);
}

static void draw_share_panel(Rectangle sc)
{
    card(sc);
    float pad = 16.0f;
    draw_text(F18, "Partage", sc.x + pad, sc.y + 15, 16.0f, COLOR_TEXT);

    if (g_app.view.running && !g_app.view.is_send) {
        draw_busy_panel(sc, ico_recv, COLOR_TEAL, "Réception en cours",
                        "Un seul transfert à la fois.", "Terminez la réception pour créer un partage.",
                        "Voir la réception", PAGE_RECV);
        return;
    }

    if (!g_app.share_visible) {
        draw_send_idle_panel(sc);
        return;
    }

    JobView *v = &g_app.view;
    bool done = v->phase == JOB_DONE;
    bool err = v->phase == JOB_ERROR;
    bool cancelled = v->phase == JOB_CANCELLED;
    bool active = v->running;
    Color dot = done ? COLOR_TEAL : (err || cancelled) ? COLOR_DANGER :
                (active ? (v->phase == JOB_WAITING ? COLOR_WARN : COLOR_ACCENT) : COLOR_MUTED);
    const char *state = done ? "Terminé" : err ? "Erreur" : cancelled ? "Annulé" :
                        v->phase == JOB_WAITING ? "En attente" :
                        active ? "En cours" : "Prêt";
    status_dot((Vector2){ sc.x + sc.width - 62, sc.y + 25 }, dot, active && !done);
    draw_text(F12, state, sc.x + sc.width - 53, sc.y + 18, 11.0f, dot);

    float qr = sc.height * 0.26f;
    if (qr < 120) qr = 120;
    if (qr > 196) qr = 196;
    float qrY = sc.y + 48;

    if (g_app.send_inv.transport == TRANSPORT_WEBRTC && g_app.send_inv.code[0]) {
        char fmt[16];
        code_format(g_app.send_inv.code, fmt, sizeof fmt);
        Rectangle cb = { sc.x + pad, sc.y + 44, sc.width - pad * 2, 54 };
        rounded(cb, 0.14f, Fade(COLOR_ACCENT, 0.09f), Fade(COLOR_ACCENT, 0.38f), 1.0f);
        draw_text(F12, "CODE DE PARTAGE", cb.x + 14, cb.y + 8, 9.0f, COLOR_MUTED);
        draw_text(F22, fmt, cb.x + 14, cb.y + 21, 20.0f, COLOR_TEXT);
        Rectangle ccopy = { cb.x + cb.width - 42, cb.y + 11, 32, 32 };
        if (ui_icon_button(ccopy, ico_copy, BTN_GHOST, true)) {
            SetClipboardText(fmt);
            toast_show("Code de partage copié");
        }
        draw_text(F12, "Chez le destinataire", cb.x + 124,
                  cb.y + 8, 9.0f, COLOR_DIM);

        qr = sc.height * 0.21f;
        if (qr < 104) qr = 104;
        if (qr > 158) qr = 158;
        qrY = cb.y + cb.height + 8;
    }

    Rectangle qrR = { sc.x + (sc.width - qr) * 0.5f, qrY, qr, qr };
    draw_qr(qrR);
    if (!g_block_input && mouse_in(qrR) && IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
        g_app.qr_zoom = 1;
    }
    if (!g_block_input && mouse_in(qrR))
        want_cursor(MOUSE_CURSOR_POINTING_HAND);
    draw_text_c(F12, "Cliquez pour agrandir", sc.x + sc.width * 0.5f, qrR.y + qr + 5, 10.0f, COLOR_DIM);

    Rectangle lb = { sc.x + pad, qrR.y + qr + 24, sc.width - pad * 2, 58 };
    rounded(lb, 0.16f, COLOR_FIELD, COLOR_BORDER, 1.0f);
    draw_text(F12, "Lien de partage", lb.x + 11, lb.y + 7, 10.0f, COLOR_DIM);
    char cut[1024];
    elide_text(F12, g_app.share_link, 12.0f, lb.width - 60, cut, sizeof cut);
    draw_text(F12, cut, lb.x + 11, lb.y + 24, 12.0f, COLOR_TEXT);
    Rectangle copyR = { lb.x + lb.width - 42, lb.y + 12, 34, 34 };
    bool copied = ui_icon_button(copyR, ico_copy, BTN_GHOST, true);
    if (copied) copy_link(g_app.share_link);
    if (!copied && !g_block_input && mouse_in(lb) && !mouse_in(copyR) &&
        IsMouseButtonPressed(MOUSE_BUTTON_LEFT))
        copy_link(g_app.share_link);
    if (!g_block_input && mouse_in(lb) && !mouse_in(copyR))
        want_cursor(MOUSE_CURSOR_POINTING_HAND);

    float y = lb.y + lb.height + 8;
    if (g_app.send_inv.has_password) {
        Rectangle pr = { sc.x + pad, y, sc.width - pad * 2, 32 };
        ico_lock((Vector2){ pr.x + 13, pr.y + 16 }, 14, COLOR_MUTED);
        draw_text(F12, "Mot de passe", pr.x + 27, pr.y + 8, 10.0f, COLOR_DIM);
        char masked[512];
        mask_text(g_app.send_pw.buf, masked, sizeof masked);
        char cut2[512];
        elide_text(F12, g_app.send_reveal ? g_app.send_pw.buf : masked, 12.0f,
                   pr.width - 92, cut2, sizeof cut2);
        draw_text(F12, cut2, pr.x + 96, pr.y + 8, 12.0f, COLOR_TEXT);
        Rectangle eye = { pr.x + pr.width - 34, pr.y + 1, 30, 30 };
        if (ui_icon_button(eye, g_app.send_reveal ? ico_eye_on : ico_eye_off, BTN_GHOST, true))
            g_app.send_reveal = !g_app.send_reveal;
        y = pr.y + pr.height + 6;
    }

    int64_t left = (int64_t)g_app.send_inv.expires_at - (int64_t)wall_now();
    char expbuf[128];
    if (left > 0) {
        char dur[32];
        fmt_duration((uint64_t)left, dur, sizeof dur);
        snprintf(expbuf, sizeof expbuf, "Expire dans %s", dur);
    } else {
        snprintf(expbuf, sizeof expbuf, "Lien expiré");
    }
    ico_clock((Vector2){ sc.x + pad + 9, y + 11 }, 13, left > 0 ? COLOR_MUTED : COLOR_DANGER);
    draw_text(F12, expbuf, sc.x + pad + 22, y + 3, 11.0f, left > 0 ? COLOR_MUTED : COLOR_DANGER);
    y += 28;

    /* zone d'état / progression */
    if (v->phase == JOB_WAITING || (v->phase == JOB_HANDSHAKE && !v->running)) {
        draw_text(F14, v->status[0] ? v->status : "En attente de connexion…",
                  sc.x + pad, y, 13.0f, COLOR_TEXT);
        if (v->detail[0]) {
            char d[512];
            elide_text(F12, v->detail, 11.0f, sc.width - pad * 2, d, sizeof d);
            draw_text(F12, d, sc.x + pad, y + 20, 11.0f, COLOR_MUTED);
        }
    } else if (v->phase == JOB_TRANSFER) {
        float pct = v->total ? (float)((double)v->done / (double)v->total) : 0.0f;
        char pl[32];
        snprintf(pl, sizeof pl, "%.0f %%", pct * 100.0f);
        draw_text(F22, pl, sc.x + pad, y - 4, 20.0f, COLOR_TEXT);
        char b1[48], b2[48], st[160];
        fmt_bytes(v->done, b1, sizeof b1);
        fmt_bytes(v->total, b2, sizeof b2);
        snprintf(st, sizeof st, "%s / %s", b1, b2);
        draw_text_r(F12, st, sc.x + sc.width - pad, y + 2, 11.0f, COLOR_MUTED);
        Rectangle bar = { sc.x + pad, y + 28, sc.width - pad * 2, 8 };
        progress_bar(bar, pct, COLOR_ACCENT);
        char sp[48], rest[160], eta[48];
        fmt_speed(v->speed, sp, sizeof sp);
        if (v->speed > 0)
            fmt_duration((v->total - v->done) / v->speed, eta, sizeof eta);
        else
            snprintf(eta, sizeof eta, "—");
        snprintf(rest, sizeof rest, "%s/s · reste %s", sp, eta);
        draw_text(F12, rest, sc.x + pad, y + 43, 11.0f, COLOR_MUTED);
    } else if (done) {
        DrawCircleV((Vector2){ sc.x + pad + 16, y + 16 }, 15, Fade(COLOR_TEAL, 0.14f));
        ico_check((Vector2){ sc.x + pad + 16, y + 16 }, 16, COLOR_TEAL);
        draw_text(F18, "Transfert terminé", sc.x + pad + 42, y + 2, 15.0f, COLOR_TEAL);
        char b[48], line[320];
        fmt_bytes(v->total, b, sizeof b);
        snprintf(line, sizeof line, "%s · %s", v->filename[0] ? v->filename : "fichier", b);
        char lc[256];
        elide_text(F12, line, 11.0f, sc.width - pad * 2 - 42, lc, sizeof lc);
        draw_text(F12, lc, sc.x + pad + 42, y + 22, 11.0f, COLOR_MUTED);
    } else if (err || cancelled) {
        Color c = cancelled ? COLOR_MUTED : COLOR_DANGER;
        DrawCircleV((Vector2){ sc.x + pad + 15, y + 15 }, 14, Fade(c, 0.14f));
        ico_x((Vector2){ sc.x + pad + 15, y + 15 }, 14, c);
        snprintf(expbuf, sizeof expbuf, "%.127s", v->status[0] ? v->status : "Transfert interrompu");
        draw_text(F14, expbuf, sc.x + pad + 38, y + 1, 13.0f, c);
        if (v->detail[0])
            draw_wrapped(F12, v->detail, (Rectangle){ sc.x + pad + 38, y + 21, sc.width - pad * 2 - 38, 40 },
                         11.0f, COLOR_MUTED, 14.0f);
    } else {
        draw_text(F14, v->status[0] ? v->status : "Partage prêt", sc.x + pad, y, 13.0f, COLOR_TEXT);
        draw_text(F12, "En attente du destinataire…", sc.x + pad, y + 20, 11.0f, COLOR_MUTED);
    }

    Rectangle action = { sc.x + pad, sc.y + sc.height - 58, sc.width - pad * 2, 42 };
    if (v->running) {
        if (ui_button(action, "Annuler le partage", BTN_DANGER, true))
            job_request_cancel(&g_app.job);
    } else {
        if (ui_button(action, "Nouveau partage", BTN_PRIMARY, true))
            reset_share();
    }
}

static void draw_send_page(void)
{
    App *a = &g_app;
    bool allow = !g_block_input && !a->view.running;

    float x = SIDEBAR_W + PAGE_PAD;
    float y = HEADER_H + 18;
    float w = (float)GetScreenWidth() - x - PAGE_PAD;
    float bottom = (float)GetScreenHeight() - 24;
    float cardH = bottom - y;
    float gap = 18;
    float leftW = (w - gap) * 0.565f;
    float rightW = w - leftW - gap;
    float fileH = 132, optH = 414;

    draw_header("Envoyer un fichier", "Chiffrez et partagez un fichier en pair-à-pair.");

    /* ---- carte fichier ---- */
    Rectangle fc = { x, y, leftW, fileH };
    card(fc);
    draw_text(F18, "Fichier à envoyer", fc.x + 18, fc.y + 13, 16.0f, COLOR_TEXT);
    DrawCircleV((Vector2){ fc.x + fc.width - 28, fc.y + 24 }, 10, Fade(COLOR_ACCENT, 0.15f));
    draw_text_c(F12, "1", fc.x + fc.width - 28, fc.y + 18, 11.0f, COLOR_ACCENT);

    Rectangle area = { fc.x + 14, fc.y + 44, fc.width - 28, fileH - 56 };
    if (!a->send_has_file) {
        rounded(area, 0.10f, Fade(COLOR_ACCENT, 0.035f), COLOR_BORDER, 1.0f);
        Rectangle ic = { area.x + 22, area.y + area.height * 0.5f - 22, 44, 44 };
        DrawCircleV((Vector2){ ic.x + 22, ic.y + 22 }, 22, Fade(COLOR_ACCENT, 0.10f));
        ico_file((Vector2){ ic.x + 22, ic.y + 22 }, 24, COLOR_ACCENT);
        draw_text(F14, "Déposez un fichier ici", area.x + 80, area.y + 22, 14.0f, COLOR_TEXT);
        draw_text(F12, "ou parcourez vos dossiers", area.x + 80, area.y + 43, 11.0f, COLOR_MUTED);
        Rectangle browse = { area.x + area.width - 116, area.y + area.height * 0.5f - 17, 100, 34 };
        if (ui_button(browse, "Parcourir", BTN_SECONDARY, allow))
            open_file_browser(0);
        if (allow && mouse_in(area) && !mouse_in(browse) && IsMouseButtonPressed(MOUSE_BUTTON_LEFT))
            open_file_browser(0);
        if (allow && mouse_in(area) && !mouse_in(browse))
            want_cursor(MOUSE_CURSOR_POINTING_HAND);
    } else {
        rounded(area, 0.10f, Fade(COLOR_ACCENT, 0.045f), Fade(COLOR_ACCENT, 0.22f), 1.0f);
        DrawCircleV((Vector2){ area.x + 34, area.y + area.height * 0.5f }, 22, Fade(COLOR_ACCENT, 0.12f));
        ico_file((Vector2){ area.x + 34, area.y + area.height * 0.5f }, 22, COLOR_ACCENT);
        char name[512];
        elide_text(F14, a->send_name, 14.0f, area.width - 220, name, sizeof name);
        draw_text(F14, name, area.x + 66, area.y + 18, 14.0f, COLOR_TEXT);
        char sz[48];
        fmt_bytes(a->send_size, sz, sizeof sz);
        draw_text(F12, sz, area.x + 66, area.y + 39, 11.0f, COLOR_MUTED);
        Rectangle change = { area.x + area.width - 148, area.y + area.height * 0.5f - 17, 88, 34 };
        if (ui_button(change, "Changer", BTN_SECONDARY, allow))
            open_file_browser(0);
        Rectangle xb = { area.x + area.width - 50, area.y + area.height * 0.5f - 15, 30, 30 };
        if (ui_icon_button(xb, ico_x, BTN_GHOST, allow)) {
            a->send_has_file = 0;
            a->send_path[0] = '\0';
            a->send_name[0] = '\0';
            a->send_size = 0;
        }
    }

    /* ---- carte options ---- */
    Rectangle oc = { x, y + fileH + gap, leftW, optH };
    card(oc);
    draw_text(F18, "Options de partage", oc.x + 18, oc.y + 13, 16.0f, COLOR_TEXT);
    DrawCircleV((Vector2){ oc.x + oc.width - 28, oc.y + 24 }, 10, Fade(COLOR_ACCENT, 0.15f));
    draw_text_c(F12, "2", oc.x + oc.width - 28, oc.y + 18, 11.0f, COLOR_ACCENT);

    draw_text(F12, "Mode de connexion", oc.x + 18, oc.y + 44, 10.0f, COLOR_DIM);
    {
        float segW = (oc.width - 36 - 8) * 0.5f;
        const char *labels[2] = { "WebRTC", "TCP direct" };
        for (int i = 0; i < 2; i++) {
            Rectangle b = { oc.x + 18 + (segW + 8) * i, oc.y + 60, segW, 32 };
            bool sel = (i == 0 && a->transport == TRANSPORT_WEBRTC) ||
                       (i == 1 && a->transport == TRANSPORT_TCP);
            Color bg = sel ? COLOR_ACCENT : (Color){ 14, 20, 31, 255 };
            Color bd = sel ? COLOR_ACCENT : COLOR_BORDER;
            Color fg = sel ? COLOR_WHITE : COLOR_MUTED;
            DrawRectangleRounded(b, 0.34f, 10, bg);
            DrawRectangleRoundedLinesEx(b, 0.34f, 10, 1.0f, bd);
            draw_text_c(F12, labels[i], b.x + b.width * 0.5f, b.y + 9, 11.0f, fg);
            if (allow && mouse_in(b)) {
                want_cursor(MOUSE_CURSOR_POINTING_HAND);
                if (IsMouseButtonPressed(MOUSE_BUTTON_LEFT))
                    a->transport = (i == 0) ? TRANSPORT_WEBRTC : TRANSPORT_TCP;
            }
        }
    }

    draw_text(F14, "Protéger par mot de passe", oc.x + 18, oc.y + 104, 14.0f, COLOR_TEXT);
    draw_text(F12, "La clé est dérivée localement (scrypt).", oc.x + 18, oc.y + 121, 10.5f, COLOR_MUTED);
    Rectangle tog = { oc.x + oc.width - 64, oc.y + 106, 44, 24 };
    if (ui_toggle(tog, &a->send_pw_on, allow)) {
        if (!a->send_pw_on) a->send_reveal = 0;
    }

    float rowY = oc.y + 136;
    if (a->send_pw_on) {
        Rectangle pf = { oc.x + 18, rowY, oc.width - 36 - 44, 40 };
        Rectangle eye = { oc.x + oc.width - 18 - 38, rowY + 1, 34, 34 };
        tf_click(&a->send_pw, pf);
        if (allow) tf_update(&a->send_pw);
        tf_draw(&a->send_pw, pf, "Mot de passe du partage", true, a->send_reveal, allow);
        if (ui_icon_button(eye, a->send_reveal ? ico_eye_on : ico_eye_off, BTN_GHOST, allow))
            a->send_reveal = !a->send_reveal;
        if (a->send_pw.len > 0)
            draw_pw_strength((Rectangle){ pf.x, pf.y + 42, pf.width, 3 }, a->send_pw.buf);
    } else {
        Rectangle info = { oc.x + 18, rowY, oc.width - 36, 40 };
        rounded(info, 0.18f, (Color){ 14, 20, 31, 255 }, COLOR_BORDER, 1.0f);
        ico_lock((Vector2){ info.x + 18, info.y + 20 }, 15, COLOR_TEAL);
        draw_text(F12, "La clé est dérivée du code de partage.", info.x + 36, info.y + 13, 11.0f, COLOR_MUTED);
    }

    draw_text(F12, "Validité du partage", oc.x + 18, oc.y + 184, 10.0f, COLOR_DIM);
    float cw = (oc.width - 36 - 18) / 4.0f;
    for (int i = 0; i < 4; i++) {
        Rectangle c = { oc.x + 18 + (cw + 6) * i, oc.y + 200, cw, 32 };
        bool sel = a->expiry_idx == i;
        Color bg = sel ? COLOR_ACCENT : (Color){ 14, 20, 31, 255 };
        Color bd = sel ? COLOR_ACCENT : COLOR_BORDER;
        Color fg = sel ? COLOR_WHITE : COLOR_MUTED;
        DrawRectangleRounded(c, 0.34f, 10, bg);
        DrawRectangleRoundedLinesEx(c, 0.34f, 10, 1.0f, bd);
        draw_text_c(F12, g_expiry_lbl[i], c.x + c.width * 0.5f, c.y + 9, 11.0f, fg);
        if (allow && mouse_in(c)) {
            want_cursor(MOUSE_CURSOR_POINTING_HAND);
            if (IsMouseButtonPressed(MOUSE_BUTTON_LEFT))
                a->expiry_idx = i;
        }
    }

    if (a->transport == TRANSPORT_WEBRTC) {
        draw_text(F12, "Serveur PeerJS", oc.x + 18, oc.y + 240, 10.0f, COLOR_DIM);
        Rectangle sf = { oc.x + 18, oc.y + 256, oc.width - 36, 36 };
        tf_click(&a->send_signal, sf);
        if (allow) tf_update(&a->send_signal);
        tf_draw(&a->send_signal, sf, "0.peerjs.com:443", false, true, allow);

        draw_text(F12, "Serveur STUN", oc.x + 18, oc.y + 300, 10.0f, COLOR_DIM);
        Rectangle stf = { oc.x + 18, oc.y + 316, oc.width - 36, 36 };
        tf_click(&a->send_stun, stf);
        if (allow) tf_update(&a->send_stun);
        tf_draw(&a->send_stun, stf, "stun:hôte:port (vide = réseau local)", false, true, allow);
    } else {
        draw_text(F12, "Réseau", oc.x + 18, oc.y + 240, 10.0f, COLOR_DIM);
        Rectangle pf = { oc.x + 18, oc.y + 256, 86, 38 };
        tf_click(&a->send_port, pf);
        if (allow) tf_update(&a->send_port);
        tf_draw(&a->send_port, pf, "Port", false, true, allow);

        float hostW = oc.width - 36 - 86 - 8 - 8 - 54;
        Rectangle hf = { pf.x + pf.width + 8, pf.y, hostW, 38 };
        tf_click(&a->send_host, hf);
        if (allow) tf_update(&a->send_host);
        tf_draw(&a->send_host, hf, "Adresse publique", false, true, allow);
        Rectangle autoB = { hf.x + hf.width + 8, hf.y, 46, 38 };
        if (ui_button(autoB, "Auto", BTN_SECONDARY, allow)) {
            char ip[128];
            local_ipv4(ip, sizeof ip);
            tf_set(&a->send_host, ip);
        }
        draw_text(F12, "Le port doit être joignable depuis le réseau du destinataire.",
                  oc.x + 18, oc.y + 306, 10.0f, COLOR_DIM);
    }

    Rectangle create = { oc.x + 18, oc.y + optH - 50, oc.width - 36, 42 };
    if (ui_button(create, a->transport == TRANSPORT_WEBRTC
                          ? "Créer le code de partage" : "Créer le lien de partage",
                  BTN_PRIMARY, allow && a->send_has_file))
        create_share();

    /* ---- astuces ---- */
    float tipsY = oc.y + optH + gap;
    float tipsH = bottom - tipsY;
    if (tipsH >= 82) {
        Rectangle tc = { x, tipsY, leftW, tipsH };
        rounded(tc, 0.055f, (Color){ 13, 19, 29, 255 }, COLOR_BORDER, 1.0f);
        draw_text(F14, "Bon à savoir", tc.x + 18, tc.y + 13, 12.0f, COLOR_TEXT);
        const char *tips[3];
        if (g_app.transport == TRANSPORT_WEBRTC) {
            tips[0] = "Code à 10 caractères, dérivé par scrypt.";
            tips[1] = "PeerJS relaie des SDP signés, jamais le fichier.";
            tips[2] = "Sans TURN : direct si le NAT le permet.";
        } else {
            tips[0] = "Un seul transfert réussi par lien.";
            tips[1] = "Sans mot de passe, le lien contient la clé.";
            tips[2] = "Aucun relais : les deux machines se connectent directement.";
        }
        for (int i = 0; i < 3; i++) {
            if (tc.y + 40 + i * 22 + 12 > tc.y + tipsH) break;
            DrawCircleV((Vector2){ tc.x + 22, tc.y + 46 + i * 22 }, 2.0f, COLOR_ACCENT);
            char cut[512];
            elide_text(F12, tips[i], 11.0f, tc.width - 52, cut, sizeof cut);
            draw_text(F12, cut, tc.x + 32, tc.y + 39 + i * 22, 11.0f, COLOR_MUTED);
        }
    }

    /* ---- panneau partage ---- */
    Rectangle sc = { x + leftW + gap, y, rightW, cardH };
    draw_share_panel(sc);
}

/* ---------------- page Recevoir ---------------- */

static void open_folder_in_manager(const char *path)
{
    if (!path || !*path) return;
    char dir[PATH_MAX];
    snprintf(dir, sizeof dir, "%s", path);
    char *slash = strrchr(dir, '/');
    if (slash && slash != dir)
        *slash = '\0';
    else if (slash)
        dir[1] = '\0';
    pid_t pid = fork();
    if (pid == 0) {
        setsid();
        pid_t p2 = fork();
        if (p2 == 0) {
            execlp("xdg-open", "xdg-open", dir, (char *)NULL);
            _exit(127);
        }
        _exit(0);
    }
}

static void parse_recv_link(void)
{
    App *a = &g_app;
    a->recv_parsed = 0;
    a->recv_error[0] = '\0';
    if (a->recv_link.len == 0)
        return;
    Invite v;
    char err[256];
    if (invite_parse(a->recv_link.buf, &v, err, sizeof err) == 0) {
        a->recv_inv = v;
        a->recv_parsed = 1;
    } else {
        snprintf(a->recv_error, sizeof a->recv_error, "%s", err);
    }
}

static void draw_recv_idle(Rectangle sc)
{
    float cx = sc.x + sc.width * 0.5f;
    float y = sc.y + 74;
    DrawCircleV((Vector2){ cx, y + 34 }, 46, Fade(COLOR_ACCENT, 0.08f));
    DrawCircleLinesV((Vector2){ cx, y + 34 }, 46, Fade(COLOR_ACCENT, 0.22f));
    ico_recv((Vector2){ cx, y + 34 }, 30, Fade(COLOR_ACCENT, 0.85f));
    draw_text_c(F18, "Aucun transfert en cours", cx, y + 100, 18.0f, COLOR_TEXT);
    draw_text_c(F12, "Saisissez le code de partage ou collez un lien.", cx, y + 128, 12.0f, COLOR_MUTED);

    float sy = y + 176;
    const char *steps[3] = {
        "Saisissez le code ou collez le lien reçu",
        "Choisissez le dossier de destination",
        "Le fichier est vérifié puis enregistré"
    };
    for (int i = 0; i < 3; i++) {
        DrawCircleV((Vector2){ sc.x + 40, sy + i * 46 + 11 }, 11, Fade(COLOR_TEAL, 0.12f));
        char n[4];
        snprintf(n, sizeof n, "%d", i + 1);
        draw_text_c(F12, n, sc.x + 40, sy + i * 46 + 5, 10.0f, COLOR_TEAL);
        draw_text(F12, steps[i], sc.x + 62, sy + i * 46 + 4, 12.0f, COLOR_MUTED);
    }

    idle_footer(sc, "Le lien est la clé",
                "Un lien = un transfert. Vérifiez son origine avant",
                "de l'ouvrir : il contient le jeton d'accès.",
                ico_lock, COLOR_ACCENT);
}

static void draw_recv_active(Rectangle sc)
{
    JobView *v = &g_app.view;
    float pad = 18.0f;
    bool done = v->phase == JOB_DONE;
    bool err = v->phase == JOB_ERROR || v->phase == JOB_CANCELLED;
    bool active = v->running;

    draw_text(F18, "Réception", sc.x + pad, sc.y + 15, 16.0f, COLOR_TEXT);
    Color dot = done ? COLOR_TEAL : err ? COLOR_DANGER : COLOR_ACCENT;
    const char *st = done ? "Terminé" : err ? "Erreur" : v->phase == JOB_HANDSHAKE ? "Authentification" :
                      v->phase == JOB_CONNECTING ? "Connexion" : "Réception";
    status_dot((Vector2){ sc.x + sc.width - 62, sc.y + 25 }, dot, active && !done);
    draw_text(F12, st, sc.x + sc.width - 53, sc.y + 18, 11.0f, dot);

    char title[512];
    snprintf(title, sizeof title, "%s", v->filename[0] ? v->filename : "Fichier entrant");
    char cut[512];
    elide_text(F16, title, 16.0f, sc.width - pad * 2, cut, sizeof cut);
    draw_text(F16, cut, sc.x + pad, sc.y + 50, 16.0f, COLOR_TEXT);

    if (done) {
        DrawCircleV((Vector2){ sc.x + sc.width * 0.5f, sc.y + sc.height * 0.34f }, 46, Fade(COLOR_TEAL, 0.12f));
        DrawCircleLinesV((Vector2){ sc.x + sc.width * 0.5f, sc.y + sc.height * 0.34f }, 46, Fade(COLOR_TEAL, 0.30f));
        ico_check((Vector2){ sc.x + sc.width * 0.5f, sc.y + sc.height * 0.34f }, 40, COLOR_TEAL);
        draw_text_c(F18, "Fichier reçu et vérifié", sc.x + sc.width * 0.5f,
                    sc.y + sc.height * 0.34f + 66, 16.0f, COLOR_TEAL);

        char b[48];
        fmt_bytes(v->total, b, sizeof b);
        draw_text_c(F14, b, sc.x + sc.width * 0.5f, sc.y + sc.height * 0.34f + 92, 13.0f, COLOR_MUTED);

        Rectangle pathBox = { sc.x + pad, sc.y + sc.height - 158, sc.width - pad * 2, 44 };
        rounded(pathBox, 0.18f, COLOR_FIELD, COLOR_BORDER, 1.0f);
        ico_folder((Vector2){ pathBox.x + 18, pathBox.y + 22 }, 16, COLOR_MUTED);
        elide_path(F12, v->savepath, 11.0f, pathBox.width - 42, cut, sizeof cut);
        draw_text(F12, cut, pathBox.x + 34, pathBox.y + 15, 11.0f, COLOR_MUTED);

        Rectangle open = { sc.x + pad, sc.y + sc.height - 100, (sc.width - pad * 2 - 10) * 0.5f, 42 };
        Rectangle nw = { open.x + open.width + 10, open.y, open.width, 42 };
        if (ui_button(open, "Ouvrir le dossier", BTN_SECONDARY, true))
            open_folder_in_manager(v->savepath);
        if (ui_button(nw, "Nouveau transfert", BTN_PRIMARY, true)) {
            job_reset_display();
            tf_clear(&g_app.recv_link);
            g_app.recv_parsed = 0;
            g_app.recv_last_len = 0;
            g_app.recv_error[0] = '\0';
        }
        return;
    }

    float ringD = sc.width - 150.0f;
    float maxD = sc.height * 0.34f;
    if (ringD > maxD) ringD = maxD;
    if (ringD > 190) ringD = 190;
    if (ringD < 120) ringD = 120;
    Vector2 c = { sc.x + sc.width * 0.5f, sc.y + 128.0f + ringD * 0.5f };
    float rad = ringD * 0.5f;
    float pct = v->total ? (float)((double)v->done / (double)v->total) : 0.0f;
    DrawRing(c, rad - 10, rad, 0, 360, 64, (Color){ 31, 42, 61, 255 });
    if (pct > 0.001f) {
        float ang = -90.0f + pct * 360.0f;
        DrawRing(c, rad - 10, rad, -90, ang, 64, err ? COLOR_DANGER : COLOR_ACCENT);
    }
    char pl[32];
    snprintf(pl, sizeof pl, "%.0f %%", pct * 100.0f);
    draw_text_c(F28, pl, c.x, c.y - 16, 26.0f, COLOR_TEXT);
    char sm[64];
    fmt_bytes(v->total ? v->total : 0, sm, sizeof sm);
    draw_text_c(F12, sm, c.x, c.y + 18, 11.0f, COLOR_MUTED);

    float sy = c.y + rad + 26;
    char b1[48], b2[48], sp[48];
    fmt_bytes(v->done, b1, sizeof b1);
    fmt_bytes(v->total, b2, sizeof b2);
    fmt_speed(v->speed, sp, sizeof sp);

    float colW = (sc.width - pad * 2) / 3.0f;
    const char *labels[3] = { "REÇU", "VITESSE", "RESTANT" };
    char vals[3][64];
    snprintf(vals[0], sizeof vals[0], "%s", b1);
    snprintf(vals[1], sizeof vals[1], "%s", sp);
    if (v->speed > 0 && v->total > v->done) {
        char d[32];
        fmt_duration((v->total - v->done) / v->speed, d, sizeof d);
        snprintf(vals[2], sizeof vals[2], "%s", d);
    } else {
        snprintf(vals[2], sizeof vals[2], "—");
    }
    for (int i = 0; i < 3; i++) {
        float cx = sc.x + pad + colW * i + colW * 0.5f;
        draw_text_c(F12, labels[i], cx, sy, 9.0f, COLOR_DIM);
        draw_text_c(F14, vals[i], cx, sy + 16, 13.0f, COLOR_TEXT);
    }

    if (err) {
        Rectangle box = { sc.x + pad, sy + 48, sc.width - pad * 2, 76 };
        rounded(box, 0.08f, Fade(COLOR_DANGER, 0.05f), Fade(COLOR_DANGER, 0.20f), 1.0f);
        draw_wrapped(F12, v->status, (Rectangle){ box.x + 12, box.y + 10, box.width - 24, 24 },
                     12.0f, COLOR_DANGER, 16.0f);
        if (v->detail[0])
            draw_wrapped(F12, v->detail, (Rectangle){ box.x + 12, box.y + 32, box.width - 24, 36 },
                         11.0f, COLOR_MUTED, 14.0f);
    } else {
        Rectangle dest = { sc.x + pad, sy + 48, sc.width - pad * 2, 40 };
        rounded(dest, 0.18f, COLOR_FIELD, COLOR_BORDER, 1.0f);
        ico_folder((Vector2){ dest.x + 17, dest.y + 20 }, 15, COLOR_MUTED);
        elide_path(F12, v->savepath[0] ? v->savepath : g_app.recv_dir.buf, 11.0f,
                   dest.width - 38, cut, sizeof cut);
        draw_text(F12, cut, dest.x + 32, dest.y + 13, 11.0f, COLOR_MUTED);
    }

    Rectangle action = { sc.x + pad, sc.y + sc.height - 58, sc.width - pad * 2, 42 };
    if (active) {
        if (ui_button(action, "Annuler la réception", BTN_DANGER, true))
            job_request_cancel(&g_app.job);
    } else {
        if (ui_button(action, "Réessayer", BTN_PRIMARY, true))
            start_receive();
    }
}

static void draw_receive_page(void)
{
    App *a = &g_app;
    bool allow = !g_block_input && !a->view.running;

    float x = SIDEBAR_W + PAGE_PAD;
    float y = HEADER_H + 18;
    float w = (float)GetScreenWidth() - x - PAGE_PAD;
    float bottom = (float)GetScreenHeight() - 24;
    float cardH = bottom - y;
    float gap = 18;
    float leftW = (w - gap) * 0.52f;
    float rightW = w - leftW - gap;

    draw_header("Recevoir un fichier", "Ouvrez un lien SILLAGE et récupérez le fichier en direct.");

    Rectangle lc = { x, y, leftW, 304 };
    card(lc);
    draw_text(F18, "Lien de partage", lc.x + 18, lc.y + 13, 16.0f, COLOR_TEXT);
    DrawCircleV((Vector2){ lc.x + lc.width - 28, lc.y + 24 }, 10, Fade(COLOR_ACCENT, 0.15f));
    draw_text_c(F12, "1", lc.x + lc.width - 28, lc.y + 18, 11.0f, COLOR_ACCENT);

    Rectangle lf = { lc.x + 18, lc.y + 46, lc.width - 36 - 92, 44 };
    Rectangle paste = { lf.x + lf.width + 8, lf.y, 84, 44 };
    tf_click(&a->recv_link, lf);
    int edited = 0;
    if (allow) {
        int r = tf_update(&a->recv_link);
        edited = r ? 1 : 0;
        if (r == 2) start_receive();
    }
    if (edited || a->recv_link.len != a->recv_last_len) {
        a->recv_last_len = a->recv_link.len;
        parse_recv_link();
    }
    tf_draw(&a->recv_link, lf, "Code de partage ou lien sillage://…", false, true, allow);
    if (ui_button(paste, "Coller", BTN_SECONDARY, allow)) {
        const char *clip = GetClipboardText();
        if (clip && *clip) {
            tf_set(&a->recv_link, clip);
            a->recv_last_len = a->recv_link.len;
            parse_recv_link();
            if (!a->recv_parsed)
                toast_show("Le presse-papiers ne contient pas un lien valide");
        } else {
            toast_show("Presse-papiers vide");
        }
    }

    if (a->recv_parsed) {
        char info[256];
        if (a->recv_inv.transport == TRANSPORT_WEBRTC) {
            char fmt[16];
            code_format(a->recv_inv.code, fmt, sizeof fmt);
            snprintf(info, sizeof info, "Partage WebRTC · %s · %.80s:%d",
                     fmt, a->recv_inv.signal_host, a->recv_inv.signal_port);
        } else {
            snprintf(info, sizeof info, "Invitation TCP valide · %.120s:%d",
                     a->recv_inv.host, a->recv_inv.port);
        }
        DrawCircleV((Vector2){ lc.x + 23, lc.y + 105 }, 3.0f, COLOR_TEAL);
        draw_text(F12, info, lc.x + 32, lc.y + 98, 11.0f, COLOR_TEAL);
    } else if (a->recv_error[0]) {
        char cut[512];
        elide_text(F12, a->recv_error, 11.0f, lc.width - 54, cut, sizeof cut);
        DrawCircleV((Vector2){ lc.x + 23, lc.y + 105 }, 3.0f, COLOR_WARN);
        draw_text(F12, cut, lc.x + 32, lc.y + 98, 11.0f, COLOR_WARN);
    } else {
        draw_text(F12, "Le lien est analysé automatiquement.", lc.x + 18, lc.y + 98, 11.0f, COLOR_DIM);
    }

    Rectangle pf = { lc.x + 18, lc.y + 122, lc.width - 36 - 44, 40 };
    Rectangle eye = { lc.x + lc.width - 18 - 38, lc.y + 123, 34, 34 };
    bool pw_enabled = allow && a->recv_parsed &&
                      (a->recv_inv.has_password || a->recv_inv.pw_unknown);
    tf_click(&a->recv_pw, pf);
    if (pw_enabled) tf_update(&a->recv_pw);
    tf_draw(&a->recv_pw, pf, a->recv_inv.pw_unknown
            ? "Mot de passe si le partage en a un" :
            (a->recv_inv.has_password ? "Mot de passe requis" : "Aucun mot de passe requis"),
            true, a->recv_reveal, pw_enabled);
    if (ui_icon_button(eye, a->recv_reveal ? ico_eye_on : ico_eye_off, BTN_GHOST, pw_enabled))
        a->recv_reveal = !a->recv_reveal;

    draw_text(F12, "Dossier de destination", lc.x + 18, lc.y + 174, 10.0f, COLOR_DIM);
    Rectangle df = { lc.x + 18, lc.y + 192, lc.width - 36 - 92, 40 };
    Rectangle browse = { df.x + df.width + 8, df.y, 84, 40 };
    tf_click(&a->recv_dir, df);
    if (allow) tf_update(&a->recv_dir);
    tf_draw(&a->recv_dir, df, "Téléchargements", false, true, allow);
    if (ui_button(browse, "Parcourir", BTN_SECONDARY, allow))
        open_file_browser(1);

    Rectangle start = { lc.x + 18, lc.y + 248, lc.width - 36, 44 };
    bool can_start = allow && a->recv_parsed &&
                     (!a->recv_inv.has_password || a->recv_pw.len > 0);
    if (ui_button(start, "Recevoir le fichier", BTN_PRIMARY, can_start))
        start_receive();

    float infoY = lc.y + lc.height + gap;
    float infoH = bottom - infoY;
    if (infoH >= 120) {
        float h1 = infoH * 0.62f;
        if (h1 > 250.0f) h1 = 250.0f;
        Rectangle ic = { x, infoY, leftW, h1 };
        rounded(ic, 0.055f, (Color){ 13, 19, 29, 255 }, COLOR_BORDER, 1.0f);
        draw_text(F14, "Transfert direct", ic.x + 18, ic.y + 13, 12.0f, COLOR_TEXT);
        const char *tips[5] = {
            "Aucun relais de données : la connexion est directe.",
            "Le fichier est déchiffré uniquement sur votre machine.",
            "Écriture dans un fichier temporaire puis renommage atomique.",
            "Le lien est à usage unique et expire automatiquement.",
            "Le mot de passe ne quitte jamais votre machine."
        };
        for (int i = 0; i < 5; i++) {
            float ry = ic.y + 45.0f + (float)i * 30.0f;
            if (ry + 12.0f > ic.y + ic.height) break;
            ico_shield((Vector2){ ic.x + 24, ry + 3 }, 13, COLOR_TEAL);
            char cut[512];
            elide_text(F12, tips[i], 11.0f, ic.width - 54, cut, sizeof cut);
            draw_text(F12, cut, ic.x + 36, ry - 3, 11.0f, COLOR_MUTED);
        }

        float h2 = infoH - h1 - gap;
        if (h2 >= 82.0f) {
            Rectangle ic2 = { x, infoY + h1 + gap, leftW, h2 };
            rounded(ic2, 0.055f, (Color){ 13, 19, 29, 255 }, COLOR_BORDER, 1.0f);
            draw_text(F14, "À garder en tête", ic2.x + 18, ic2.y + 12, 12.0f, COLOR_TEXT);
            const char *notes[3] = {
                "Un seul transfert à la fois.",
                "Taille maximale : 1 Tio.",
                "Fichier final accessible au propriétaire uniquement."
            };
            for (int i = 0; i < 3; i++) {
                float ry = ic2.y + 38.0f + (float)i * 22.0f;
                if (ry + 12.0f > ic2.y + ic2.height) break;
                DrawCircleV((Vector2){ ic2.x + 22, ry + 4 }, 2.0f, COLOR_ACCENT);
                char cut[512];
                elide_text(F12, notes[i], 11.0f, ic2.width - 50, cut, sizeof cut);
                draw_text(F12, cut, ic2.x + 32, ry - 2, 11.0f, COLOR_MUTED);
            }
        }
    }

    Rectangle sc = { x + leftW + gap, y, rightW, cardH };
    card(sc);
    if (a->view.running && a->view.is_send)
        draw_busy_panel(sc, ico_send, COLOR_ACCENT, "Un partage est en cours",
                        "Le lien est actif, en attente du destinataire.",
                        "Terminez ce partage avant de recevoir un fichier.",
                        "Voir le partage", PAGE_SEND);
    else if (a->view.running && !a->view.is_send)
        draw_recv_active(sc);
    else if (!a->view.is_send && (a->view.phase == JOB_DONE || a->view.phase == JOB_ERROR ||
                                  a->view.phase == JOB_CANCELLED))
        draw_recv_active(sc);
    else
        draw_recv_idle(sc);
}

/* ---------------- page Historique ---------------- */

static void history_add(const JobView *v)
{
    if (g_app.hist_count >= 32) {
        memmove(&g_app.hist[1], &g_app.hist[0], sizeof(HistoryItem) * 31);
        g_app.hist_count = 31;
    } else {
        memmove(&g_app.hist[1], &g_app.hist[0], sizeof(HistoryItem) * (size_t)g_app.hist_count);
        g_app.hist_count++;
    }
    HistoryItem *h = &g_app.hist[0];
    memset(h, 0, sizeof *h);
    snprintf(h->name, sizeof h->name, "%s", v->filename[0] ? v->filename : "Transfert");
    h->size = v->total;
    h->send = v->is_send;
    h->ok = v->result == 1;
    h->when = wall_now();
    snprintf(h->status, sizeof h->status, "%.127s", v->status);
    snprintf(h->remote, sizeof h->remote, "%s", v->remote);
}

static void check_job_completion(void)
{
    job_snapshot(&g_app.job, &g_app.view);
    if (g_app.view.running || g_app.view.history_logged)
        return;
    if (g_app.view.phase != JOB_DONE && g_app.view.phase != JOB_ERROR &&
        g_app.view.phase != JOB_CANCELLED)
        return;
    history_add(&g_app.view);
    job_lock(&g_app.job);
    g_app.job.history_logged = 1;
    job_unlock(&g_app.job);
    g_app.view.history_logged = 1;
    if (g_app.view.phase == JOB_DONE)
        toast_show("Transfert terminé · %s", g_app.view.filename[0] ? g_app.view.filename : "fichier");
    else if (g_app.view.phase == JOB_ERROR)
        toast_show("%s", g_app.view.status);
    else
        toast_show("Transfert annulé");
}

static void draw_history_page(void)
{
    float x = SIDEBAR_W + PAGE_PAD;
    float y = HEADER_H + 18;
    float w = (float)GetScreenWidth() - x - PAGE_PAD;
    float bottom = (float)GetScreenHeight() - 24;
    draw_header("Historique", "Les derniers transferts effectués pendant cette session.");

    Rectangle c = { x, y, w, bottom - y };
    card(c);

    if (g_app.hist_count == 0) {
        float cx = c.x + c.width * 0.5f, cy = c.y + c.height * 0.42f;
        DrawCircleV((Vector2){ cx, cy }, 46, Fade(COLOR_ACCENT, 0.07f));
        ico_activity((Vector2){ cx, cy }, 34, Fade(COLOR_ACCENT, 0.8f));
        draw_text_c(F18, "Aucun transfert pour le moment", cx, cy + 70, 16.0f, COLOR_TEXT);
        draw_text_c(F12, "Vos envois et réceptions apparaîtront ici.", cx, cy + 96, 12.0f, COLOR_MUTED);
        return;
    }

    float rowH = 66.0f;
    float top = c.y + 14;
    float viewH = c.height - 28;
    float contentH = (float)g_app.hist_count * rowH;
    float maxScroll = contentH - viewH;
    if (maxScroll < 0) maxScroll = 0;
    if (maxScroll > 0 && !g_block_input && mouse_in(c))
        g_app.hist_scroll -= GetMouseWheelMove() * 48.0f;
    if (g_app.hist_scroll < 0) g_app.hist_scroll = 0;
    if (g_app.hist_scroll > maxScroll) g_app.hist_scroll = maxScroll;

    BeginScissorMode((int)c.x + 1, (int)top, (int)c.width - 2, (int)viewH);
    for (int i = 0; i < g_app.hist_count; i++) {
        HistoryItem *h = &g_app.hist[i];
        float ry = top + i * rowH - g_app.hist_scroll;
        if (ry + rowH < top || ry > top + viewH) continue;
        Rectangle row = { c.x + 10, ry, c.width - 20, rowH - 6 };
        if (mouse_in(row) && !g_block_input)
            DrawRectangleRounded(row, 0.16f, 10, (Color){ 21, 29, 44, 255 });
        Color ic = h->send ? COLOR_ACCENT : COLOR_TEAL;
        DrawCircleV((Vector2){ row.x + 34, row.y + 30 }, 19, Fade(ic, 0.12f));
        if (h->send) ico_send((Vector2){ row.x + 34, row.y + 30 }, 17, ic);
        else ico_recv((Vector2){ row.x + 34, row.y + 30 }, 17, ic);

        char cut[512];
        elide_text(F14, h->name, 14.0f, row.width - 260, cut, sizeof cut);
        draw_text(F14, cut, row.x + 64, row.y + 13, 14.0f, COLOR_TEXT);
        char tm[32];
        format_time_short(h->when, tm, sizeof tm);
        char sub[256];
        snprintf(sub, sizeof sub, "%s · %s", h->send ? "Envoyé" : "Reçu", tm);
        draw_text(F12, sub, row.x + 64, row.y + 34, 10.5f, COLOR_MUTED);

        char b[48];
        fmt_bytes(h->size, b, sizeof b);
        draw_text_r(F14, b, row.x + row.width - 132, row.y + 14, 12.0f, COLOR_TEXT);
        Rectangle st = { row.x + row.width - 108, row.y + 17, 86, 24 };
        Color sc = h->ok ? COLOR_TEAL : COLOR_DANGER;
        DrawRectangleRounded(st, 0.5f, 12, Fade(sc, 0.10f));
        DrawRectangleRoundedLinesEx(st, 0.5f, 12, 1.0f, Fade(sc, 0.30f));
        draw_text_c(F12, h->ok ? "Réussi" : "Échec", st.x + st.width * 0.5f, st.y + 5, 10.0f, sc);
    }
    EndScissorMode();

    if (maxScroll > 0) {
        float trackH = viewH - 8;
        float thumbH = trackH * (viewH / contentH);
        if (thumbH < 30) thumbH = 30;
        float ty = top + 4 + (trackH - thumbH) * (g_app.hist_scroll / maxScroll);
        Rectangle tr = { c.x + c.width - 8, ty, 3, thumbH };
        DrawRectangleRounded(tr, 0.5f, 6, COLOR_BORDER_HI);
    }
}

/* ---------------- page À propos ---------------- */

static void about_card(Rectangle r, const char *title, void (*icon)(Vector2, float, Color),
                       Color accent, const char *body)
{
    card(r);
    DrawCircleV((Vector2){ r.x + 34, r.y + 34 }, 18, Fade(accent, 0.12f));
    icon((Vector2){ r.x + 34, r.y + 34 }, 18, accent);
    draw_text(F18, title, r.x + 62, r.y + 22, 15.0f, COLOR_TEXT);
    draw_wrapped(F12, body, (Rectangle){ r.x + 20, r.y + 62, r.width - 40, r.height - 76 },
                 11.5f, COLOR_MUTED, 17.0f);
}

static void about_spec(Rectangle r, int col, int row, const char *k, const char *v)
{
    float cw = (r.width - 40.0f) * 0.5f;
    float x = r.x + 20.0f + (float)col * (cw + 8.0f);
    float y = r.y + 42.0f + (float)row * 23.0f;
    draw_text(F12, k, x, y, 10.5f, COLOR_DIM);
    draw_text(F12, v, x + 96.0f, y, 11.0f, COLOR_TEXT);
}

static void draw_about_page(void)
{
    float x = SIDEBAR_W + PAGE_PAD;
    float y = HEADER_H + 18;
    float w = (float)GetScreenWidth() - x - PAGE_PAD;
    float bottom = (float)GetScreenHeight() - 24;
    draw_header("À propos", "SILLAGE Transfer · chiffrement post-quantique expérimental.");

    Rectangle hero = { x, y, w, 120 };
    rounded(hero, 0.06f, (Color){ 15, 21, 33, 255 }, COLOR_BORDER, 1.0f);
    Rectangle lg = { hero.x + 26, hero.y + 27, 64, 64 };
    DrawRectangleRounded(lg, 0.28f, 12, COLOR_ACCENT);
    DrawCircleV((Vector2){ lg.x + 20, lg.y + 28 }, 16, Fade(COLOR_ACCENT2, 0.5f));
    ico_arrow((Vector2){ lg.x + 34, lg.y + 30 }, 0, 0, COLOR_WHITE);
    ico_arrow((Vector2){ lg.x + 34, lg.y + 41 }, 0, 1, COLOR_WHITE);
    draw_text(F28, "SILLAGE Transfer", hero.x + 110, hero.y + 26, 26.0f, COLOR_TEXT);
    draw_text(F12, "Partage direct WebRTC, chiffré de bout en bout, sans compte ni relais de données.",
              hero.x + 112, hero.y + 62, 12.0f, COLOR_MUTED);
    draw_text(F12, "v" APP_VERSION " · raylib · SILLAGE BRUME-512", hero.x + 112, hero.y + 84, 11.0f, COLOR_DIM);
    ico_shield((Vector2){ hero.x + hero.width - 54, hero.y + 60 }, 32, COLOR_TEAL);

    float gy = hero.y + hero.height + 16;
    float gh = 174;
    float cw = (w - 18) * 0.5f;
    Rectangle c1 = { x, gy, cw, gh };
    Rectangle c2 = { x + cw + 18, gy, cw, gh };
    Rectangle c3 = { x, gy + gh + 16, cw, gh };
    Rectangle c4 = { x + cw + 18, gy + gh + 16, cw, gh };

    about_card(c1, "Cryptographie", ico_lock, COLOR_ACCENT,
        "BRUME-512 AEAD : clé de 512 bits, nonce de 192 bits, tag de 128 bits. "
        "Chaque trame possède son propre nonce et ses données authentifiées (AAD). "
        "Le mot de passe est dérivé localement (scrypt) et ne transite jamais.");

    about_card(c2, "Protocole", ico_link, COLOR_TEAL,
        "WebRTC/DataChannel (ICE + STUN) ou TCP direct. PeerJS Cloud échange "
        "les descriptions de session SDP, authentifiées par HMAC-SHA256 ; "
        "un défi-réponse vérifie ensuite le jeton. Un seul transfert réussi "
        "par invitation ; métadonnées et contenu sont chiffrés séparément.");

    about_card(c3, "Vie privée", ico_shield, COLOR_ACCENT2,
        "Aucun compte, aucune télémétrie, aucun stockage. PeerJS Cloud ne voit "
        "qu'un identifiant de salle opaque et des SDP signés : jamais le "
        "fichier, le code ni les clés. Sans TURN, les données restent "
        "strictement directes entre les deux machines.");

    about_card(c4, "Avertissement", ico_info, COLOR_WARN,
        "SILLAGE est une suite cryptographique de recherche, non auditée. "
        "Cet outil est expérimental : n'utilisez pas SILLAGE Transfer pour des "
        "secrets critiques sans évaluation indépendante.");

    float ty = gy + gh * 2.0f + 16.0f;
    float th = bottom - ty - 26.0f;
    if (th >= 120.0f) {
        Rectangle tech = { x, ty, w, th };
        rounded(tech, 0.055f, COLOR_PANEL, COLOR_BORDER, 1.0f);
        draw_text(F18, "Détails techniques", tech.x + 20, tech.y + 13, 14.0f, COLOR_TEXT);
        about_spec(tech, 0, 0, "Chiffrement", "BRUME-512 (AEAD)");
        about_spec(tech, 1, 0, "Clé · nonce · tag", "512 · 192 · 128 bits");
        about_spec(tech, 0, 1, "Transport", "WebRTC DataChannel · TCP direct");
        about_spec(tech, 1, 1, "Signalisation", "PeerJS Cloud · SDP signé HMAC");
        about_spec(tech, 0, 2, "Dérivation", "scrypt N=2^15, r=8, p=1");
        about_spec(tech, 1, 2, "Trames", "1 Mio · nonce par trame");
        about_spec(tech, 0, 3, "Invitation", "code 50 bits · usage unique");
        about_spec(tech, 1, 3, "Réception", "fichier 0600 · renommage atomique");
    }

    draw_text_c(F12, "QR Code generator © Project Nayuki (MIT) · raylib (zlib) · SILLAGE v0.4.0",
                x + w * 0.5f, bottom - 16, 10.0f, COLOR_DIM);
}

/* ===================================================================== */
/*  Navigateur de fichiers                                               */
/* ===================================================================== */

static int dir_entry_cmp(const void *pa, const void *pb)
{
    const DirEntry *a = (const DirEntry *)pa;
    const DirEntry *b = (const DirEntry *)pb;
    if (a->is_dir != b->is_dir)
        return a->is_dir ? -1 : 1;
    return strcasecmp(a->name, b->name);
}

static void browser_load(void)
{
    App *a = &g_app;
    a->browser_count = 0;
    a->browser_scroll = 0;
    DIR *d = opendir(a->browser_dir);
    if (!d) {
        snprintf(a->browser_note, sizeof a->browser_note, "Dossier inaccessible");
        return;
    }
    struct dirent *e;
    while ((e = readdir(d)) != NULL && a->browser_count < 512) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        if (e->d_name[0] == '.')
            continue;
        DirEntry *de = &a->browser_entries[a->browser_count];
        snprintf(de->name, sizeof de->name, "%s", e->d_name);
        de->is_dir = 0;
        de->size = 0;
        char full[PATH_MAX];
        join_path(full, sizeof full, a->browser_dir, e->d_name);
        struct stat st;
        if (stat(full, &st) == 0) {
            de->is_dir = S_ISDIR(st.st_mode);
            de->size = (uint64_t)st.st_size;
        }
        a->browser_count++;
    }
    closedir(d);
    qsort(a->browser_entries, (size_t)a->browser_count, sizeof(DirEntry), dir_entry_cmp);
    snprintf(a->browser_note, sizeof a->browser_note, "%d élément%s",
             a->browser_count, a->browser_count > 1 ? "s" : "");
}

static void open_file_browser(int dir_mode)
{
    App *a = &g_app;
    a->browser_open = 1;
    a->browser_dir_mode = dir_mode;
    a->browser_scroll = 0;
    const char *start = home_dir();
    if (dir_mode) {
        if (a->recv_dir.buf[0]) start = a->recv_dir.buf;
        else {
            char d[PATH_MAX];
            default_download_dir(d, sizeof d);
            snprintf(a->browser_dir, sizeof a->browser_dir, "%s", d);
            browser_load();
            return;
        }
    } else if (a->send_path[0]) {
        copy_path(a->browser_dir, sizeof a->browser_dir, a->send_path);
        char *s = strrchr(a->browser_dir, '/');
        if (s && s != a->browser_dir) *s = '\0';
        else snprintf(a->browser_dir, sizeof a->browser_dir, "%s", home_dir());
        browser_load();
        return;
    }
    copy_path(a->browser_dir, sizeof a->browser_dir, start);
    browser_load();
}

static void browser_go_up(void)
{
    App *a = &g_app;
    char *s = strrchr(a->browser_dir, '/');
    if (!s) return;
    if (s == a->browser_dir) {
        a->browser_dir[1] = '\0';
    } else {
        *s = '\0';
    }
    browser_load();
}

static void browser_enter(const char *name)
{
    App *a = &g_app;
    char next[PATH_MAX];
    join_path(next, sizeof next, a->browser_dir, name);
    copy_path(a->browser_dir, sizeof a->browser_dir, next);
    browser_load();
}

static void draw_browser(void)
{
    if (!g_app.browser_open)
        return;
    g_block_input = false;
    int sw = GetScreenWidth(), sh = GetScreenHeight();
    DrawRectangle(0, 0, sw, sh, Fade((Color){ 0, 0, 0, 255 }, 0.66f));

    float cw = 800.0f, ch = 620.0f;
    if (cw > (float)sw - 60.0f) cw = (float)sw - 60.0f;
    if (ch > (float)sh - 60.0f) ch = (float)sh - 60.0f;
    Rectangle c = { ((float)sw - cw) * 0.5f, ((float)sh - ch) * 0.5f, cw, ch };
    rounded(c, 0.05f, COLOR_PANEL, COLOR_BORDER, 1.0f);

    draw_text(F18, g_app.browser_dir_mode ? "Choisir un dossier" : "Choisir un fichier",
              c.x + 24, c.y + 20, 18.0f, COLOR_TEXT);
    draw_text(F12, g_app.browser_note, c.x + 24, c.y + 45, 10.5f, COLOR_DIM);
    Rectangle close = { c.x + c.width - 54, c.y + 16, 34, 34 };
    if (ui_icon_button(close, ico_x, BTN_GHOST, true))
        g_app.browser_open = 0;

    Rectangle up = { c.x + 24, c.y + 66, 38, 38 };
    Rectangle hm = { up.x + 44, up.y, 38, 38 };
    Rectangle path = { hm.x + 48, up.y, c.width - 48 - 24 - 44 - 38 - 48, 38 };
    if (ui_icon_button(up, ico_up, BTN_SECONDARY, true))
        browser_go_up();
    if (ui_icon_button(hm, ico_home, BTN_SECONDARY, true)) {
        copy_path(g_app.browser_dir, sizeof g_app.browser_dir, home_dir());
        browser_load();
    }
    rounded(path, 0.18f, COLOR_FIELD, COLOR_BORDER, 1.0f);
    char cut[2048];
    elide_path(F12, g_app.browser_dir, 12.0f, path.width - 24, cut, sizeof cut);
    draw_text(F12, cut, path.x + 12, path.y + 12, 12.0f, COLOR_MUTED);

    Rectangle list = { c.x + 18, c.y + 118, c.width - 36, c.height - 190 };
    rounded(list, 0.035f, (Color){ 12, 17, 26, 255 }, COLOR_BORDER, 1.0f);
    float rowH = 42.0f;
    float contentH = (float)g_app.browser_count * rowH;
    float viewH = list.height - 8;
    float maxScroll = contentH - viewH;
    if (maxScroll < 0) maxScroll = 0;
    if (maxScroll > 0 && !g_block_input && mouse_in(list))
        g_app.browser_scroll -= GetMouseWheelMove() * 52.0f;
    if (g_app.browser_scroll < 0) g_app.browser_scroll = 0;
    if (g_app.browser_scroll > maxScroll) g_app.browser_scroll = maxScroll;

    BeginScissorMode((int)list.x + 1, (int)list.y + 2, (int)list.width - 2, (int)list.height - 4);
    for (int i = 0; i < g_app.browser_count; i++) {
        DirEntry *de = &g_app.browser_entries[i];
        float ry = list.y + 4 + (float)i * rowH - g_app.browser_scroll;
        if (ry + rowH < list.y || ry > list.y + list.height) continue;
        Rectangle row = { list.x + 4, ry, list.width - 8, rowH - 2 };
        bool hover = !g_block_input && mouse_in(row) && mouse_in(list);
        if (hover)
            DrawRectangleRounded(row, 0.20f, 8, (Color){ 23, 32, 48, 255 });
        Vector2 ic = { row.x + 22, row.y + 20 };
        if (de->is_dir)
            ico_folder(ic, 18, COLOR_WARN);
        else
            ico_file(ic, 18, COLOR_ACCENT);
        char nm[512];
        elide_text(F14, de->name, 13.0f, row.width - 160, nm, sizeof nm);
        draw_text(F14, nm, row.x + 42, row.y + 11, 13.0f, de->is_dir ? COLOR_TEXT : COLOR_MUTED);
        if (de->is_dir) {
            draw_text_r(F12, "Dossier", row.x + row.width - 40, row.y + 13, 10.0f, COLOR_DIM);
            ico_chevron((Vector2){ row.x + row.width - 18, row.y + 20 }, 14, COLOR_DIM);
        } else {
            char b[48];
            fmt_bytes(de->size, b, sizeof b);
            draw_text_r(F12, b, row.x + row.width - 20, row.y + 13, 10.0f, COLOR_DIM);
        }
        if (hover) want_cursor(MOUSE_CURSOR_POINTING_HAND);
        if (hover && IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
            if (de->is_dir) {
                browser_enter(de->name);
            } else if (!g_app.browser_dir_mode) {
                char full[PATH_MAX];
                join_path(full, sizeof full, g_app.browser_dir, de->name);
                select_send_file(full);
                g_app.browser_open = 0;
            }
        }
    }
    EndScissorMode();

    if (g_app.browser_count == 0) {
        draw_text_c(F14, "Dossier vide", list.x + list.width * 0.5f,
                    list.y + list.height * 0.5f, 13.0f, COLOR_DIM);
    }

    if (maxScroll > 0) {
        float trackH = list.height - 8;
        float thumbH = trackH * (viewH / contentH);
        if (thumbH < 30) thumbH = 30;
        float ty = list.y + 4 + (trackH - thumbH) * (g_app.browser_scroll / maxScroll);
        DrawRectangleRounded((Rectangle){ list.x + list.width - 7, ty, 3, thumbH }, 0.5f, 6,
                             COLOR_BORDER_HI);
    }

    Rectangle cancel = { c.x + c.width - 24 - 100, c.y + c.height - 54, 100, 40 };
    if (ui_button(cancel, "Annuler", BTN_SECONDARY, true))
        g_app.browser_open = 0;
    if (g_app.browser_dir_mode) {
        Rectangle choose = { cancel.x - 166, cancel.y, 156, 40 };
        if (ui_button(choose, "Choisir ce dossier", BTN_PRIMARY, true)) {
            tf_set(&g_app.recv_dir, g_app.browser_dir);
            g_app.browser_open = 0;
        }
    }
    if (IsKeyPressed(KEY_ESCAPE))
        g_app.browser_open = 0;
    if (IsKeyPressed(KEY_ENTER) && g_app.browser_dir_mode) {
        tf_set(&g_app.recv_dir, g_app.browser_dir);
        g_app.browser_open = 0;
    }

    /* bloque les interactions de la page sous-jacente */
    g_block_input = true;
}

/* ===================================================================== */
/*  Boucle principale                                                    */
/* ===================================================================== */

static void init_app(void)
{
    memset(&g_app, 0, sizeof g_app);
    job_init(&g_app.job);
    g_app.page = PAGE_SEND;
    g_app.expiry_idx = 1;
    load_fonts();

    char ip[128];
    local_ipv4(ip, sizeof ip);
    tf_set(&g_app.send_host, ip);
    tf_set(&g_app.send_port, "45871");

    g_app.transport = TRANSPORT_WEBRTC;
    tf_set(&g_app.send_signal, signal_default());
    tf_set(&g_app.send_stun, stun_default());

    char dl[PATH_MAX];
    default_download_dir(dl, sizeof dl);
    tf_set(&g_app.recv_dir, dl);

    job_snapshot(&g_app.job, &g_app.view);
}

static void handle_file_drop(void)
{
    if (!IsFileDropped())
        return;
    FilePathList files = LoadDroppedFiles();
    if (files.count > 0 && !g_app.browser_open && !g_app.view.running) {
        for (unsigned int i = 0; i < files.count; i++) {
            struct stat st;
            if (stat(files.paths[i], &st) == 0 && S_ISREG(st.st_mode)) {
                select_send_file(files.paths[i]);
                g_app.page = PAGE_SEND;
                break;
            }
        }
    } else if (files.count > 0) {
        toast_show("Annulez le transfert en cours avant d'ajouter un fichier");
    }
    UnloadDroppedFiles(files);
}

static void draw_frame(void)
{
    g_cursor_want = MOUSE_CURSOR_DEFAULT;
    check_job_completion();

    g_block_input = g_app.browser_open || g_app.qr_zoom;

    draw_background();
    draw_sidebar();

    switch (g_app.page) {
    case PAGE_SEND: draw_send_page(); break;
    case PAGE_RECV: draw_receive_page(); break;
    case PAGE_HISTORY: draw_history_page(); break;
    case PAGE_ABOUT: draw_about_page(); break;
    }

    if (g_app.qr_zoom) {
        g_block_input = false;
        qr_zoom_overlay();
        g_block_input = true;
    }

    draw_toast();

    if (g_app.browser_open)
        draw_browser();

    g_block_input = false;

    if (g_cursor_want != g_cursor_applied) {
        SetMouseCursor(g_cursor_want);
        g_cursor_applied = g_cursor_want;
    }
}

int main(int argc, char **argv)
{
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--selftest") == 0)
            return run_selftest();
        if (strcmp(argv[i], "--selftest-peerjs") == 0)
            return run_selftest_peerjs();
        if (strcmp(argv[i], "--signal-server") == 0) {
            int port = LEGACY_SIGNAL_PORT;
            if (i + 1 < argc)
                port = atoi(argv[i + 1]);
            signal(SIGPIPE, SIG_IGN);
            return run_signal_server(port);
        }
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("%s %s\n\n", APP_NAME, APP_VERSION);
            printf("Usage : %s [--selftest] [--selftest-peerjs] "
                   "[--signal-server [port]] [--help]\n\n", argv[0]);
            printf("  --selftest              vérifie la crypto, le QR et les transferts\n");
            printf("  --selftest-peerjs       test réseau réel via PeerJS Cloud\n");
            printf("  --signal-server [port]  ancien relais local (déprécié, défaut : %d)\n",
                   LEGACY_SIGNAL_PORT);
            printf("  --help                  affiche cette aide\n\n");
            printf("Variables : SILLAGE_PEERJS (hôte:port, défaut 0.peerjs.com:443),\n");
            printf("            SILLAGE_PEERJS_KEY (clé PeerServer), SILLAGE_STUN.\n");
            printf("Interface : raylib + SILLAGE BRUME-512 + libdatachannel.\n");
            return 0;
        }
    }

    signal(SIGPIPE, SIG_IGN);
    sl_init();

    SetTraceLogLevel(LOG_WARNING);

    /* Rythme d'affichage.
     *
     * Sous Wayland/XWayland, le compositeur assure déjà la synchronisation :
     * cumuler FLAG_VSYNC_HINT avec un plafond de 120 i/s sur un écran à
     * 170 Hz fait présenter des frames dans le désordre (image dédoublée,
     * clignotement au survol, fréquent avec NVIDIA + XWayland). On laisse
     * donc le compositeur piloter et on plafonne à 60 i/s, largement
     * suffisant pour une interface.
     *
     * Sous X11 sans compositeur, on garde le VSync pour éviter le tearing. */
    const char *session = getenv("XDG_SESSION_TYPE");
    int composited = session && strcmp(session, "wayland") == 0;

    unsigned int flags = FLAG_WINDOW_RESIZABLE;
    if (!getenv("SILLAGE_NO_MSAA"))   /* échappatoire si artefacts GPU */
        flags |= FLAG_MSAA_4X_HINT;
    if (!composited)
        flags |= FLAG_VSYNC_HINT;
    SetConfigFlags(flags);
    InitWindow(1280, 820, APP_NAME);
    SetWindowMinSize(1080, 700);
    SetExitKey(KEY_NULL);
    /* 240 i/s en secours : si le VSync X11 est indisponible, cela évite une
     * boucle non bornée à plusieurs milliers d'images par seconde. */
    SetTargetFPS(composited ? 60 : 240);

    init_app();

    while (!WindowShouldClose()) {
        handle_file_drop();
        BeginDrawing();
        draw_frame();
        EndDrawing();
    }

    job_request_cancel(&g_app.job);
    for (int i = 0; i < 100; i++) {
        job_snapshot(&g_app.job, &g_app.view);
        if (!g_app.view.running)
            break;
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 10000000 };
        nanosleep(&ts, NULL);
    }

    qr_destroy();
    unload_fonts();
    secure_zero(&g_app.send_pw, sizeof g_app.send_pw);
    secure_zero(&g_app.recv_pw, sizeof g_app.recv_pw);
    CloseWindow();
    return 0;
}

