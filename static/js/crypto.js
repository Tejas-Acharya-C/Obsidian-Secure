// ============================================================
// OBSIDIAN SECURE — CLIENT-SIDE E2E ENCRYPTION MODULE
// Web Crypto API | AES-256-GCM | Zero-Knowledge Server
// ============================================================

// ===== KEY GENERATION & EXPORT =====

async function generateKey() {
  return await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,  // extractable for export to URL
    ['encrypt', 'decrypt']
  );
}

async function exportKey(cryptoKey) {
  const exported = await crypto.subtle.exportKey('raw', cryptoKey);
  return arrayBufferToBase64(exported);
}

async function importKey(keyBase64) {
  const keyBuffer = base64ToArrayBuffer(keyBase64);
  return await crypto.subtle.importKey(
    'raw',
    keyBuffer,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

// ===== IV GENERATION =====

function generateIV() {
  return crypto.getRandomValues(new Uint8Array(12));
}

// ===== FILE ENCRYPTION/DECRYPTION =====

async function encryptFile(file, key) {
  // Generate random IV
  const iv = generateIV();
  
  // Convert file to ArrayBuffer
  const fileBuffer = await file.arrayBuffer();
  
  // Encrypt: AES-256-GCM produces ciphertext + auth tag
  const encryptedData = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    fileBuffer
  );
  
  // Prepend IV to ciphertext: [12-byte IV][ciphertext+authTag]
  const combined = new Uint8Array(iv.length + encryptedData.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(encryptedData), iv.length);
  
  // Return as Blob for form submission
  return new Blob([combined], { type: 'application/octet-stream' });
}

async function decryptFile(encryptedBlob, key) {
  // Read encrypted blob to ArrayBuffer
  const buffer = await encryptedBlob.arrayBuffer();
  
  // Extract IV (first 12 bytes)
  const iv = new Uint8Array(buffer, 0, 12);
  
  // Extract ciphertext+authTag (remaining bytes)
  const ciphertext = new Uint8Array(new Uint8Array(buffer, 12));
  
  // Decrypt
  const decryptedData = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    ciphertext
  );
  
  return new Blob([decryptedData]);
}

// ===== TEXT ENCRYPTION/DECRYPTION =====

async function encryptText(plaintext, key) {
  // Generate random IV
  const iv = generateIV();
  
  // Encode text to UTF-8
  const encoder = new TextEncoder();
  const plaintextBuffer = encoder.encode(plaintext);
  
  // Encrypt
  const encryptedData = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    plaintextBuffer
  );
  
  // Prepend IV to ciphertext
  const combined = new Uint8Array(iv.length + encryptedData.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(encryptedData), iv.length);
  
  // Return as base64 string
  return arrayBufferToBase64(combined);
}

async function decryptText(ciphertextBase64, key) {
  // Decode base64
  const buffer = base64ToArrayBuffer(ciphertextBase64);
  
  // Extract IV (first 12 bytes)
  const iv = new Uint8Array(buffer, 0, 12);
  
  // Extract ciphertext+authTag (remaining bytes)
  const ciphertext = new Uint8Array(new Uint8Array(buffer, 12));
  
  // Decrypt
  const decryptedData = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    ciphertext
  );
  
  // Decode UTF-8
  const decoder = new TextDecoder();
  return decoder.decode(decryptedData);
}

// ===== URL FRAGMENT HELPERS =====

function getKeyFromFragment() {
  // Extract key from #key=BASE64KEY
  const fragment = window.location.hash.substring(1);
  const params = new URLSearchParams(fragment);
  return params.get('key');
}

function setKeyFragment(keyBase64) {
  // Update URL with key in fragment (not visible to server)
  window.location.hash = `key=${keyBase64}`;
}

// ===== ENCODING HELPERS =====

function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToArrayBuffer(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// ============================================================
// OBSv2 — STREAMING CHUNK-BASED ENCRYPTION MODULE
// Constant-memory AES-256-GCM | Per-chunk authenticated framing
// ============================================================

// ===== OBSv2 CONSTANTS =====

var OBSV2_CHUNK_SIZE = 1048576; // 1 MB (1,048,576 bytes)
var OBSV2_HEADER_SIZE = 24;
var OBSV2_VERSION = 0x01;

// ===== OBSv2 HELPER FUNCTIONS =====

function buildNonce(prefix, counter) {
  // Nonce (12 bytes) = [8-byte random stream prefix] || [4-byte big-endian chunk counter]
  // Security: prefix is unique per file, counter is unique per chunk.
  // Combined nonce is guaranteed unique for every chunk under the same key.
  var nonce = new Uint8Array(12);
  nonce.set(prefix, 0);
  nonce[8]  = (counter >>> 24) & 0xFF;
  nonce[9]  = (counter >>> 16) & 0xFF;
  nonce[10] = (counter >>> 8)  & 0xFF;
  nonce[11] =  counter         & 0xFF;
  return nonce;
}

function buildAAD(chunkIndex, isFinal) {
  // AAD (5 bytes) = [4-byte chunk index big-endian] || [1-byte flags]
  // Flags: bit 0 = isFinal (prevents truncation attacks)
  // Binding chunk index to ciphertext prevents reordering and duplication.
  var aad = new Uint8Array(5);
  aad[0] = (chunkIndex >>> 24) & 0xFF;
  aad[1] = (chunkIndex >>> 16) & 0xFF;
  aad[2] = (chunkIndex >>> 8)  & 0xFF;
  aad[3] =  chunkIndex         & 0xFF;
  aad[4] = isFinal ? 0x01 : 0x00;
  return aad;
}

function writeOBSv2Header(chunkSize, noncePrefix, totalChunks) {
  // Header layout (24 bytes):
  //   [0-3]   Magic "OBS2"            (4 bytes)
  //   [4]     Version                 (1 byte)
  //   [5-8]   Chunk size uint32 BE    (4 bytes)
  //   [9-16]  Nonce prefix            (8 bytes)
  //   [17-20] Total chunks uint32 BE  (4 bytes)
  //   [21-23] Reserved (zeros)        (3 bytes)
  var h = new Uint8Array(OBSV2_HEADER_SIZE);
  h[0] = 0x4F; h[1] = 0x42; h[2] = 0x53; h[3] = 0x32; // "OBS2"
  h[4] = OBSV2_VERSION;
  h[5]  = (chunkSize >>> 24) & 0xFF;
  h[6]  = (chunkSize >>> 16) & 0xFF;
  h[7]  = (chunkSize >>> 8)  & 0xFF;
  h[8]  =  chunkSize         & 0xFF;
  h.set(noncePrefix, 9);
  h[17] = (totalChunks >>> 24) & 0xFF;
  h[18] = (totalChunks >>> 16) & 0xFF;
  h[19] = (totalChunks >>> 8)  & 0xFF;
  h[20] =  totalChunks         & 0xFF;
  return h;
}

function parseOBSv2Header(data) {
  // data: Uint8Array containing at least 24 bytes
  if (data.length < OBSV2_HEADER_SIZE) {
    throw new Error('Invalid OBSv2 header: too short');
  }
  if (data[0] !== 0x4F || data[1] !== 0x42 || data[2] !== 0x53 || data[3] !== 0x32) {
    throw new Error('Invalid OBSv2 header: bad magic bytes');
  }
  var version = data[4];
  if (version !== OBSV2_VERSION) {
    throw new Error('Unsupported OBSv2 version: ' + version);
  }
  // Parse multi-byte fields using manual byte extraction (avoids DataView alignment issues)
  var chunkSize = ((data[5] << 24) | (data[6] << 16) | (data[7] << 8) | data[8]) >>> 0;
  var noncePrefix = data.slice(9, 17);
  var totalChunks = ((data[17] << 24) | (data[18] << 16) | (data[19] << 8) | data[20]) >>> 0;
  return {
    version: version,
    chunkSize: chunkSize,
    noncePrefix: noncePrefix,
    totalChunks: totalChunks
  };
}

// ===== OBSv2 STREAMING FILE ENCRYPTION =====

async function encryptFileStreaming(file, key, onProgress) {
  var totalBytes = file.size;
  var totalChunks = Math.max(1, Math.ceil(totalBytes / OBSV2_CHUNK_SIZE));

  // Generate 8-byte random nonce prefix (unique per encryption session)
  var noncePrefix = crypto.getRandomValues(new Uint8Array(8));

  // Build OBSv2 header
  var header = writeOBSv2Header(OBSV2_CHUNK_SIZE, noncePrefix, totalChunks);

  // Accumulate encrypted frames for Blob assembly
  // Memory profile: only 1 plaintext chunk (~1MB) in RAM at any time during encryption.
  // Encrypted chunks accumulate in parts[] for final Blob (~1x file size).
  var parts = [header];

  for (var i = 0; i < totalChunks; i++) {
    var start = i * OBSV2_CHUNK_SIZE;
    var end = Math.min(start + OBSV2_CHUNK_SIZE, totalBytes);
    var isFinal = (i === totalChunks - 1);

    // Read only this chunk into memory via File.slice() — constant ~1MB
    var chunkBlob = file.slice(start, end);
    var chunkData = await chunkBlob.arrayBuffer();

    // Derive per-chunk nonce: [prefix(8)] || [counter(4)]
    var nonce = buildNonce(noncePrefix, i);
    // Derive per-chunk AAD: [index(4)] || [flags(1)]
    var aad = buildAAD(i, isFinal);

    // Encrypt chunk: AES-256-GCM (produces ciphertext + 16-byte auth tag)
    var encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: aad },
      key,
      chunkData
    );

    // Frame: [4-byte chunk length big-endian][ciphertext + GCM auth tag]
    var encBytes = new Uint8Array(encrypted);
    var frame = new Uint8Array(4 + encBytes.length);
    frame[0] = (encBytes.length >>> 24) & 0xFF;
    frame[1] = (encBytes.length >>> 16) & 0xFF;
    frame[2] = (encBytes.length >>> 8)  & 0xFF;
    frame[3] =  encBytes.length         & 0xFF;
    frame.set(encBytes, 4);

    parts.push(frame);

    if (onProgress) {
      onProgress({
        bytesProcessed: end,
        totalBytes: totalBytes,
        chunksCompleted: i + 1,
        totalChunks: totalChunks
      });
    }
  }

  return new Blob(parts, { type: 'application/octet-stream' });
}

// ===== OBSv2 CHUNKED FILE DECRYPTION =====

async function decryptFileChunked(buffer, key) {
  var data = new Uint8Array(buffer);
  var header = parseOBSv2Header(data);

  var offset = OBSV2_HEADER_SIZE;
  var decryptedParts = [];
  var chunkIndex = 0;

  while (offset < data.length) {
    // Read chunk length (4 bytes big-endian)
    if (offset + 4 > data.length) {
      throw new Error('Truncated chunk header at byte offset ' + offset);
    }
    var chunkLen = ((data[offset] << 24) | (data[offset+1] << 16) |
                    (data[offset+2] << 8) | data[offset+3]) >>> 0;
    offset += 4;

    if (chunkLen === 0 || offset + chunkLen > data.length) {
      throw new Error('Invalid or truncated chunk at index ' + chunkIndex);
    }

    // Extract ciphertext view (no copy — shares underlying buffer)
    var ciphertext = new Uint8Array(data.subarray(offset, offset + chunkLen));
    offset += chunkLen;

    // Determine if this is the final chunk (all data consumed)
    var isFinal = (offset >= data.length);

    // Derive nonce and AAD (must exactly match encryption)
    var nonce = buildNonce(header.noncePrefix, chunkIndex);
    var aad = buildAAD(chunkIndex, isFinal);

    // Decrypt and verify integrity
    // AES-GCM validates the 16-byte auth tag AND the AAD binding.
    // If chunk order, index, or final-flag has been tampered with, this throws.
    var plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: aad },
      key,
      ciphertext
    );

    decryptedParts.push(new Uint8Array(plaintext));
    chunkIndex++;
  }

  // Validate chunk count against header hint
  if (header.totalChunks > 0 && chunkIndex !== header.totalChunks) {
    throw new Error('Chunk count mismatch: expected ' + header.totalChunks + ', got ' + chunkIndex);
  }

  return new Blob(decryptedParts);
}

// ===== AUTO-DETECTING DECRYPTOR (v1 legacy / v2 streaming) =====

async function decryptFileAuto(encryptedBlob, key) {
  var buffer = await encryptedBlob.arrayBuffer();

  // Detect OBSv2 format via magic bytes "OBS2" (0x4F 0x42 0x53 0x32)
  if (buffer.byteLength >= OBSV2_HEADER_SIZE) {
    var magic = new Uint8Array(buffer, 0, 4);
    if (magic[0] === 0x4F && magic[1] === 0x42 &&
        magic[2] === 0x53 && magic[3] === 0x32) {
      return decryptFileChunked(buffer, key);
    }
  }

  // Legacy v1 format: [12-byte IV][ciphertext + GCM auth tag]
  var iv = new Uint8Array(buffer, 0, 12);
  var ciphertext = new Uint8Array(new Uint8Array(buffer, 12));
  var decryptedData = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    ciphertext
  );
  return new Blob([decryptedData]);
}

// ===== OBSv2 PHASE 2: TRUE STREAMING INTERFACES (5GB SUPPORT) =====

function encryptFileToStream(file, key, onProgress) {
  var totalBytes = file.size;
  var totalChunks = Math.max(1, Math.ceil(totalBytes / OBSV2_CHUNK_SIZE));
  var noncePrefix = crypto.getRandomValues(new Uint8Array(8));
  var header = writeOBSv2Header(OBSV2_CHUNK_SIZE, noncePrefix, totalChunks);

  var chunkIndex = 0;

  return new ReadableStream({
    start(controller) {
      controller.enqueue(header);
    },
    async pull(controller) {
      if (chunkIndex >= totalChunks) {
        controller.close();
        return;
      }

      var start = chunkIndex * OBSV2_CHUNK_SIZE;
      var end = Math.min(start + OBSV2_CHUNK_SIZE, totalBytes);
      var isFinal = (chunkIndex === totalChunks - 1);

      var chunkBlob = file.slice(start, end);
      var chunkData = await chunkBlob.arrayBuffer();

      var nonce = buildNonce(noncePrefix, chunkIndex);
      var aad = buildAAD(chunkIndex, isFinal);

      var encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce, additionalData: aad },
        key,
        chunkData
      );

      var encBytes = new Uint8Array(encrypted);
      var frame = new Uint8Array(4 + encBytes.length);
      frame[0] = (encBytes.length >>> 24) & 0xFF;
      frame[1] = (encBytes.length >>> 16) & 0xFF;
      frame[2] = (encBytes.length >>> 8)  & 0xFF;
      frame[3] =  encBytes.length         & 0xFF;
      frame.set(encBytes, 4);

      controller.enqueue(frame);

      if (onProgress) {
        onProgress({
          bytesProcessed: end,
          totalBytes: totalBytes,
          chunksCompleted: chunkIndex + 1,
          totalChunks: totalChunks
        });
      }

      chunkIndex++;
    }
  });
}

async function decryptStreamToStream(readableStream, writableStream, key, onProgress) {
  const reader = readableStream.getReader();
  const writer = writableStream.getWriter();

  let buffer = new Uint8Array(0);
  let headerParsed = false;
  let headerInfo = null;
  let chunkIndex = 0;
  let bytesDecrypted = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      
      if (value) {
        let newBuffer = new Uint8Array(buffer.length + value.length);
        newBuffer.set(buffer, 0);
        newBuffer.set(value, buffer.length);
        buffer = newBuffer;
      }

      if (!headerParsed) {
        if (buffer.length >= OBSV2_HEADER_SIZE) {
          headerInfo = parseOBSv2Header(buffer);
          buffer = buffer.subarray(OBSV2_HEADER_SIZE);
          headerParsed = true;
        } else if (done) {
          throw new Error('Truncated stream: missing header');
        }
      }

      if (headerParsed) {
        // Read as many full chunks as are available in the buffer
        while (buffer.length >= 4) {
          const chunkLen = ((buffer[0] << 24) | (buffer[1] << 16) | (buffer[2] << 8) | buffer[3]) >>> 0;
          
          if (buffer.length >= 4 + chunkLen) {
            const ciphertext = new Uint8Array(buffer.subarray(4, 4 + chunkLen));
            
            // If totalChunks is known from header, use it to determine isFinal
            // If not, we have to rely on stream end. 
            // In OBSv2, totalChunks is provided.
            const isFinal = (headerInfo.totalChunks > 0 && chunkIndex === headerInfo.totalChunks - 1) || 
                            (done && buffer.length === 4 + chunkLen);

            const nonce = buildNonce(headerInfo.noncePrefix, chunkIndex);
            const aad = buildAAD(chunkIndex, isFinal);

            const plaintextBuffer = await crypto.subtle.decrypt(
              { name: 'AES-GCM', iv: nonce, additionalData: aad },
              key,
              ciphertext
            );

            const plaintext = new Uint8Array(plaintextBuffer);
            await writer.write(plaintext);
            
            bytesDecrypted += plaintext.length;
            if (onProgress) {
              onProgress({ bytesDecrypted, chunksCompleted: chunkIndex + 1, totalChunks: headerInfo.totalChunks });
            }

            buffer = buffer.subarray(4 + chunkLen);
            chunkIndex++;
          } else {
            break; // need more data for this chunk
          }
        }
      }

      if (done) break;
    }

    if (buffer.length > 0) {
      throw new Error('Stream ended with leftover undecrypted bytes');
    }
  } finally {
    await writer.close();
  }
}
