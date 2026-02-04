#!/usr/bin/env node
/**
 * Log File Splitter for FreeKhana SIEM API
 * Splits large log files into chunks that fit within Cloudflare Workers CPU limits
 */

const fs = require('fs');
const path = require('path');

const DEFAULT_CHUNK_SIZE = 256 * 1024; // 256KB
const MIN_CHUNK_SIZE = 64 * 1024; // 64KB minimum
const MAX_CHUNK_SIZE = 512 * 1024; // 512KB maximum

function showHelp() {
  console.log(`
FreeKhana SIEM - Log File Splitter
===================================

Usage: node split-log-file.js <file> [chunkSizeKB] [outputDir]

Arguments:
  file         Path to the log file to split
  chunkSizeKB  Chunk size in KB (default: 256, min: 64, max: 512)
  outputDir    Output directory (default: ./split-logs)

Examples:
  node split-log-file.js large.log
  node split-log-file.js auth.log 128 ./chunks
  node split-log-file.js /path/to/logs/app.log 256

Output:
  Creates <filename-chunks>/ directory with:
  - chunk_001.log
  - chunk_002.log
  ...
  - manifest.json (for programmatic use)

Cloudflare Workers Limits:
  - Text files: 512KB max (256KB recommended)
  - EVTX files: 2MB max
  - CPU time: 10-50ms per request

For API usage, send chunks to /parse/chunked endpoint:
  POST /parse/chunked
  Body: { "chunks": ["<chunk1 content>", "<chunk2 content>", ...], "fileName": "original.log" }

`);
  process.exit(0);
}

function validateChunkSize(size) {
  const kb = parseInt(size, 10);
  if (isNaN(kb) || kb < MIN_CHUNK_SIZE || kb > MAX_CHUNK_SIZE) {
    console.error(`Error: Chunk size must be between ${MIN_CHUNK_SIZE/1024}KB and ${MAX_CHUNK_SIZE/1024}KB`);
    console.error(`Using default: ${DEFAULT_CHUNK_SIZE/1024}KB`);
    return DEFAULT_CHUNK_SIZE;
  }
  return kb * 1024;
}

function splitFile(inputPath, chunkSize, outputDir) {
  if (!fs.existsSync(inputPath)) {
    console.error(`Error: File not found: ${inputPath}`);
    process.exit(1);
  }

  const stats = fs.statSync(inputPath);
  const fileSize = stats.size;
  const fileName = path.basename(inputPath, path.extname(inputPath));
  const extension = path.extname(inputPath);

  console.log(`\nFreeKhana SIEM - Log File Splitter`);
  console.log(`==================================`);
  console.log(`Input file: ${inputPath}`);
  console.log(`File size: ${(fileSize / 1024 / 1024).toFixed(2)} MB`);
  console.log(`Chunk size: ${(chunkSize / 1024).toKB} KB`);
  console.log(`Output dir: ${outputDir}`);

  // Create output directory
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  // Read entire file
  const content = fs.readFileSync(inputPath, 'utf8');

  // Split by lines to avoid breaking log entries
  const lines = content.split('\n');
  const chunks = [];
  let currentChunk = '';
  let currentSize = 0;
  let chunkIndex = 1;

  for (const line of lines) {
    const lineWithNewline = line + '\n';
    const lineSize = Buffer.byteLength(lineWithNewline);

    // If adding this line would exceed chunk size, start new chunk
    if (currentSize + lineSize > chunkSize && currentChunk.length > 0) {
      chunks.push({
        index: chunkIndex,
        content: currentChunk.trimEnd(),
        size: currentSize,
        lineCount: currentChunk.split('\n').length
      });
      chunkIndex++;
      currentChunk = lineWithNewline;
      currentSize = lineSize;
    } else {
      currentChunk += lineWithNewline;
      currentSize += lineSize;
    }
  }

  // Add remaining content as last chunk
  if (currentChunk.trimEnd().length > 0) {
    chunks.push({
      index: chunkIndex,
      content: currentChunk.trimEnd(),
      size: currentSize,
      lineCount: currentChunk.split('\n').length
    });
  }

  // Write chunks to files
  const manifest = {
    originalFile: inputPath,
    originalSize: fileSize,
    chunkSize,
    totalChunks: chunks.length,
    createdAt: new Date().toISOString(),
    chunks: []
  };

  console.log(`\nProcessing ${lines.length.toLocaleString()} lines...`);

  for (const chunk of chunks) {
    const chunkFileName = `chunk_${String(chunk.index).padStart(3, '0')}.log`;
    const chunkPath = path.join(outputDir, chunkFileName);

    fs.writeFileSync(chunkPath, chunk.content, 'utf8');

    manifest.chunks.push({
      file: chunkFileName,
      size: chunk.size,
      lineCount: chunk.lineCount,
      path: chunkPath
    });

    process.stdout.write(`\rWriting chunk ${chunk.index}/${chunks.length}...`);
  }

  console.log(`\n✓ Created ${chunks.length} chunks`);

  // Write manifest
  const manifestPath = path.join(outputDir, 'manifest.json');
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2), 'utf8');
  console.log(`✓ Manifest: ${manifestPath}`);

  // Print summary
  console.log(`\nSummary:`);
  console.log(`--------`);
  console.log(`Total chunks: ${chunks.length}`);
  console.log(`Largest chunk: ${Math.max(...chunks.map(c => c.size))} bytes`);
  console.log(`Smallest chunk: ${Math.min(...chunks.map(c => c.size))} bytes`);

  // API usage instructions
  console.log(`\nAPI Usage:`);
  console.log(`----------`);
  console.log(`1. Load chunks into array:`);
  console.log(`   const fs = require('fs');`);
  console.log(`   const chunks = [`);
  manifest.chunks.forEach((c, i) => {
    if (i < 3) {
      console.log(`     fs.readFileSync('${c.file}', 'utf8'),`);
    } else if (i === 3) {
      console.log(`     // ... (${chunks.length - 3} more chunks)`);
    }
  });
  console.log(`   ];`);

  console.log(`\n2. Send to API:`);
  console.log(`   POST ${'/parse/chunked'}`);
  console.log(`   Body: { chunks, fileName: '${path.basename(inputPath)}' }`);

  console.log(`\n3. Quick curl command:`);
  console.log(`   curl -X POST "https://siem-backend.tanubhavj.workers.dev/parse/chunked" \\`);
  console.log(`     -H "Content-Type: application/json" \\`);
  console.log(`     -d '{"chunks":['`);

  const sampleChunk = chunks[0]?.content?.slice(0, 100)?.replace(/'/g, "\\'") || '';
  console.log(`       "${sampleChunk}..."`);

  console.log(`     ], "fileName": "${path.basename(inputPath)}"}'`);

  console.log(`\nFor complete CLI tool, install FreeKhana CLI globally.`);
  console.log(`\nOutput directory: ${path.resolve(outputDir)}`);

  return manifest;
}

// Main
if (process.argv.includes('--help') || process.argv.includes('-h')) {
  showHelp();
}

const args = process.argv.slice(2);
if (args.length === 0) {
  console.log('Error: Missing required argument: file path');
  console.log('Usage: node split-log-file.js <file> [chunkSizeKB] [outputDir]');
  console.log('       node split-log-file.js --help for more info');
  process.exit(1);
}

const inputFile = args[0];
const chunkSizeKB = args[1] ? validateChunkSize(args[1]) : DEFAULT_CHUNK_SIZE;
const outputDir = args[2] || `./${path.basename(inputFile, path.extname(inputFile))}-chunks`;

splitFile(inputFile, chunkSizeKB, outputDir);
