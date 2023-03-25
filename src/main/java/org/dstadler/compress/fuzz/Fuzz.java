package org.dstadler.compress.fuzz;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.util.Collection;
import java.util.Set;

import org.apache.commons.compress.archivers.ArchiveEntry;
import org.apache.commons.compress.archivers.ArchiveException;
import org.apache.commons.compress.archivers.ArchiveInputStream;
import org.apache.commons.compress.archivers.ArchiveOutputStream;
import org.apache.commons.compress.archivers.ArchiveStreamFactory;
import org.apache.commons.compress.archivers.ar.ArArchiveOutputStream;
import org.apache.commons.compress.archivers.cpio.CpioArchiveOutputStream;
import org.apache.commons.compress.archivers.jar.JarArchiveOutputStream;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream;
import org.apache.commons.compress.compressors.CompressorException;
import org.apache.commons.compress.compressors.CompressorInputStream;
import org.apache.commons.compress.compressors.CompressorOutputStream;
import org.apache.commons.compress.compressors.CompressorStreamFactory;
import org.apache.commons.compress.compressors.bzip2.BZip2CompressorOutputStream;
import org.apache.commons.compress.compressors.deflate.DeflateCompressorOutputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorOutputStream;
import org.apache.commons.compress.compressors.lz4.BlockLZ4CompressorOutputStream;
import org.apache.commons.compress.compressors.lz4.FramedLZ4CompressorOutputStream;
import org.apache.commons.compress.compressors.lzma.LZMACompressorOutputStream;
import org.apache.commons.compress.compressors.pack200.Pack200CompressorOutputStream;
import org.apache.commons.compress.compressors.snappy.FramedSnappyCompressorOutputStream;
import org.apache.commons.compress.compressors.snappy.SnappyCompressorOutputStream;
import org.apache.commons.compress.compressors.xz.XZCompressorOutputStream;
import org.apache.commons.compress.compressors.zstandard.ZstdCompressorOutputStream;
import org.apache.commons.compress.utils.ArchiveUtils;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.filefilter.TrueFileFilter;
import org.apache.commons.io.output.NullOutputStream;
import org.apache.commons.lang3.exception.ExceptionUtils;

/**
 * This class provides a simple target for fuzzing Apache Commons Compress with Jazzer.
 *
 * It uses the fuzzed input data to try to detect and unpack archives.
 *
 * It catches all exceptions that are currently expected.
 */
public class Fuzz {
	private static final int MAX_UNCOMPRESSED_BYTES = 1024*1024;

	public static void fuzzerTestOneInput(byte[] inputData) {
		// try to read the data as archive and extract and re-archive it with all archivers
		checkArchiver(inputData);

		// also try to read the data as compressed file and decompress and re-compress it with all compressors
		checkCompressor(inputData);
	}

	private static void checkArchiver(byte[] inputData) {
		try {
			ArchiveInputStream input = new ArchiveStreamFactory()
					.createArchiveInputStream(new ByteArrayInputStream(inputData));

			// try to extract all the files in the archive into a temporary directory
			File tempDir = File.createTempFile("compress-fuzz", "");
			if (!tempDir.delete()) {
				throw new IOException("Failed to delete " + tempDir);
			}
			try {
				while (true) {
					ArchiveEntry entry = input.getNextEntry();
					if (entry == null) {
						break;
					}

					ArchiveUtils.toString(entry);

					if (!input.canReadEntryData(entry)) {
						continue;
					}

					File f = new File(tempDir, entry.getName());
					if (entry.isDirectory()) {
						if (!f.isDirectory() && !f.mkdirs()) {
							throw new IOException("failed to create directory " + f);
						}
					} else {
						File parent = f.getParentFile();
						if (!parent.isDirectory() && !parent.mkdirs()) {
							throw new IOException("failed to create directory " + parent);
						}
						try (OutputStream o = Files.newOutputStream(f.toPath())) {
							IOUtils.copy(input, o);
						}
					}
				}

				// try to put the extracted files into an archive again
				Collection<File> filesToArchive = FileUtils.listFiles(tempDir, TrueFileFilter.TRUE, TrueFileFilter.TRUE);
				for (ArchiveOutputStream out : createArchivers()) {
					try (out) {
						for (File f : filesToArchive) {
							ArchiveEntry entry = out.createArchiveEntry(f, f.getName());
							out.putArchiveEntry(entry);
							try (InputStream i = Files.newInputStream(f.toPath())) {
								IOUtils.copy(i, out);
							}
							out.closeArchiveEntry();
						}
						out.finish();
					}
				}
			} finally {
				FileUtils.deleteDirectory(tempDir);
			}
		} catch (ArchiveException | IOException |
				// many runtime-exceptions are
				// thrown with corrupt files
				RuntimeException e) {
			// expected here
		}
	}

	private static final Set<String> UNDETECTED = Set.of(
			CompressorStreamFactory.BROTLI,
			CompressorStreamFactory.SNAPPY_RAW,
			CompressorStreamFactory.DEFLATE64,
			CompressorStreamFactory.LZ4_BLOCK);

	private static void checkCompressor(byte[] inputData) {
		String name = null;
		try {
			name = CompressorStreamFactory.detect(new ByteArrayInputStream(inputData));
		} catch (IllegalArgumentException | CompressorException e) {
			// expected here if the type cannot be detected
		}

		if (name == null) {
			// if we cannot detect the type, we iterate over the "undetectable" formats to also cover those
			for (String type : UNDETECTED) {
				runCheck(inputData, type);
			}
		} else {
			runCheck(inputData, name);
		}
	}

	private static void runCheck(byte[] inputData, String name) {
		try {
			CompressorInputStream input = new CompressorStreamFactory(false,
					// enable safety feature which limits how much memory can be allocated
					1024)
					.createCompressorInputStream(name, new ByteArrayInputStream(inputData));

			ByteArrayOutputStream bytesIn = new ByteArrayOutputStream();
			// read the input stream
			byte[] bytes = new byte[64*1024];
			while (true) {
				int read = input.read(bytes);
				if (read < 0) {
					break;
				}

				// do not try to decompress huge files to avoid OOMs here
				if (bytesIn.size() > MAX_UNCOMPRESSED_BYTES) {
					// we could not fully uncompress the data, but let's still feed it into the archive and compressor
					// to see what happens with cut-off data
					break;
				}

				bytesIn.writeBytes(bytes);
			}

			// this might now be an archive, so let's run it through that as well
			checkArchiver(bytesIn.toByteArray());

			// write out via all available compressors
			for (CompressorOutputStream stream : createCompressors()) {
				try (stream) {
					stream.write(bytesIn.toByteArray());
				}
			}
		} catch (CompressorException | IOException |
				// many runtime-exceptions are
				// thrown with corrupt files
				RuntimeException e) {
			// expected here
		} catch (Error e) {

			// allow "Error" directly as there are some cases where it is thrown
			if (e.getClass().getSimpleName().equals("Error")) {
				return;
			}

			// this is reported at https://issues.apache.org/jira/browse/COMPRESS-599
			// so this can be removed as soon as this is fixed in commons-compress
			if (e instanceof OutOfMemoryError &&
					ExceptionUtils.getStackTrace(e).contains("unpack200")) {
				return;
			}

			throw e;
		}
	}

	private static ArchiveOutputStream[] createArchivers() {
		return new ArchiveOutputStream[] {
				new CpioArchiveOutputStream(NullOutputStream.NULL_OUTPUT_STREAM),
				new TarArchiveOutputStream(NullOutputStream.NULL_OUTPUT_STREAM),
				new ArArchiveOutputStream(NullOutputStream.NULL_OUTPUT_STREAM),
				new ZipArchiveOutputStream(NullOutputStream.NULL_OUTPUT_STREAM),
				new JarArchiveOutputStream(NullOutputStream.NULL_OUTPUT_STREAM),
		};
	}

	private static CompressorOutputStream[] createCompressors() throws IOException {
		return new CompressorOutputStream[] {
				new FramedSnappyCompressorOutputStream(NullOutputStream.NULL_OUTPUT_STREAM),
				new Pack200CompressorOutputStream(NullOutputStream.NULL_OUTPUT_STREAM),
				new BZip2CompressorOutputStream(NullOutputStream.NULL_OUTPUT_STREAM),
				new FramedLZ4CompressorOutputStream(NullOutputStream.NULL_OUTPUT_STREAM),
				new XZCompressorOutputStream(NullOutputStream.NULL_OUTPUT_STREAM),
				new DeflateCompressorOutputStream(NullOutputStream.NULL_OUTPUT_STREAM),
				new BlockLZ4CompressorOutputStream(NullOutputStream.NULL_OUTPUT_STREAM),
				new GzipCompressorOutputStream(NullOutputStream.NULL_OUTPUT_STREAM),
				new SnappyCompressorOutputStream(NullOutputStream.NULL_OUTPUT_STREAM, 1000),
				new LZMACompressorOutputStream(NullOutputStream.NULL_OUTPUT_STREAM),
				new ZstdCompressorOutputStream(NullOutputStream.NULL_OUTPUT_STREAM),
		};
	}
}
