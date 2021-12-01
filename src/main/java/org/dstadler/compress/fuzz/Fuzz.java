package org.dstadler.compress.fuzz;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import org.apache.commons.compress.archivers.ArchiveEntry;
import org.apache.commons.compress.archivers.ArchiveException;
import org.apache.commons.compress.archivers.ArchiveInputStream;
import org.apache.commons.compress.archivers.ArchiveStreamFactory;
import org.apache.commons.compress.compressors.CompressorException;
import org.apache.commons.compress.compressors.CompressorInputStream;
import org.apache.commons.compress.compressors.CompressorStreamFactory;

/**
 * This class provides a simple target for fuzzing Apache Commons Compress with Jazzer.
 *
 * It uses the fuzzed input data to try to detect and unpack archives.
 *
 * It catches all exceptions that are currently expected.
 */
public class Fuzz {
	public static void fuzzerTestOneInput(byte[] inputData) {
		// try to invoke various methods which read archive data
		try {
			ArchiveInputStream input = new ArchiveStreamFactory()
					.createArchiveInputStream(new ByteArrayInputStream(inputData));

			while(true) {
				ArchiveEntry nextEntry = input.getNextEntry();
				if (nextEntry == null) {
					break;
				}
			}
		} catch (ArchiveException | IOException |
				// many runtime-exceptions are
				// thrown with corrupt files
				RuntimeException e) {
			// expected here
		}

		try {
			CompressorInputStream input = new CompressorStreamFactory(false,
						// enable safety feature which limits how much memory can be allocated
						1024)
					.createCompressorInputStream(new ByteArrayInputStream(inputData));

			// read the input stream
			byte[] bytes = new byte[1024];
			while (true) {
				int read = input.read(bytes);
				if (read < 0) {
					break;
				}
			}
		} catch (CompressorException | IOException |
				// many runtime-exceptions are
				// thrown with corrupt files
				RuntimeException e) {
			// expected here
		} catch (Error e) {
			// only allow "Error" directly, none of the derived classes
			if (!e.getClass().getSimpleName().equals("Error")) {
				throw e;
			}
		}
	}
}
