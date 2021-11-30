package org.dstadler.compress.fuzz;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import org.apache.commons.compress.archivers.ArchiveEntry;
import org.apache.commons.compress.archivers.ArchiveException;
import org.apache.commons.compress.archivers.ArchiveInputStream;
import org.apache.commons.compress.archivers.ArchiveStreamFactory;

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
		} catch (ArchiveException | IOException e) {
			// expected here
		}
	}
}
