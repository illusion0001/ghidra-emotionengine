package ghidra.emotionengine.importer;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FSRLRoot;
import ghidra.formats.gfilesystem.FSUtilities;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryFull;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeBytesOnly;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeWithFile;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import static ghidra.emotionengine.importer.EmotionEngineRomImgFileSystem.MAX_HEADER_OFFSET;

public class EmotionEngineRomImgFactory
	implements GFileSystemFactoryFull<EmotionEngineRomImgFileSystem>,
	GFileSystemProbeBytesOnly, GFileSystemProbeWithFile {

	private static final String EXTENSION = ".img";
	private static final String[] HEADER_NAMES = new String[] { "RESET", "ROMDIR", "EXTINFO" };

	private static final int BLOCK_SIZE = 0x10;

	@Override
	public int getBytesRequired() {
		return MAX_HEADER_OFFSET;
	}

	protected static String getNullTerminatedString(byte[] bytes) {
		for (int i = 0; i < bytes.length; i++) {
			if (bytes[i] == 0) {
				return new String(bytes, 0, i);
			}
		}
		return new String(bytes);
	}

	protected static int getHeaderOffset(byte[] bytes) {
		byte[] header = HEADER_NAMES[0].getBytes();
		MainLoop:
		for (int i = 0; i < MAX_HEADER_OFFSET && i < bytes.length; i += BLOCK_SIZE) {
			if (bytes[i] == header[0]) {
				for (int j = 1; j < header.length; j++) {
					if (bytes[i+j] != header[j]) {
						continue MainLoop;
					}
				}
				return i;
			}
		}
		return -1;
	}

	@Override
	public boolean probeStartBytes(FSRL containerFSRL, byte[] startBytes) {
		int offset = getHeaderOffset(startBytes);
		if (offset > -1) {
			byte[] block = new byte[0x10];
			ByteBuffer buf = ByteBuffer.wrap(startBytes, offset, block.length*3);
			Boolean result = null;
			for (String name : HEADER_NAMES) {
				buf.get(block);
				String fName = getNullTerminatedString(block);
				if (result == null) {
					result = name.equals(fName);
				} else {
					result &= name.equals(fName);
				}
			}
			return result;
		}
		return false;
	}

	@Override
	public EmotionEngineRomImgFileSystem create(FSRL containerFSRL, FSRLRoot targetFSRL,
		ByteProvider byteProvider, File containerFile, FileSystemService fsService,
		TaskMonitor monitor) throws IOException, CancelledException {
			EmotionEngineRomImgFileSystem fs =
				new EmotionEngineRomImgFileSystem(
					containerFile, targetFSRL, byteProvider);
			fs.mount(monitor);
			return fs;
	}

	@Override
	public boolean probe(FSRL containerFSRL, File containerFile, FileSystemService fsService,
		TaskMonitor monitor) throws IOException, CancelledException {
			String filename = containerFSRL.getName();
			String ext = FSUtilities.getExtension(filename, 1);
			if (ext != null && EXTENSION.equals(ext.toLowerCase())) {
				try (InputStream is = new FileInputStream(containerFile)) {
					byte[] startBytes = new byte[MAX_HEADER_OFFSET];
					if (is.read(startBytes) == startBytes.length) {
						return probeStartBytes(null, startBytes);
					}
				}
			}
			return false;
	}
			
}
