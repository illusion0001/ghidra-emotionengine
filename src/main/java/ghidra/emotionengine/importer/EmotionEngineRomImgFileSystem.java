package ghidra.emotionengine.importer;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderInputStream;
import ghidra.formats.gfilesystem.FSRLRoot;
import ghidra.formats.gfilesystem.FileSystemIndexHelper;
import ghidra.formats.gfilesystem.FileSystemRefManager;
import ghidra.formats.gfilesystem.GFile;
import ghidra.formats.gfilesystem.GFileSystem;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import static ghidra.emotionengine.importer.EmotionEngineRomImgFactory.getNullTerminatedString;
import static ghidra.emotionengine.importer.EmotionEngineRomImgFactory.getHeaderOffset;

@FileSystemInfo(type = "img", description = "Iop Rom Image", priority = FileSystemInfo.PRIORITY_LOW, factory = EmotionEngineRomImgFactory.class)
public class EmotionEngineRomImgFileSystem implements GFileSystem {

	private File file;
	private FSRLRoot fsrl;
	private ByteProvider provider;
	private static final byte BLOCK_SIZE = 0x10;
	private FileSystemIndexHelper<RomDirMetaData> helper;
	private FileSystemRefManager refManager = new FileSystemRefManager(this);
	protected static final int MAX_NAME_LENGTH = 10;
	private RomDirMetaData[] header = new RomDirMetaData[3];

	protected static final int MAX_HEADER_OFFSET = 0x4000;
	private static final String FILE_SEPARATOR = "-";

	public EmotionEngineRomImgFileSystem(File file, FSRLRoot fsrl, ByteProvider provider) {
		this.file = file;
		this.fsrl = fsrl;
		this.helper = new FileSystemIndexHelper<>(this, fsrl.getFS());
		this.provider = provider;
	}

	protected void mount(TaskMonitor monitor) throws IOException, CancelledException {
		int offset = getHeaderOffset(provider.readBytes(0, MAX_HEADER_OFFSET));
		byte[] block = new byte[BLOCK_SIZE];
		InputStream stream = provider.getInputStream(offset);
		ByteBuffer buf = ByteBuffer.wrap(block);
		buf.order(ByteOrder.LITTLE_ENDIAN);
		RomDirMetaData meta = null;

		// Since the helper doesn't return the list in index order
		List<String> fNames = new LinkedList<>();
		for (int i = 0; i < header.length; i++) {
			// reset position and read next block into the buffer
			buf.clear();
			stream.read(block);
			meta = new RomDirMetaData(buf);
			header[i] = meta;
		}
		while (true) {
			monitor.checkCanceled();
			// reset position and read next block into the buffer
			buf.clear();
			stream.read(block);
			meta = new RomDirMetaData(buf);
			if (meta.name.length() <= 0) {
				break;
			}
			fNames.add(meta.name);
			helper.storeFile(meta.name, helper.getFileCount(), false, meta.size, meta);
		}
		stream = provider.getInputStream(offset+header[1].size);
		for (RomDirMetaData metaHeader : header) {
			if (metaHeader.extsize == 0) {
				// EXTINFO has no extinfo :p
				continue;
			}
			block = new byte[metaHeader.extsize];
			stream.read(block);
			metaHeader.fillExtInfo(ByteBuffer.wrap(block));
		}
		int irxOffset = (offset+header[1].size + header[2].size + 0xf) & ~0xf;
		List<RomDirMetaData> metaDatas = new ArrayList<>(helper.getFileCount());
		for (String fName : fNames) {
			monitor.checkCanceled();
			GFile file = helper.lookup(fName);
			meta = helper.getMetadata(file);
			meta.offset = irxOffset;
			irxOffset += (meta.size+ 0xf) & ~0xf;
			block = new byte[meta.extsize];
			stream.read(block);
			meta.fillExtInfo(ByteBuffer.wrap(block));
			if (!fName.equals(FILE_SEPARATOR)) {
				metaDatas.add(meta);
			}
		}
		helper.clear();
		for (RomDirMetaData metaData : metaDatas) {
			helper.storeFile(metaData.name, helper.getFileCount(), false, metaData.size, metaData);
		}
	}

	@Override
	public void close() throws IOException {
		if (provider == null) {
			throw new IOException(file.getName()+" is closed.");
		}
		refManager.onClose();
		provider.close();
		// set it to null so we know when it's been closed.
		provider = null;
	}

	@Override
	public String getName() {
		return file.getName();
	}

	@Override
	public FSRLRoot getFSRL() {
		return fsrl;
	}

	@Override
	public boolean isClosed() {
		return provider == null;
	}

	@Override
	public FileSystemRefManager getRefManager() {
		return refManager;
	}

	@Override
	public GFile lookup(String path) throws IOException {
		return helper.lookup(path);
	}

	@Override
	public InputStream getInputStream(GFile file, TaskMonitor monitor)
		throws IOException, CancelledException {
			RomDirMetaData meta = helper.getMetadata(file);
			if (meta == null) {
				throw new IOException("Unknown file " + file);
			}
			return new ByteProviderInputStream(provider, meta.offset, meta.size);
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		return helper.getListing(directory);
	}

	@SuppressWarnings("unused")
	private static class RomDirMetaData {
		static final byte EXT_HEADER_SIZE = 4;
		static final byte SIZE_OFFSET = 0xc;
		static final byte DATE = 1;
		static final byte VERSION = 2;
		static final byte DESCRIPTION = 3;
		static final byte NULL = 0x7f;

		String name;
		String description;
		byte flags;
		int date;
		short version;
		int offset;
		int extsize;
		int size;

		RomDirMetaData(ByteBuffer buf) {
			byte[] bytes = new byte[MAX_NAME_LENGTH];
			buf.get(bytes);
			name = getNullTerminatedString(bytes);
			extsize = buf.getShort();
			size = buf.getInt();
		}

		void fillExtInfo(ByteBuffer buf) throws IOException {
			while (extsize > 0) {
				short value = buf.getShort();
				byte metaSize = buf.get();
				byte id = buf.get();
				extsize -= metaSize+EXT_HEADER_SIZE;
				switch (id) {
					case DATE:
						date = buf.getInt();
						extsize -= 4;
						flags |= 1;
						break;
					case VERSION:
						version = value;
						flags |= 2;
						break;
					case DESCRIPTION:
						byte[] bytes = new byte[metaSize];
						buf.get(bytes);
						description = getNullTerminatedString(bytes);
						extsize -= description.length();
						flags |= 4;
						break;
					case NULL:
						flags |= 8;
						break;
					default:
						break;
				}
			}
		}
	}

}
