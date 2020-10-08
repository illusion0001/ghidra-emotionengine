package ghidra.emotionengine.analysis;

import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.emotionengine.iop.IopModule;
import ghidra.emotionengine.iop.IopModuleUtil;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.StringUtilities;
import ghidra.util.bytesearch.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;
import ghidra.xml.XmlPullParser;

public final class EmotionEngineIrxAnalyzer extends AbstractEmotionEngineAnalyzer {

	private static final String NAME = EmotionEngineIrxAnalyzer.class.getSimpleName();
	private static final String DESCRIPTION =
		"Locates IRX module imports and adds them to the SymbolTree IMPORTS";

	private static final DittedBitSequence IRX_SEQUENCE =
		new DittedBitSequence("0x2E 01.01001 01.10010 01.11000");
	private static final DittedBitSequence IMG_SEQUENCE =
		new DittedBitSequence("0x2E 01.01001 01.01101 0.100111");

	private Program program;
	private MessageLog log;

	public EmotionEngineIrxAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.DATA_ANALYZER);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		this.program = program;
		this.log = log;
		IrxMatchAction action = new IrxMatchAction();
		MemoryBytePatternSearcher searcher = new MemoryBytePatternSearcher("Irx Module Searcher");
		searcher.addPattern(action.getIrxPattern());
		searcher.addPattern(action.getImgPattern());
		searcher.search(program, set, monitor);
		return true;
	}

	private String getModuleName(Address address) throws Exception {
		Listing listing = program.getListing();
		Data data = listing.getDataContaining(address);
		if (data == null || data.getValueClass() != String.class) {
			data = getStringData(address);
		}
		String name = StringUtilities.getLastWord((String) data.getValue(), "\\").split(";")[0];
		return name.toUpperCase();
	}

	private Data getStringData(Address address) throws Exception {
		Listing listing = program.getListing();
		Address end = address.add(IRX_SEQUENCE.getSize());
		MemBuffer buf = new DumbMemBufferImpl(program.getMemory(), address);
		int offset = 0;
		while (true) {
			char b = (char) buf.getByte(offset);
			if (!StringUtilities.isAsciiChar(b)) {
				break;
			}
			offset--;
		}
		address = address.add(offset);
		listing.clearCodeUnits(address, end, true);
		return listing.createData(address, TerminatedStringDataType.dataType);
	}

	private void createExternalModule(String module) {
		module = module.replaceAll(".IRX", "").toLowerCase();
		ExternalManager manager = program.getExternalManager();
		if (!manager.contains(module)) {
			try {
				IopModule irx = IopModuleUtil.getIopModule(module);
				Library library = manager.addExternalLibraryName(module, SourceType.IMPORTED);
				if (irx == null) {
					return;
				}
				for (String function : irx.getFunctions()) {
					manager.addExtFunction(library, function, null, SourceType.IMPORTED, true);
				}
			} catch (DuplicateNameException | InvalidInputException e) {
				// cant happen
				throw new AssertException(e);
			}
		}
	}

	private final class IrxMatchAction implements MatchAction {

		@Override
		public void apply(Program program, Address addr, Match match) {
			try {
				String module = getModuleName(addr);
				if (module.isBlank()) {
					return;
				}
				if (!SymbolUtilities.containsInvalidChars(module)) {
					// don't create a module for a log message
					createExternalModule(module);
				}
			} catch (Exception e) {
				log.appendException(e);
			}
		}

		@Override
		public void restoreXml(XmlPullParser parser) {
			throw new UnsupportedOperationException();
		}

		Pattern getIrxPattern() {
			return new Pattern(IRX_SEQUENCE, 0, new PostRule[0], new MatchAction[]{ this });
		}

		Pattern getImgPattern() {
			return new Pattern(IMG_SEQUENCE, 0, new PostRule[0], new MatchAction[]{ this });
		}

	}
}
