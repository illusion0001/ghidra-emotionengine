package ghidra.emotionengine.analysis;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.emotionengine.EmotionEngineLoader;
import ghidra.program.model.listing.Program;

public abstract class AbstractEmotionEngineAnalyzer extends AbstractAnalyzer {

	protected AbstractEmotionEngineAnalyzer(String name, String description, AnalyzerType type) {
		super(name, description, type);
	}

	@Override
	public final boolean canAnalyze(Program program) {
		return EmotionEngineLoader.canLoad(program);
	}

	@Override
	public final boolean getDefaultEnablement(Program program) {
		return canAnalyze(program);
	}
}
