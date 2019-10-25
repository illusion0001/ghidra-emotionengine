package ghidra.emotionengine;

import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import org.xml.sax.*;

import ghidra.app.plugin.processors.sleigh.SleighException;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.plugin.processors.sleigh.template.ConstructTpl;
import ghidra.app.plugin.processors.sleigh.template.OpTpl;
import ghidra.pcodeCPort.slgh_compile.PcodeParser;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeXMLException;
import ghidra.sleigh.grammar.Location;
import ghidra.util.Msg;
import ghidra.util.xml.XmlUtilities;
import ghidra.xml.XmlPullParser;
import ghidra.xml.XmlPullParserFactory;

public class InjectPayloadVu extends InjectPayloadCallother {
    private SleighLanguage language;
    private SAXParser saxParser;

    private static final String FLOAT_ADD = "f+";
	private static final String FLOAT_SUB = "f-";
	private static final String FLOAT_MUL = "f*";
    private static final String ABS = "abs";
    private static final String FLOAT2FLOAT = "float2float";
    private static final String INT2FLOAT = "int2float";
    private static final String TRUNC = "trunc";
    private static final String END_LINE = ";\n";

    private static final String VUFD = "VUFD";
    private static final String VUFS = "VUFS";
	private static final String VUFT = "VUFT";
	private static final String VUACC = "vuACC";

    private static final String[] VECTOR_DIRECTIONS = new String[]{
        "[96,32]",
        "[64,32]",
        "[32,32]",
        "[0,32]"
    };

    public InjectPayloadVu(String sourceName, SleighLanguage language) {
		super(sourceName);
		this.language = language;
		try {
			saxParser = getSAXParser();
		}
		catch (PcodeXMLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	SleighLanguage getLanguage() {
		return language;
	}

	InjectContext getInjectContext(Program program, String context) {
		InjectContext injectContext = new InjectContext();
		injectContext.language = language;
		try {
			injectContext.restoreXml(saxParser, context, program.getAddressFactory());
			saxParser.reset();
		}
		catch (PcodeXMLException e1) {
			Msg.info(this, e1.getMessage());
			e1.printStackTrace();
		}
		return injectContext;
	}

	//from DecompileCallback.java
	private static SAXParser getSAXParser() throws PcodeXMLException {
		try {
			SAXParserFactory saxParserFactory = XmlUtilities.createSecureSAXParserFactory(false);
			saxParserFactory.setFeature("http://xml.org/sax/features/namespaces", false);
			saxParserFactory.setFeature("http://xml.org/sax/features/validation", false);
			return saxParserFactory.newSAXParser();
		}
		catch (Exception e) {
			Msg.error(PcodeInjectLibraryVu.class, e.getMessage());
			throw new PcodeXMLException("Failed to instantiate XML parser", e);
		}
	}

	/**
	 * This method is used to generate and compile pcode for a given
	 * callotherfixup.
	 * 
	 * @param parser Used to parse pcode.
	 * @param program The program containing the callotherfixup
	 * @param context The context of the callotherfixup.
	 * @return An array of OpTpl (for passing to
	 *         PcodeInjectLibrary.adjustUniqueBase)
	 */
	public OpTpl[] getPcode(PcodeParser parser, Program program, String context) {
		String sourceName = getSource();
		Location loc = new Location(sourceName, 1);

		InjectParameter[] input = getInput();
		for (InjectParameter element : input) {
			parser.addOperand(loc, element.getName(), element.getIndex());
		}
		InjectParameter[] output = getOutput();
		for (InjectParameter element : output) {
			parser.addOperand(loc, element.getName(), element.getIndex());
		}
        InjectContext injectContext = getInjectContext(program, context);
		String pcodeText = getPcodeText(injectContext.inputlist.get(0).getOffset());
		String constructTplXml =
			PcodeParser.stringifyTemplate(parser.compilePcode(pcodeText, sourceName, 1));
		if (constructTplXml == null) {
			throw new SleighException("pcode compile failed " + sourceName);
		}
		final SAXParseException[] exception = new SAXParseException[1];
		XmlPullParser xmlParser = null;
		try {
			xmlParser =
				XmlPullParserFactory.create(constructTplXml, sourceName, new ErrorHandler() {
					@Override
					public void warning(SAXParseException e) throws SAXException {
						Msg.warn(this, e.getMessage());
					}

					@Override
					public void fatalError(SAXParseException e) throws SAXException {
						exception[0] = e;
					}

					@Override
					public void error(SAXParseException e) throws SAXException {
						exception[0] = e;
					}
				}, false);
		}
		catch (SAXException e) {
			e.printStackTrace();
		}

		ConstructTpl constructTpl = new ConstructTpl();
		try {
			constructTpl.restoreXml(xmlParser, language.getAddressFactory());
		}
		catch (UnknownInstructionException e) {
			e.printStackTrace();
		}
		if (exception[0] != null) {
			throw new SleighException("pcode compiler returned invalid xml " + sourceName,
				exception[0]);
		}
		OpTpl[] opTemplates = constructTpl.getOpVec();
		setTemplate(constructTpl);
		return opTemplates;
    }

    private String getOperationText1(long dest, String operation,
        String output, String input) {
            StringBuilder builder = new StringBuilder();
            for(int i = 0; i < 4; i++) {
                if (((dest >> i) & 1) == 1) {
                    builder.append(output);
                    builder.append(VECTOR_DIRECTIONS[i]);
                    builder.append(' ');
                    builder.append('=');
                    builder.append(' ');
                    builder.append(operation);
                    builder.append('(');
                    builder.append(input);
                    builder.append(VECTOR_DIRECTIONS[i]);
                    builder.append(')');
                    builder.append(END_LINE);
                }
            }
            return builder.toString();
	}

    private String getOperationText3(long dest, String operation,
        String output, String input1, String input2, boolean broadcast) {
            StringBuilder builder = new StringBuilder();
            for(int i = 0; i < 4; i++) {
                if (((dest >> i) & 1) == 1) {
                    builder.append(output);
                    builder.append(VECTOR_DIRECTIONS[i]);
                    builder.append(' ');
                    builder.append('=');
                    builder.append(' ');
                    builder.append(input1);
                    builder.append(VECTOR_DIRECTIONS[i]);
                    builder.append(' ');
                    builder.append(operation);
                    builder.append(' ');
					builder.append(input2);
					if (!broadcast) {
						builder.append(VECTOR_DIRECTIONS[i]);
					}
                    builder.append(END_LINE);
                }
            }
            return builder.toString();
	}
	
	private String getMultiplyOperationText3(long dest, String operation,
        String output, String input1, String input2, boolean broadcast) {
            StringBuilder builder = new StringBuilder();
            for(int i = 0; i < 4; i++) {
                if (((dest >> i) & 1) == 1) {
                    builder.append(output);
                    builder.append(VECTOR_DIRECTIONS[i]);
                    builder.append(' ');
                    builder.append('=');
					builder.append(' ');
					builder.append(VUACC);
					builder.append(VECTOR_DIRECTIONS[i]);
					builder.append(' ');
					builder.append(operation);
					builder.append(' ');
                    builder.append(input1);
                    builder.append(VECTOR_DIRECTIONS[i]);
                    builder.append(' ');
                    builder.append(FLOAT_MUL);
                    builder.append(' ');
					builder.append(input2);
					if (!broadcast) {
						builder.append(VECTOR_DIRECTIONS[i]);
					}
                    builder.append(END_LINE);
                }
            }
            return builder.toString();
    }

    private String getPcodeText(long dest) {
        switch(getName()) {
            case PcodeInjectLibraryVu.VABS:
                return getOperationText1(dest, ABS, VUFT, VUFS);
			case PcodeInjectLibraryVu.VADD:
				return getOperationText3(dest, FLOAT_ADD, VUFD, VUFS, VUFT, false);
			case PcodeInjectLibraryVu.VADDBC:
				return getOperationText3(dest, FLOAT_ADD, VUFD, VUFS, VUFT, true);
			case PcodeInjectLibraryVu.VMADD:
				return getMultiplyOperationText3(dest, FLOAT_ADD, VUFD, VUFS, VUFT, false);
			case PcodeInjectLibraryVu.VMADDBC:
				return getMultiplyOperationText3(dest, FLOAT_ADD, VUFD, VUFS, VUFT, true);
            case PcodeInjectLibraryVu.VSUB:
				return getOperationText3(dest, FLOAT_SUB, VUFD, VUFS, VUFT, false);
			case PcodeInjectLibraryVu.VSUBBC:
				return getOperationText3(dest, FLOAT_SUB, VUFD, VUFS, VUFT, true);
			case PcodeInjectLibraryVu.VMUL:
				return getOperationText3(dest, FLOAT_MUL, VUFD, VUFS, VUFT, false);
			case PcodeInjectLibraryVu.VMULBC:
				return getOperationText3(dest, FLOAT_MUL, VUFD, VUFS, VUFT, true);
			case PcodeInjectLibraryVu.VMSUB:
				return getMultiplyOperationText3(dest, FLOAT_SUB, VUFD, VUFS, VUFT, false);
			case PcodeInjectLibraryVu.VMSUBBC:
				return getMultiplyOperationText3(dest, FLOAT_SUB, VUFD, VUFS, VUFT, true);
            case PcodeInjectLibraryVu.VFTOI0:
                return getOperationText1(dest, TRUNC, VUFT, VUFS);
            case PcodeInjectLibraryVu.VFTOI:
                return getOperationText1(dest, FLOAT2FLOAT, VUFT, VUFS);
            case PcodeInjectLibraryVu.VITOF:
                return getOperationText1(dest, INT2FLOAT, VUFT, VUFS);
            default:
                return null;
        }
    }
}
