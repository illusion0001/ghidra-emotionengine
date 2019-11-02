/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

 // InjectPayloadJava modified for use with ghidra-emotionengine

package ghidra.emotionengine;

import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import org.xml.sax.*;

import generic.stl.Pair;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.function.BiFunction;

import ghidra.app.plugin.processors.sleigh.SleighException;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.plugin.processors.sleigh.template.ConstructTpl;
import ghidra.app.plugin.processors.sleigh.template.OpTpl;
import ghidra.pcodeCPort.slgh_compile.PcodeParser;
import ghidra.program.model.address.Address;
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

	private static final String FLOAT_ADD = " f+ ";
	private static final String INT_ADD = " + ";
	private static final String FLOAT_SUB = " f- ";
	private static final String FLOAT_MUL = " f* ";
	private static final String FLOAT_GREATER_THAN = " f> ";
	private static final String FLOAT_LESS_THAN = " f< ";
	private static final String ASSIGNMENT = " = ";
	private static final String GOTO = " goto ";
	private static final String IF = "if (";
	private static final String MAX = "<max";
	private static final String MIN = "<min";
	private static final String END = "<end";
	private static final String SEXT = "sext(";
    private static final String ABS = "abs";
    private static final String FLOAT2FLOAT = "float2float";
    private static final String INT2FLOAT = "int2float";
    private static final String TRUNC = "trunc";
    private static final String END_LINE = ";\n";

    private static final String VUFD = "VUFD";
    private static final String VUFS = "VUFS";
	private static final String VUFT = "VUFT";
	private static final String VUIS = "VUIS";
	private static final String VUACC = "vuACC";

	private static final String ADDRESS = "addr";
	private static final String FLOAT_POINTER = "*:4 ";
	private static final String BROADCAST = "BC";
	private static final String VEC_ZERO = "vf0";

	private static final String[] ZERO = new String[]{
		"int2float(1:4)",
		"int2float(0:4)",
		"int2float(0:4)",
		"int2float(0:4)"
	};
    private static final String[] VECTOR_DIRECTIONS = new String[]{
        "[96,32]",
        "[64,32]",
        "[32,32]",
        "[0,32]"
	};
	
	private static final Map<String, Pair<BiFunction<Long, String, String>, String>>
		INSTRUCTIONS = getInstructionMap();

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

	private String setZero(long dest, String register) {
		final int MAX_STRING_LENGTH = 119;
		StringBuilder builder = new StringBuilder(MAX_STRING_LENGTH);
		for(int i = 0; i < 4; i++) {
			if (((dest >> i) & 1) == 1) {
				builder.append(register)
				.append(VECTOR_DIRECTIONS[i])
				.append(ASSIGNMENT)
				.append(ZERO[i])
				.append(END_LINE);
			}
		}
		return builder.toString();
	}

	public OpTpl[] getPcode(PcodeParser parser, Program program, String context) {
		Address vf0Address = program.getRegister(VEC_ZERO).getAddress();
		if (!INSTRUCTIONS.containsKey(getName())) {
			return new OpTpl[0];
		}
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
		long dest = injectContext.inputlist.get(0).getOffset();
		BiFunction<Long, String, String> function = INSTRUCTIONS.get(getName()).first;
		StringBuilder pcodeTextBuilder = new StringBuilder();
		for (int i = 1; i < injectContext.inputlist.size(); i++) {
			if (injectContext.inputlist.get(i).getSize() == 0x10) {
				if (vf0Address.equals(injectContext.inputlist.get(i).getAddress())) {
					pcodeTextBuilder.append(setZero(dest, input[i].getName()));
				}
			}
		}
		pcodeTextBuilder.append(function.apply(dest, getName()));
		String constructTplXml =
			PcodeParser.stringifyTemplate(parser.compilePcode(
				pcodeTextBuilder.toString(), sourceName, 1));
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

    private static String getOperationText1(long dest, String name) {
		StringBuilder builder = new StringBuilder();
		String operation = INSTRUCTIONS.get(name).second;
		for(int i = 0; i < 4; i++) {
			if (((dest >> i) & 1) == 1) {
				builder.append(VUFT)
				.append(VECTOR_DIRECTIONS[i])
				.append(ASSIGNMENT)
				.append(operation)
				.append('(')
				.append(VUFS)
				.append(VECTOR_DIRECTIONS[i])
				.append(')')
				.append(END_LINE);
			}
		}
		return builder.toString();
	}

    private static String getOperationText3(long dest, String name) {
		StringBuilder builder = new StringBuilder();
		boolean broadcast = name.endsWith(BROADCAST);
		String operation = INSTRUCTIONS.get(name).second;
		for(int i = 0; i < 4; i++) {
			if (((dest >> i) & 1) == 1) {
				builder.append(VUFD)
				.append(VECTOR_DIRECTIONS[i])
				.append(ASSIGNMENT)
				.append(VUFS)
				.append(VECTOR_DIRECTIONS[i])
				.append(operation)
				.append(VUFT);
				if (!broadcast) {
					builder.append(VECTOR_DIRECTIONS[i]);
				}
				builder.append(END_LINE);
			}
		}
		return builder.toString();
	}
	
	private static String getMultiplyOperationText3(long dest, String name) {
		StringBuilder builder = new StringBuilder();
		boolean broadcast = name.endsWith(BROADCAST);
		String operation = INSTRUCTIONS.get(name).second;
		for(int i = 0; i < 4; i++) {
			if (((dest >> i) & 1) == 1) {
				builder.append(VUFD)
				.append(VECTOR_DIRECTIONS[i])
				.append(ASSIGNMENT)
				.append(VUACC)
				.append(VECTOR_DIRECTIONS[i])
				.append(operation)
				.append(VUFS)
				.append(VECTOR_DIRECTIONS[i])
				.append(FLOAT_MUL)
				.append(VUFT);
				if (!broadcast) {
					builder.append(VECTOR_DIRECTIONS[i]);
				}
				builder.append(END_LINE);
			}
		}
		return builder.toString();
	}
	
	private static String getLoadText(long dest, String name) {
            StringBuilder builder = new StringBuilder();
            for(int i = 0; i < 4; i++) {
                if (((dest >> i) & 1) == 1) {
                    builder.append(VUFT)
                    .append(VECTOR_DIRECTIONS[i])
                    .append(ASSIGNMENT)
					.append(FLOAT_POINTER)
					.append('(')
					.append(ADDRESS)
					.append(INT_ADD)
					.append(Integer.toString(4*i))
					.append(')')
					.append(END_LINE);
                }
            }
            return builder.toString();
	}
	
	private static String getStoreText(long dest, String name) {
		StringBuilder builder = new StringBuilder();
		for(int i = 0; i < 4; i++) {
			if (((dest >> i) & 1) == 1) {
				builder.append(FLOAT_POINTER)
					   .append('(')
					   .append(ADDRESS)
					   .append(INT_ADD)
					   .append(Integer.toString(4*i))
					   .append(')')
					   .append(ASSIGNMENT)
					   .append(VUFS)
					   .append(VECTOR_DIRECTIONS[i])
					   .append(END_LINE);
			}
		}
		return builder.toString();
	}

	private static String getMaxText(long dest, String name) {
		boolean broadcast = name.endsWith(BROADCAST);
		StringBuilder builder = new StringBuilder();
		for(int i = 0; i < 4; i++) {
			if (((dest >> i) & 1) == 1) {
				String max = new StringBuilder(MAX)
							.append(Integer.toString(i))
							.append('>').toString();
				String end = new StringBuilder(END)
							.append(Integer.toString(i))
							.append('>').toString();
				builder.append(IF)
				.append(VUFS)
				.append(VECTOR_DIRECTIONS[i])
				.append(FLOAT_GREATER_THAN)
				.append(VUFT)
				.append(VECTOR_DIRECTIONS[i])
				.append(GOTO)
				.append(max)
				.append(END_LINE)
				.append(VUFD)
				.append(VECTOR_DIRECTIONS[i])
				.append(ASSIGNMENT)
				.append(VUFT);
				if (!broadcast) {
					builder.append(VECTOR_DIRECTIONS[i]);
				}
				builder.append(GOTO)
				.append(end)
				.append(END_LINE)
				.append(max)
				.append('\n')
				.append(VUFD)
				.append(VECTOR_DIRECTIONS[i])
				.append(ASSIGNMENT)
				.append(VUFS)
				.append(VECTOR_DIRECTIONS[i])
				.append(END_LINE)
				.append(end);
			}
		}
		return builder.toString();
	}

	private static String getMinText(long dest, String name) {
		boolean broadcast = name.endsWith(BROADCAST);
		StringBuilder builder = new StringBuilder();
		for(int i = 0; i < 4; i++) {
			if (((dest >> i) & 1) == 1) {
				String max = new StringBuilder(MIN)
							.append(Integer.toString(i))
							.append('>').toString();
				String end = new StringBuilder(END)
							.append(Integer.toString(i))
							.append('>').toString();
				builder.append(IF)
				.append(VUFS)
				.append(VECTOR_DIRECTIONS[i])
				.append(FLOAT_LESS_THAN)
				.append(VUFT);
				if (!broadcast) {
					builder.append(VECTOR_DIRECTIONS[i]);
				}
				builder.append(GOTO)
				.append(max)
				.append(END_LINE)
				.append(VUFD)
				.append(VECTOR_DIRECTIONS[i])
				.append(ASSIGNMENT)
				.append(VUFT);
				if (!broadcast) {
					builder.append(VECTOR_DIRECTIONS[i]);
				}
				builder.append(GOTO)
				.append(end)
				.append(END_LINE)
				.append(max)
				.append('\n')
				.append(VUFD)
				.append(VECTOR_DIRECTIONS[i])
				.append(ASSIGNMENT)
				.append(VUFS)
				.append(VECTOR_DIRECTIONS[i])
				.append(END_LINE)
				.append(end);
			}
		}
		return builder.toString();
	}

	private static String getMFIRText(long dest, String name) {
		StringBuilder builder = new StringBuilder();
		for(int i = 0; i < 4; i++) {
			if (((dest >> i) & 1) == 1) {
				builder.append(VUFT)
				.append(VECTOR_DIRECTIONS[i])
				.append(ASSIGNMENT)
				.append(SEXT)
				.append(VUIS)
				.append(')')
				.append(END_LINE);
			}
		}
		return builder.toString();
	}

	private static String getMoveText(long dest, String name) {
		StringBuilder builder = new StringBuilder();
		boolean broadcast = name.endsWith(BROADCAST);
		for(int i = 0; i < 4; i++) {
			if (((dest >> i) & 1) == 1) {
				builder.append(VUFT)
				.append(VECTOR_DIRECTIONS[i])
				.append(ASSIGNMENT)
				.append(VUFS);
				if (!broadcast) {
					builder.append(VECTOR_DIRECTIONS[i]);
				}
				builder.append(END_LINE);
			}
		}
		return builder.toString();
	}

	private static String getMoveRotateText(long dest, String name) {
		StringBuilder builder = new StringBuilder();
		for(int i = 0; i < 4; i++) {
			if (((dest >> i) & 1) == 1) {
				builder.append(VUFT)
				.append(VECTOR_DIRECTIONS[i])
				.append(ASSIGNMENT)
				.append(VUFS);
				if (i+1 >= VECTOR_DIRECTIONS.length) {
					builder.append(VECTOR_DIRECTIONS[0]);
				} else {
					builder.append(VECTOR_DIRECTIONS[i+1]);
				}
				builder.append(END_LINE);
			}
		}
		return builder.toString();
	}

    private static Map<String, Pair<BiFunction<Long, String, String>, String>> getInstructionMap() {
		Map<String, Pair<BiFunction<Long, String, String>, String>> instructions = new HashMap<>();
		instructions.put(PcodeInjectLibraryVu.VABS,
						 new Pair<BiFunction<Long, String, String>, String>(
							InjectPayloadVu::getOperationText1, ABS));
		instructions.put(PcodeInjectLibraryVu.VADD,
						 new Pair<BiFunction<Long, String, String>, String>(
							InjectPayloadVu::getOperationText3, FLOAT_ADD));
		instructions.put(PcodeInjectLibraryVu.VADDBC,
						 new Pair<BiFunction<Long, String, String>, String>(
							InjectPayloadVu::getOperationText3, FLOAT_ADD));
		instructions.put(PcodeInjectLibraryVu.VMADD,
						 new Pair<BiFunction<Long, String, String>, String>(
							InjectPayloadVu::getMultiplyOperationText3, FLOAT_ADD));
		instructions.put(PcodeInjectLibraryVu.VMADDBC,
						 new Pair<BiFunction<Long, String, String>, String>(
							InjectPayloadVu::getMultiplyOperationText3, FLOAT_ADD));
		instructions.put(PcodeInjectLibraryVu.VSUB,
						 new Pair<BiFunction<Long, String, String>, String>(
							InjectPayloadVu::getOperationText3, FLOAT_SUB));
		instructions.put(PcodeInjectLibraryVu.VSUBBC,
						 new Pair<BiFunction<Long, String, String>, String>(
							InjectPayloadVu::getOperationText3, FLOAT_SUB));
		instructions.put(PcodeInjectLibraryVu.VMUL,
						 new Pair<BiFunction<Long, String, String>, String>(
							InjectPayloadVu::getOperationText3, FLOAT_MUL));
		instructions.put(PcodeInjectLibraryVu.VMULBC,
						 new Pair<BiFunction<Long, String, String>, String>(
							InjectPayloadVu::getOperationText3, FLOAT_MUL));
		instructions.put(PcodeInjectLibraryVu.VMSUB,
						 new Pair<BiFunction<Long, String, String>, String>(
							InjectPayloadVu::getMultiplyOperationText3, FLOAT_SUB));
		instructions.put(PcodeInjectLibraryVu.VMSUBBC,
						 new Pair<BiFunction<Long, String, String>, String>(
							InjectPayloadVu::getMultiplyOperationText3, FLOAT_SUB));
		instructions.put(PcodeInjectLibraryVu.VFTOI0,
						 new Pair<BiFunction<Long, String, String>, String>(
							InjectPayloadVu::getOperationText1, TRUNC));
		instructions.put(PcodeInjectLibraryVu.VFTOI,
						 new Pair<BiFunction<Long, String, String>, String>(
							InjectPayloadVu::getOperationText1, FLOAT2FLOAT));
		instructions.put(PcodeInjectLibraryVu.VITOF,
						 new Pair<BiFunction<Long, String, String>, String>(
							InjectPayloadVu::getOperationText1, INT2FLOAT));
		instructions.put(PcodeInjectLibraryVu.VULQ,
						 new Pair<BiFunction<Long, String, String>, String>(
							InjectPayloadVu::getLoadText, null));
		instructions.put(PcodeInjectLibraryVu.VUSQ,
						 new Pair<BiFunction<Long, String, String>, String>(
							InjectPayloadVu::getStoreText, null));
		instructions.put(PcodeInjectLibraryVu.VMAX,
						 new Pair<BiFunction<Long, String, String>, String>(
							InjectPayloadVu::getMaxText, null));
		instructions.put(PcodeInjectLibraryVu.VMAXBC,
						 new Pair<BiFunction<Long, String, String>, String>(
							InjectPayloadVu::getMaxText, null));
		instructions.put(PcodeInjectLibraryVu.VMIN,
						 new Pair<BiFunction<Long, String, String>, String>(
							InjectPayloadVu::getMinText, null));
		instructions.put(PcodeInjectLibraryVu.VMINBC,
						 new Pair<BiFunction<Long, String, String>, String>(
							InjectPayloadVu::getMinText, null));
		instructions.put(PcodeInjectLibraryVu.VMFIR,
						 new Pair<BiFunction<Long, String, String>, String>(
							InjectPayloadVu::getMFIRText, null));
		instructions.put(PcodeInjectLibraryVu.VMOVE,
						 new Pair<BiFunction<Long, String, String>, String>(
							InjectPayloadVu::getMoveText, null));
		instructions.put(PcodeInjectLibraryVu.VMOVEBC,
						 new Pair<BiFunction<Long, String, String>, String>(
							InjectPayloadVu::getMoveText, null));
		instructions.put(PcodeInjectLibraryVu.VMR32,
						 new Pair<BiFunction<Long, String, String>, String>(
							InjectPayloadVu::getMoveRotateText, null));
		return Collections.unmodifiableMap(instructions);
    }
}
