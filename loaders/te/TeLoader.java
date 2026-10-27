package teloader;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramLoader;
import ghidra.app.util.opinion.LoadException;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loaded;
import ghidra.app.util.opinion.LoaderTier;
import ghidra.framework.model.Project;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Ghidra loader for UEFI TE (Terse Executable) images ("VZ" magic).
 *
 * <p>TE is a stripped PE: the PE headers are removed and the sections are packed
 * right after a 40-byte TE header plus the section table. Section RVAs and the
 * entry point are stored EXACTLY as in the original PE for EDK2 GenFw output
 * (verified on QemuVideoDxe.te vs its PE twin: identical VAs and entry point),
 * so sections load at ImageBase + VirtualAddress and the entry point is
 * ImageBase + AddressOfEntryPoint, matching how EDK2 loads TE images at runtime.
 * No bytes are invented: sections map exactly from file bytes, and stripped
 * fields (e.g. the debug directory) are simply absent.
 *
 * <p>Soundness rules: the image base and entry point come from the TE header,
 * never guessed. Any structural problem (bad magic, unsupported machine,
 * truncated section table, section extending past end-of-file, entry point
 * outside every section) fails the import with a LoadException — never a
 * partial or shifted program. Relocations are NOT applied: the image is loaded
 * at its header ImageBase, so no relocation is needed (same as the PE loader
 * when the load base matches).
 */
public class TeLoader extends AbstractProgramLoader {

	public static final String TE_NAME = "Terse Executable (TE)";
	public static final String TE_LOADER_VERSION = "1";

	private static final int TE_HEADER_SIZE = 40;
	private static final int SECTION_HEADER_SIZE = 40;
	private static final int MAX_SECTIONS = 96;

	private static final int MACHINE_X86_64 = 0x8664;
	private static final int MACHINE_X86_32 = 0x014c;

	private static final long IMAGE_SCN_MEM_EXECUTE = 0x20000000L;
	private static final long IMAGE_SCN_MEM_READ = 0x40000000L;
	private static final long IMAGE_SCN_MEM_WRITE = 0x80000000L;

	/** One TE section header, parsed verbatim from the file. */
	private static class Section {
		String name;
		long virtualSize;
		long virtualAddress;
		long rawSize;
		long rawPtr;
		long characteristics;
	}

	/** A parsed TE header plus its section table. */
	private static class TeHeader {
		int machine;
		int numSections;
		int subsystem;
		int strippedSize;
		long entryPoint;
		long baseOfCode;
		long imageBase;
		long relocVa;
		long relocSize;
		List<Section> sections = new ArrayList<>();
	}

	@Override
	public String getName() {
		return TE_NAME;
	}

	@Override
	public LoaderTier getTier() {
		return LoaderTier.SPECIALIZED_TARGET_LOADER;
	}

	@Override
	public int getTierPriority() {
		return 10;
	}

	@Override
	public java.util.Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider)
			throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		if (provider.length() < TE_HEADER_SIZE) {
			return loadSpecs;
		}
		BinaryReader reader = new BinaryReader(provider, true);
		byte b0 = reader.readNextByte();
		byte b1 = reader.readNextByte();
		if (b0 != 'V' || b1 != 'Z') {
			return loadSpecs; // not a TE image; some other loader owns it
		}
		int machine = reader.readNextShort() & 0xffff;
		LanguageCompilerSpecPair pair = pairForMachine(machine);
		if (pair == null) {
			return loadSpecs; // known TE magic, unsupported machine: do not claim
		}
		// ImageBase sits at offset 16: skip the 12 bytes between the machine
		// field (offset 4) and it (sections/subsystem/stripped/entry/baseOfCode).
		reader.readNextByteArray(12);
		long imageBase = reader.readNextLong();
		if (imageBase < 0) {
			return loadSpecs; // pathological base; refuse rather than guess
		}
		loadSpecs.add(new LoadSpec(this, imageBase, pair, true));
		return loadSpecs;
	}

	@Override
	protected List<Loaded<Program>> loadProgram(ByteProvider provider, String programName,
			Project project, String programFolderPath, LoadSpec loadSpec, List<Option> options,
			MessageLog log, Object consumer, TaskMonitor monitor)
			throws IOException, LoadException, CancelledException {
		LanguageCompilerSpecPair pair = loadSpec.getLanguageCompilerSpec();
		Language language = getLanguageService().getLanguage(pair.languageID);
		CompilerSpec compilerSpec = language.getCompilerSpecByID(pair.compilerSpecID);

		Address baseAddr = language.getAddressFactory()
				.getDefaultAddressSpace()
				.getAddress(loadSpec.getDesiredImageBase());
		Program prog = createProgram(provider, programName, baseAddr, getName(), language,
			compilerSpec, consumer);
		List<Loaded<Program>> loadedList =
				List.of(new Loaded<>(prog, programName, programFolderPath));

		boolean success = false;
		try {
			// Final loadInto() opens the transaction and calls loadProgramInto().
			loadInto(provider, loadSpec, options, log, prog, monitor);
			success = true;
			return loadedList;
		}
		finally {
			if (!success) {
				release(loadedList, consumer);
			}
		}
	}

	@Override
	protected void loadProgramInto(ByteProvider provider, LoadSpec loadSpec,
			List<Option> options, MessageLog messageLog, Program program, TaskMonitor monitor)
			throws IOException, LoadException, CancelledException {
		TeHeader header = parse(provider);

		long desiredBase = loadSpec.getDesiredImageBase();
		long programBase = program.getImageBase().getOffset();
		if (programBase != desiredBase) {
			throw new LoadException("TE load-into refused: program image base 0x" +
				Long.toHexString(programBase) + " differs from TE header image base 0x" +
				Long.toHexString(desiredBase) + "; loading at a different base would " +
				"misplace every section");
		}

		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, provider, monitor);

		for (int i = 0; i < header.sections.size(); i++) {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}
			Section section = header.sections.get(i);
			String sectionName = section.name.isBlank() ? "SECTION." + i : section.name;
			boolean r = (section.characteristics & IMAGE_SCN_MEM_READ) != 0;
			boolean w = (section.characteristics & IMAGE_SCN_MEM_WRITE) != 0;
			boolean x = (section.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;

			long startOffset = addChecked(header.imageBase, section.virtualAddress,
				"section " + sectionName + " address");
			Address address = space.getAddress(startOffset);

			long dataSize = (section.rawSize > section.virtualSize && section.virtualSize > 0)
					? section.virtualSize
					: section.rawSize;
			MemoryBlock block = null;
			if (section.rawSize != 0 && section.rawPtr != 0) {
				try {
					block = MemoryBlockUtils.createInitializedBlock(program, false, sectionName,
						address, fileBytes, section.rawPtr, dataSize, "", "", r, w, x,
						messageLog);
				}
				catch (AddressOverflowException e) {
					throw new LoadException("TE section " + sectionName +
						" address range overflows the address space", e);
				}
				if (block == null) {
					throw new LoadException("TE section " + sectionName +
						" conflicts with an existing memory block at " + address);
				}
			}
			if (section.virtualSize > dataSize) {
				// Remainder of the virtual size is zero-filled (BSS-style tail).
				long remainder = section.virtualSize - dataSize;
				Address remainderAddress;
				try {
					remainderAddress = address.add(dataSize);
				}
				catch (AddressOutOfBoundsException e) {
					throw new LoadException("TE section " + sectionName +
						" virtual size overflows the address space", e);
				}
				if (block != null) {
					MemoryBlock paddingBlock = MemoryBlockUtils.createInitializedBlock(program,
						false, sectionName, remainderAddress, remainder, "", "", r, w, x,
						messageLog);
					if (paddingBlock != null) {
						try {
							program.getMemory().join(block, paddingBlock);
						}
						catch (Exception e) {
							messageLog.appendMsg("TE: could not join padding block for " +
								sectionName + ": " + e.getMessage());
						}
					}
					else {
						MemoryBlock tail = MemoryBlockUtils.createUninitializedBlock(program,
							false, sectionName, remainderAddress, remainder, "", "", r, w, x,
							messageLog);
						if (tail == null) {
							throw new LoadException("TE section " + sectionName +
								" zero-fill tail conflicts with an existing memory block");
						}
					}
				}
				else {
					MemoryBlock tail = MemoryBlockUtils.createUninitializedBlock(program, false,
						sectionName, remainderAddress, remainder, "", "", r, w, x, messageLog);
					if (tail == null) {
						throw new LoadException("TE section " + sectionName +
							" conflicts with an existing memory block at " + remainderAddress);
					}
				}
			}
			else if (section.rawSize == 0 && section.virtualSize > 0) {
				// Pure BSS section: no file bytes at all.
				MemoryBlock tail = MemoryBlockUtils.createUninitializedBlock(program, false,
					sectionName, address, section.virtualSize, "", "", r, w, x, messageLog);
				if (tail == null) {
					throw new LoadException("TE section " + sectionName +
						" conflicts with an existing memory block at " + address);
				}
			}
			else if (section.rawSize == 0 && section.virtualSize == 0) {
				messageLog.appendMsg("TE: skipping zero-size section " + sectionName);
			}
		}

		long entryOffset =
				addChecked(header.imageBase, header.entryPoint, "entry point");
		Address entryAddr = space.getAddress(entryOffset);
		boolean entryInSection = false;
		for (Section section : header.sections) {
			long span = Math.max(section.virtualSize, section.rawSize);
			if (span > 0 && header.entryPoint >= section.virtualAddress &&
				header.entryPoint < section.virtualAddress + span) {
				entryInSection = true;
				break;
			}
		}
		if (!entryInSection) {
			throw new LoadException("TE entry point 0x" + Long.toHexString(header.entryPoint) +
				" is not within any section");
		}
		program.getSymbolTable().addExternalEntryPoint(entryAddr);
		messageLog.appendMsg("TE loader v" + TE_LOADER_VERSION + ": " + header.sections.size() +
			" sections, image base 0x" + Long.toHexString(header.imageBase) + ", entry 0x" +
			Long.toHexString(header.entryPoint) + ", stripped size 0x" +
			Integer.toHexString(header.strippedSize));
	}

	/**
	 * Maps a TE machine field to a Ghidra language/compiler pair, or null.
	 * The compiler spec is "windows" for both: x86 languages have no "default"
	 * cspec (x86-64 offers windows/clangwindows/gcc/golang/swift), and "windows"
	 * is what Ghidra's PE loader picks for the PE twins of these drivers, so TE
	 * analysis matches PE analysis as closely as possible.
	 */
	private static LanguageCompilerSpecPair pairForMachine(int machine) {
		switch (machine) {
			case MACHINE_X86_64:
				return new LanguageCompilerSpecPair(new LanguageID("x86:LE:64:default"),
					new CompilerSpecID("windows"));
			case MACHINE_X86_32:
				return new LanguageCompilerSpecPair(new LanguageID("x86:LE:32:default"),
					new CompilerSpecID("windows"));
			default:
				return null;
		}
	}

	/** Adds two unsigned values, failing cleanly on overflow instead of wrapping. */
	private static long addChecked(long a, long b, String what) throws LoadException {
		if (b < 0 || a > Long.MAX_VALUE - b) {
			throw new LoadException("TE " + what + " overflows the address space");
		}
		return a + b;
	}

	/**
	 * Parses and fully validates the TE header and section table. Any structural
	 * problem throws LoadException with a specific message; nothing is loaded
	 * partially, so a failed import can never produce a shifted program.
	 */
	private static TeHeader parse(ByteProvider provider) throws IOException, LoadException {
		long length = provider.length();
		if (length < TE_HEADER_SIZE) {
			throw new LoadException(
				"File too small for a TE header (" + length + " bytes)");
		}
		BinaryReader reader = new BinaryReader(provider, true);
		byte b0 = reader.readNextByte();
		byte b1 = reader.readNextByte();
		if (b0 != 'V' || b1 != 'Z') {
			throw new LoadException("Not a TE image (bad magic 0x" +
				Integer.toHexString(((b1 & 0xff) << 8) | (b0 & 0xff)) + ")");
		}
		TeHeader header = new TeHeader();
		header.machine = reader.readNextShort() & 0xffff;
		if (pairForMachine(header.machine) == null) {
			throw new LoadException(
				"Unsupported TE machine 0x" + Integer.toHexString(header.machine));
		}
		header.numSections = reader.readNextByte() & 0xff;
		header.subsystem = reader.readNextByte() & 0xff;
		header.strippedSize = reader.readNextShort() & 0xffff;
		header.entryPoint = reader.readNextInt() & 0xffffffffL;
		header.baseOfCode = reader.readNextInt() & 0xffffffffL;
		header.imageBase = reader.readNextLong();
		if (header.imageBase < 0) {
			throw new LoadException("TE image base 0x" + Long.toHexString(header.imageBase) +
				" is out of range");
		}
		header.relocVa = reader.readNextInt() & 0xffffffffL;
		header.relocSize = reader.readNextInt() & 0xffffffffL;
		// Debug directory (VA + size) is read for completeness and ignored:
		// TE images strip it, and nothing downstream needs it.
		reader.readNextInt();
		reader.readNextInt();

		if (header.numSections < 1 || header.numSections > MAX_SECTIONS) {
			throw new LoadException(
				"Implausible TE section count " + header.numSections);
		}
		long tableEnd = (long) TE_HEADER_SIZE + (long) header.numSections * SECTION_HEADER_SIZE;
		if (tableEnd > length) {
			throw new LoadException("Truncated TE section table: needs " + tableEnd +
				" bytes, file is " + length + " bytes");
		}
		for (int i = 0; i < header.numSections; i++) {
			Section section = new Section();
			byte[] nameBytes = reader.readNextByteArray(8);
			int nul = 0;
			while (nul < nameBytes.length && nameBytes[nul] != 0) {
				nul++;
			}
			section.name = new String(nameBytes, 0, nul, StandardCharsets.US_ASCII);
			section.virtualSize = reader.readNextInt() & 0xffffffffL;
			section.virtualAddress = reader.readNextInt() & 0xffffffffL;
			section.rawSize = reader.readNextInt() & 0xffffffffL;
			section.rawPtr = reader.readNextInt() & 0xffffffffL;
			reader.readNextInt(); // PointerToRelocations (unused)
			reader.readNextInt(); // PointerToLinenumbers (unused)
			reader.readNextShort(); // NumberOfRelocations (unused)
			reader.readNextShort(); // NumberOfLinenumbers (unused)
			section.characteristics = reader.readNextInt() & 0xffffffffL;
			if (section.rawSize != 0 && section.rawPtr == 0) {
				throw new LoadException("TE section " + section.name +
					" has raw data size 0x" + Long.toHexString(section.rawSize) +
					" but a null raw data pointer (would map header bytes as section data)");
			}
			if (section.rawPtr > length || section.rawSize > length - section.rawPtr) {
				throw new LoadException("TE section " + section.name +
					" extends past end-of-file (rawPtr 0x" + Long.toHexString(section.rawPtr) +
					" + rawSize 0x" + Long.toHexString(section.rawSize) +
					" > file length 0x" + Long.toHexString(length) + ")");
			}
			header.sections.add(section);
		}
		return header;
	}
}
