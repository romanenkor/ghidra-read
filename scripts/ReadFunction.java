// Export static evidence for one explicitly selected function.
//@category Firmware

import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.util.exception.CancelledException;

public class ReadFunction extends GhidraScript {
    private static final int DECOMPILE_SECONDS = 30;
    private static final int TEXT_LIMIT = 32_768;
    private static final int STRING_LIMIT = 2_048;

    private interface Section {
        JsonObject read() throws CancelledException;
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 4 || currentProgram == null) {
            throw new IllegalArgumentException("Expected an imported program and output, selector kind, selector, limit");
        }
        int limit = Integer.parseInt(args[3]);
        if (limit < 1 || limit > 1000) {
            throw new IllegalArgumentException("Evidence limit must be between 1 and 1000");
        }

        JsonObject result = new JsonObject();
        result.addProperty("schema_version", 1);
        result.add("program", programIdentity());
        JsonObject selector = new JsonObject();
        selector.addProperty("kind", args[1]);
        selector.addProperty("value", args[2]);
        result.add("selector", selector);

        Map<Address, Function> matches = select(args[1], args[2], Math.max(2, limit) + 1);
        if (matches.isEmpty()) {
            result.addProperty("status", "not_found");
        }
        else if (matches.size() > 1) {
            result.addProperty("status", "ambiguous");
            JsonArray candidates = new JsonArray();
            for (Function function : matches.values()) {
                if (candidates.size() == limit) {
                    break;
                }
                candidates.add(functionIdentity(function));
            }
            result.add("candidates", candidates);
            result.addProperty("candidates_truncated", matches.size() > limit);
        }
        else {
            Function function = matches.values().iterator().next();
            result.addProperty("status", "ok");
            result.add("function", functionIdentity(function));
            JsonObject sections = new JsonObject();
            sections.add("assembly", readSection(() -> assembly(function, limit)));
            sections.add("decompile", readSection(() -> decompile(function)));
            sections.add("xrefs", readSection(() -> xrefs(function, limit)));
            sections.add("strings", readSection(() -> strings(function, limit)));
            result.add("sections", sections);
        }

        try (Writer writer = Files.newBufferedWriter(Path.of(args[0]))) {
            new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create().toJson(result, writer);
        }
    }

    private JsonObject programIdentity() {
        JsonObject program = new JsonObject();
        program.addProperty("name", currentProgram.getName());
        program.addProperty("sha256", currentProgram.getExecutableSHA256());
        program.addProperty("ghidra_version", Application.getApplicationVersion());
        program.addProperty("language_id", currentProgram.getLanguageID().toString());
        program.addProperty("architecture", currentProgram.getLanguage().getProcessor().toString());
        program.addProperty("format", currentProgram.getExecutableFormat());
        program.addProperty("image_base", virtualAddress(currentProgram.getImageBase()));
        return program;
    }

    private static String virtualAddress(Address address) {
        return "0x" + Long.toUnsignedString(address.getUnsignedOffset(), 16);
    }

    private static JsonObject functionIdentity(Function function) {
        JsonObject identity = new JsonObject();
        Address entry = function.getEntryPoint();
        identity.addProperty("name", function.getName());
        identity.addProperty("qualified_name", function.getSymbol().getName(true));
        identity.addProperty("address", entry.toString(true));
        identity.addProperty("entry_va", virtualAddress(entry));
        return identity;
    }

    private Address parseEntryAddress(String value) {
        if (!value.matches("(?i)(?:0x)?[0-9a-f]{1,16}")) {
            throw new IllegalArgumentException("Expected a hexadecimal Ghidra virtual address");
        }
        String hex = value.replaceFirst("(?i)^0x", "");
        long offset = Long.parseUnsignedLong(hex, 16);
        try {
            return currentProgram.getAddressFactory().getDefaultAddressSpace()
                .getAddressInThisSpaceOnly(offset);
        }
        catch (AddressOutOfBoundsException error) {
            return null;
        }
    }

    private Map<Address, Function> select(String kind, String value, int maximum)
            throws CancelledException {
        Map<Address, Function> matches = new LinkedHashMap<>();
        var manager = currentProgram.getFunctionManager();
        if (kind.equals("address")) {
            Address address = parseEntryAddress(value);
            Function function = address == null ? null : manager.getFunctionAt(address);
            if (function != null) {
                matches.put(function.getEntryPoint(), function);
            }
            return matches;
        }
        if (!kind.equals("symbol") || value.isBlank()) {
            throw new IllegalArgumentException("Expected an exact symbol or a hexadecimal address");
        }
        int separator = value.lastIndexOf("::");
        String name = value.substring(separator < 0 ? 0 : separator + 2);
        SymbolIterator symbols = currentProgram.getSymbolTable().getSymbols(name);
        while (symbols.hasNext() && matches.size() < maximum) {
            monitor.checkCancelled();
            Symbol symbol = symbols.next();
            if (separator >= 0 && !symbol.getName(true).equals(value)) {
                continue;
            }
            Function function = manager.getFunctionAt(symbol.getAddress());
            if (function != null) {
                matches.putIfAbsent(function.getEntryPoint(), function);
            }
        }
        return matches;
    }

    private JsonObject readSection(Section section) throws CancelledException {
        try {
            monitor.checkCancelled();
            return section.read();
        }
        catch (RuntimeException error) {
            return status("failed", error.toString());
        }
    }

    private static JsonObject status(String status, String reason) {
        JsonObject section = new JsonObject();
        section.addProperty("status", status);
        if (reason != null && !reason.isBlank()) {
            section.addProperty("reason", reason);
        }
        return section;
    }

    private static JsonObject listSection(JsonArray data, boolean truncated) {
        JsonObject section = truncated ? status("truncated", "Evidence limit reached") : status("ok", null);
        section.add("data", data);
        return section;
    }

    private static String limitText(String value, int maximum) {
        if (value.length() <= maximum) {
            return value;
        }
        int end = maximum;
        if (Character.isSurrogatePair(value.charAt(end - 1), value.charAt(end))) {
            end--;
        }
        return value.substring(0, end);
    }

    private InstructionIterator instructions(Function function) {
        return currentProgram.getListing().getInstructions(function.getBody(), true);
    }

    private JsonObject assembly(Function function, int limit) throws CancelledException {
        if (function.isExternal()) {
            return status("unavailable", "External function has no local instructions");
        }
        JsonArray data = new JsonArray();
        InstructionIterator instructions = instructions(function);
        while (instructions.hasNext() && data.size() < limit) {
            monitor.checkCancelled();
            Instruction instruction = instructions.next();
            JsonObject row = new JsonObject();
            row.addProperty("address", instruction.getAddress().toString(true));
            row.addProperty("text", instruction.toString());
            data.add(row);
        }
        return listSection(data, instructions.hasNext());
    }

    private JsonObject decompile(Function function) throws CancelledException {
        if (function.isExternal()) {
            return status("unavailable", "External function has no local body");
        }
        DecompInterface decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(currentProgram)) {
                return status("failed", decompiler.getLastMessage());
            }
            DecompileResults results = decompiler.decompileFunction(function, DECOMPILE_SECONDS, monitor);
            monitor.checkCancelled();
            if (!results.decompileCompleted() || results.getDecompiledFunction() == null) {
                String reason = results.isTimedOut() ? "Decompile timed out" : results.getErrorMessage();
                return status("failed", reason == null || reason.isBlank() ? "No decompile result" : reason);
            }
            String code = results.getDecompiledFunction().getC();
            boolean truncated = code.length() > TEXT_LIMIT;
            JsonObject section = truncated
                ? status("truncated", "Decompile text limit reached") : status("ok", null);
            section.addProperty("data", limitText(code, TEXT_LIMIT));
            return section;
        }
        finally {
            decompiler.dispose();
        }
    }

    private static JsonObject referenceRow(Reference reference) {
        JsonObject row = new JsonObject();
        row.addProperty("from", reference.getFromAddress().toString(true));
        row.addProperty("to", reference.getToAddress().toString(true));
        row.addProperty("type", reference.getReferenceType().toString());
        row.addProperty("source", reference.getSource().toString());
        row.addProperty("operand", reference.getOperandIndex());
        return row;
    }

    private JsonObject xrefs(Function function, int limit) throws CancelledException {
        JsonArray incoming = new JsonArray();
        JsonArray outgoing = new JsonArray();
        var manager = currentProgram.getReferenceManager();
        ReferenceIterator toEntry = manager.getReferencesTo(function.getEntryPoint());
        while (toEntry.hasNext() && incoming.size() < limit) {
            monitor.checkCancelled();
            incoming.add(referenceRow(toEntry.next()));
        }

        boolean outgoingTruncated = false;
        if (!function.isExternal()) {
            InstructionIterator instructions = instructions(function);
            outer:
            while (instructions.hasNext()) {
                monitor.checkCancelled();
                for (Reference reference : instructions.next().getReferencesFrom()) {
                    if (outgoing.size() == limit) {
                        outgoingTruncated = true;
                        break outer;
                    }
                    outgoing.add(referenceRow(reference));
                }
            }
        }

        boolean incomingTruncated = toEntry.hasNext();
        JsonObject data = new JsonObject();
        data.add("incoming", incoming);
        data.add("outgoing", outgoing);
        data.addProperty("incoming_truncated", incomingTruncated);
        data.addProperty("outgoing_truncated", outgoingTruncated);
        JsonObject section = incomingTruncated || outgoingTruncated
            ? status("truncated", "Evidence limit reached") : status("ok", null);
        section.addProperty("incoming_scope", "function entry");
        section.addProperty("outgoing_scope", "instructions in the function body");
        section.add("data", data);
        return section;
    }

    private JsonObject strings(Function function, int limit) throws CancelledException {
        if (function.isExternal()) {
            return status("unavailable", "External function has no local instructions");
        }
        JsonArray data = new JsonArray();
        boolean truncated = false;
        InstructionIterator instructions = instructions(function);
        outer:
        while (instructions.hasNext()) {
            monitor.checkCancelled();
            for (Reference reference : instructions.next().getReferencesFrom()) {
                Address address = reference.getToAddress();
                if (!address.isMemoryAddress()) {
                    continue;
                }
                Data item = currentProgram.getListing().getDefinedDataContaining(address);
                if (item == null || !StringDataInstance.isString(item)) {
                    continue;
                }
                StringDataInstance string = StringDataInstance.getStringDataInstance(item);
                if (!item.getAddress().equals(address)) {
                    string = string.getByteOffcut((int) address.subtract(item.getAddress()));
                }
                String value = string.getStringValue();
                if (value == null) {
                    continue;
                }
                if (data.size() == limit) {
                    truncated = true;
                    break outer;
                }
                JsonObject row = referenceRow(reference);
                boolean shortened = value.length() > STRING_LIMIT;
                row.addProperty("value", limitText(value, STRING_LIMIT));
                row.addProperty("value_truncated", shortened);
                data.add(row);
                truncated |= shortened;
            }
        }
        return listSection(data, truncated);
    }
}
