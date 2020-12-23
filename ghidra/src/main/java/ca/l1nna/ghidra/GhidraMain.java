package ca.l1nna.ghidra;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.LongStream;

import ghidra.util.InvalidNameException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.VersionException;

public class GhidraMain {

    public static void main(String[] args) {
        if (args.length > 0) {
            String bin = args[0];
            String json = args[1];
            String ghidra_project = args[2];
            boolean decompiled = args.length > 3 ? Boolean.parseBoolean(args[3]) : true;
            String functionBoundaryDefnitions = args.length > 4 ? args[4] : "";

            List<Long> functionStarts = new ArrayList<>();
            if (functionBoundaryDefnitions.length() > 1) {
                try {
                    functionStarts = Files.readAllLines(Paths.get(functionBoundaryDefnitions)).stream()
                            .map(l -> Long.parseLong(l)).collect(Collectors.toList());
                } catch (Exception e) {
                    System.out.println(
                            "Provided function boundaries but cannot be paresed: " + functionBoundaryDefnitions);
                    System.out.println(e.getMessage());
                    e.printStackTrace();
                }
            }

            GhidraDecompiler decompiler;
            try {
                decompiler = new GhidraDecompiler(bin, ghidra_project, decompiled, functionStarts);
                decompiler.dump(json);
                decompiler.close();
            } catch (VersionException | CancelledException | DuplicateNameException | InvalidNameException
                    | IOException e) {
                e.printStackTrace();
            }
        }

    }
}