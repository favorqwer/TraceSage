package util.llm;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import model.EntityNode;
import model.EventEdge;
import org.jgrapht.graph.DirectedPseudograph;

/** Line-oriented parser for the active semantic repair agent protocol. */
final class LlmSemanticRepairLineParser {
   private LlmSemanticRepairLineParser() { }

   static GraphAssessment parseAssessment(String response, AttackTacticKnowledge knowledge,
      DirectedPseudograph<EntityNode, EventEdge> universe, int maxGaps) {
      MutableDiagnostics diagnostics = new MutableDiagnostics();
      String rawText = response == null ? "" : response;
      Set<Long> edgeIds = new LinkedHashSet<>();
      Set<Long> nodeIds = new LinkedHashSet<>();
      if (universe != null) {
         for (EntityNode node : universe.vertexSet()) nodeIds.add(node.getId());
         for (EventEdge edge : universe.edgeSet()) edgeIds.add(edge.getID());
      }

      List<GraphAssessment.ObservedTactic> observed = new ArrayList<>();
      List<GraphAssessment.StorySegment> segments = new ArrayList<>();
      List<GraphAssessment.Gap> gaps = new ArrayList<>();
      Set<String> gapIds = new LinkedHashSet<>();
      String summary = "";

      for (String rawLine : rawText.split("\\R", -1)) {
         String line = rawLine.trim();
         if (line.isEmpty() || "END".equalsIgnoreCase(line)) continue;
         if (startsWith(line, "SUMMARY")) {
            String value = remainder(line, "SUMMARY");
            if (value.isEmpty()) { diagnostics.ignoredLines++; continue; }
            summary = value;
            diagnostics.validLines++;
            continue;
         }
         if (startsWith(line, "TACTIC")) {
            String[] fields = splitFields(line, "TACTIC", 2);
            if (fields == null || !knowledge.isValidTactic(fields[0])) { diagnostics.ignoredLines++; continue; }
            observed.add(new GraphAssessment.ObservedTactic(fields[0], parseKnownIds(fields[1], edgeIds)));
            diagnostics.validLines++;
            continue;
         }
         if (startsWith(line, "SEGMENT")) {
            String[] fields = splitFields(line, "SEGMENT", 3);
            if (fields == null || !knowledge.isValidTactic(fields[0]) || !knowledge.isValidTactic(fields[1])) {
               diagnostics.ignoredLines++; continue;
            }
            segments.add(new GraphAssessment.StorySegment(fields[0], fields[1], parseKnownIds(fields[2], edgeIds)));
            diagnostics.validLines++;
            continue;
         }
         if (startsWith(line, "GAP")) {
            int separator = line.indexOf("::");
            if (separator < 0) { diagnostics.ignoredLines++; continue; }
            String[] fields = splitFields(line.substring(0, separator).trim(), "GAP", 5);
            if (fields == null || !knowledge.isValidTactic(fields[1]) || !knowledge.isValidTactic(fields[2])) {
               diagnostics.ignoredLines++; continue;
            }
            if (gaps.size() >= Math.max(0, maxGaps) || !gapIds.add(fields[0])) {
               diagnostics.ignoredLines++; continue;
            }
            Double priority = parsePriority(fields[3]);
            if (priority == null) { diagnostics.ignoredLines++; continue; }
            List<Long> anchors = parseKnownIds(fields[4], nodeIds);
            String description = line.substring(separator + 2).trim();
            gaps.add(new GraphAssessment.Gap(fields[0], fields[1], fields[2], description, anchors, priority.doubleValue()));
            diagnostics.validLines++;
            continue;
         }
         diagnostics.ignoredLines++;
      }
      return new GraphAssessment(observed, segments, gaps, summary, rawText, diagnostics.freeze());
   }

   static RepairDecision parseSelection(String response, GraphAssessment assessment, int maxRank, int maxSelected) {
      MutableDiagnostics diagnostics = new MutableDiagnostics();
      String rawText = response == null ? "" : response;
      Set<String> knownGaps = new LinkedHashSet<>();
      if (assessment != null) for (GraphAssessment.Gap gap : assessment.getGaps()) knownGaps.add(gap.getGapId());
      Map<String, SelectionBuilder> selections = new LinkedHashMap<>();
      Set<Integer> seenRanks = new LinkedHashSet<>();
      int selectedCount = 0;
      for (String rawLine : rawText.split("\\R", -1)) {
         String line = rawLine.trim();
         if (line.isEmpty() || "END".equalsIgnoreCase(line)) continue;
         if (startsWith(line, "SELECT")) {
            int separator = line.indexOf("::");
            if (separator < 0) { diagnostics.ignoredLines++; continue; }
            String[] fields = splitFields(line.substring(0, separator).trim(), "SELECT", 2);
            Integer rank = parseRank(fields == null ? null : fields[1], maxRank);
            if (fields == null || !knownGaps.contains(fields[0]) || rank == null || selectedCount >= Math.max(0, maxSelected) || !seenRanks.add(rank)) {
               diagnostics.ignoredLines++; continue;
            }
            SelectionBuilder builder = selections.get(fields[0]);
            if (builder == null) { builder = new SelectionBuilder(fields[0]); selections.put(fields[0], builder); }
            builder.ranks.add(rank);
            builder.reason = appendReason(builder.reason, line.substring(separator + 2).trim());
            selectedCount++;
            diagnostics.validLines++;
            continue;
         }
         if (startsWith(line, "UNRESOLVED")) {
            int separator = line.indexOf("::");
            if (separator < 0) { diagnostics.ignoredLines++; continue; }
            String[] fields = splitFields(line.substring(0, separator).trim(), "UNRESOLVED", 1);
            if (fields == null || !knownGaps.contains(fields[0])) { diagnostics.ignoredLines++; continue; }
            SelectionBuilder builder = selections.get(fields[0]);
            if (builder == null) { builder = new SelectionBuilder(fields[0]); selections.put(fields[0], builder); }
            builder.reason = appendReason(builder.reason, line.substring(separator + 2).trim());
            diagnostics.validLines++;
            continue;
         }
         diagnostics.ignoredLines++;
      }
      List<RepairDecision.Selection> result = new ArrayList<>();
      for (SelectionBuilder builder : selections.values()) {
         result.add(new RepairDecision.Selection(builder.gapId, builder.ranks, builder.reason));
      }
      return new RepairDecision(result, rawText, diagnostics.freeze());
   }

   private static boolean startsWith(String line, String keyword) {
      return line.equalsIgnoreCase(keyword) || line.regionMatches(true, 0, keyword + " ", 0, keyword.length() + 1);
   }

   private static String remainder(String line, String keyword) {
      return line.length() <= keyword.length() ? "" : line.substring(keyword.length()).trim();
   }

   private static String[] splitFields(String line, String keyword, int expected) {
      String rest = remainder(line, keyword);
      if (rest.isEmpty()) return null;
      String[] fields = rest.split("\\s+", expected);
      return fields.length == expected ? fields : null;
   }

   private static Integer parseRank(String value, int maxRank) {
      if (value == null || value.trim().isEmpty()) return null;
      String normalized = value.trim();
      if (!normalized.matches("C\\d{3,}")) return null;
      try {
         int rank = Integer.parseInt(normalized.substring(1));
         return rank >= 1 && rank <= maxRank ? Integer.valueOf(rank) : null;
      } catch (NumberFormatException ex) {
         return null;
      }
   }

   private static Double parsePriority(String value) {
      if (value == null) return null;
      String normalized = value.trim().toLowerCase();
      if ("high".equals(normalized)) return Double.valueOf(1.0d);
      if ("medium".equals(normalized)) return Double.valueOf(0.5d);
      if ("low".equals(normalized)) return Double.valueOf(0.0d);
      try {
         double parsed = Double.parseDouble(normalized);
         return parsed >= 0.0d && parsed <= 1.0d ? Double.valueOf(parsed) : null;
      } catch (NumberFormatException ex) {
         return null;
      }
   }

   private static List<Long> parseKnownIds(String value, Set<Long> known) {
      if (value == null || value.trim().isEmpty() || "-".equals(value.trim())) return Collections.emptyList();
      List<Long> result = new ArrayList<>();
      for (String token : value.split(",")) {
         try {
            long id = Long.parseLong(token.trim());
            if (known.contains(id) && !result.contains(id)) result.add(id);
         } catch (NumberFormatException ignored) { }
      }
      return result;
   }

   private static String appendReason(String current, String next) {
      if (next == null || next.isEmpty()) return current == null ? "" : current;
      if (current == null || current.isEmpty()) return next;
      return current + "; " + next;
   }

   static final class ParseDiagnostics {
      private final int validLines;
      private final int ignoredLines;
      ParseDiagnostics(int validLines, int ignoredLines) { this.validLines = validLines; this.ignoredLines = ignoredLines; }
      int getValidLines() { return validLines; }
      int getIgnoredLines() { return ignoredLines; }
   }

   private static final class MutableDiagnostics {
      int validLines;
      int ignoredLines;
      ParseDiagnostics freeze() { return new ParseDiagnostics(validLines, ignoredLines); }
   }

   private static final class SelectionBuilder {
      final String gapId;
      final List<Integer> ranks = new ArrayList<>();
      String reason = "";
      SelectionBuilder(String gapId) { this.gapId = gapId; }
   }
}
