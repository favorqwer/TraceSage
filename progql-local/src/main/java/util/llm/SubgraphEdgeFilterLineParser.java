package util.llm;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Parses the batch protocol used by process-subgraph filtering. */
final class SubgraphEdgeFilterLineParser {
   private static final Pattern DROP = Pattern.compile("^DROP\\s+(\\d+)\\s+::\\s+(\\S(?:.*\\S)?)$", Pattern.CASE_INSENSITIVE);

   private SubgraphEdgeFilterLineParser() { }

   static ParseResult parse(String response, Set<Long> ownedEdgeIds, Set<Long> contextEdgeIds) {
      Map<Long, String> drops = new LinkedHashMap<>();
      Map<Long, String> rejectedDrops = new LinkedHashMap<>();
      Set<Long> owned = ownedEdgeIds == null ? Collections.<Long>emptySet() : ownedEdgeIds;
      Set<Long> context = contextEdgeIds == null ? Collections.<Long>emptySet() : contextEdgeIds;
      int invalid = 0;
      int outsideBatch = 0;
      int contextOnly = 0;
      int duplicate = 0;
      boolean decisionsSeen = false;
      boolean decisionLineSeen = false;
      boolean summarySeen = false;
      boolean noDropSeen = false;
      boolean structuralProtocolError = false;
      String summary = "";

      String[] lines = response == null ? new String[0] : response.replace("\r", "").split("\n");
      for (String raw : lines) {
         String line = raw == null ? "" : raw.trim();
         if (line.isEmpty()) continue;
         if ("DECISIONS".equalsIgnoreCase(line)) {
            if (decisionsSeen || summarySeen) structuralProtocolError = true;
            decisionsSeen = true;
            continue;
         }
         if (line.regionMatches(true, 0, "UPDATED_SUMMARY", 0, "UPDATED_SUMMARY".length())) {
            if (!decisionsSeen || summarySeen) structuralProtocolError = true;
            summarySeen = true;
            String inlineSummary = line.substring("UPDATED_SUMMARY".length()).trim();
            if (!inlineSummary.isEmpty()) summary = inlineSummary;
            continue;
         }
         if (!decisionsSeen || summarySeen) {
            if (summarySeen && summary.isEmpty()) summary = line;
            else structuralProtocolError = true;
            continue;
         }
         if ("NO_DROP".equalsIgnoreCase(line)) {
            if (noDropSeen || !drops.isEmpty()) structuralProtocolError = true;
            noDropSeen = true;
            decisionLineSeen = true;
            continue;
         }
         Matcher matcher = DROP.matcher(line);
         if (!matcher.matches()) {
            invalid++;
            continue;
         }
         if (noDropSeen) {
            structuralProtocolError = true;
            continue;
         }
         decisionLineSeen = true;
         long edgeId;
         try {
            edgeId = Long.parseLong(matcher.group(1));
         } catch (NumberFormatException ex) {
            invalid++;
            structuralProtocolError = true;
            continue;
         }
         if (context.contains(edgeId) && !owned.contains(edgeId)) {
            contextOnly++;
            rejectedDrops.put(edgeId, "rejected_context_edge");
            continue;
         }
         if (!owned.contains(edgeId)) {
            outsideBatch++;
            rejectedDrops.put(edgeId, "rejected_outside_owned_batch");
            continue;
         }
         if (drops.containsKey(edgeId)) {
            duplicate++;
            rejectedDrops.put(edgeId, "rejected_duplicate_drop");
            continue;
         }
         drops.put(edgeId, matcher.group(2).trim());
      }
      if (!decisionsSeen || !summarySeen || !decisionLineSeen) structuralProtocolError = true;
      return new ParseResult(drops, rejectedDrops, summary, invalid, outsideBatch, contextOnly, duplicate, !structuralProtocolError);
   }

   static final class ParseResult {
      private final Map<Long, String> drops;
      private final Map<Long, String> rejectedDrops;
      private final String updatedSummary;
      private final int invalidLineCount;
      private final int outsideBatchIdCount;
      private final int contextOnlyIdCount;
      private final int duplicateDropCount;
      private final boolean validProtocol;

      private ParseResult(Map<Long, String> drops, Map<Long, String> rejectedDrops, String updatedSummary, int invalidLineCount, int outsideBatchIdCount,
         int contextOnlyIdCount, int duplicateDropCount, boolean validProtocol) {
         this.drops = Collections.unmodifiableMap(new LinkedHashMap<>(drops));
         this.rejectedDrops = Collections.unmodifiableMap(new LinkedHashMap<>(rejectedDrops));
         this.updatedSummary = updatedSummary == null ? "" : updatedSummary;
         this.invalidLineCount = invalidLineCount;
         this.outsideBatchIdCount = outsideBatchIdCount;
         this.contextOnlyIdCount = contextOnlyIdCount;
         this.duplicateDropCount = duplicateDropCount;
         this.validProtocol = validProtocol;
      }

      Map<Long, String> getDrops() { return this.drops; }
      Map<Long, String> getRejectedDrops() { return this.rejectedDrops; }
      String getUpdatedSummary() { return this.updatedSummary; }
      int getInvalidLineCount() { return this.invalidLineCount; }
      int getOutsideBatchIdCount() { return this.outsideBatchIdCount; }
      int getContextOnlyIdCount() { return this.contextOnlyIdCount; }
      int getDuplicateDropCount() { return this.duplicateDropCount; }
      boolean isValidProtocol() { return this.validProtocol; }
   }
}
