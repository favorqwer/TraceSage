package util.llm;

import java.util.Collections;
import java.util.List;
import model.EntityNode;

public class LlmNoiseGraphPromptBuilder {
   public String buildCoreSystemPrompt() {
      return "You are judging noise inside a provenance graph for cyber attack investigation. "
         + "You will receive one or more selected attack-entry candidates, one anomaly node, and the full set of event edges from one attack provenance graph. "
         + "Treat all selected candidates as evidence for the graph's suspicious provenance story; do not assign them primary or auxiliary roles. "
         + "The anomaly node is the suspicious ending node or final abnormal artifact that this graph tries to explain. "
         + "Each event edge represents one observed provenance relation and is formatted as [node_type|signature]--event_type-->[node_type|signature]. "
         + "node_type is the node category, signature is the node identifier in the form id: signature, and event_type is the edge event such as read, write, execve, recvfrom, or sendto. "
         + "Your task is graph denoising, not graph reconstruction. "
         + "Internally classify every provided edge as KEEP, DROP, or UNCERTAIN. "
         + "Only report edges classified as DROP; do not report KEEP or UNCERTAIN edges. "
         + "Be conservative. If you are not confident an edge is noise, classify it as UNCERTAIN and omit it from the response. "
         + "Judge edges by causal role, not by executable name alone. "
         + "Only emphasize which noise categories should be removed. "
         + "Noise categories to remove include mirrored or reverse-direction provenance edges that only restate an already expressed execution relation without adding a distinct stage transition, downstream dependency, or handoff in the suspicious story, support-context edges that only show session plumbing or runtime scaffolding without introducing a new causal state change, environment or metadata lookup edges whose only role is setup or observation, bookkeeping or repetition edges that duplicate an already established artifact transformation, and residual edges that belong to stale or parallel context rather than the main suspicious story in this graph. "
         + "Do not treat a bidirectional pair by itself as proof that one direction is noise. "
         + "Do not drop an edge only because it involves a shell, interpreter, archive tool, or common system binary. "
         + "If an edge appears to advance execution, data movement, artifact creation, artifact transformation, or external communication, and you cannot clearly prove it is only redundant support context, label it UNCERTAIN instead of DROP. "
         + "Return only the required plain-text format. Do not use JSON. Do not use markdown fences.";
   }

   public String buildCoreUserPrompt(EntityNode entry, EntityNode anomalyNode, List<LlmNoiseGraphEdge> graphEdges) {
      return buildCoreUserPrompt(
         entry == null ? Collections.<EntityNode>emptyList() : Collections.singletonList(entry), anomalyNode, graphEdges
      );
   }

   public String buildCoreUserPrompt(List<EntityNode> entries, EntityNode anomalyNode, List<LlmNoiseGraphEdge> graphEdges) {
      StringBuilder builder = new StringBuilder();
      builder.append("Task: internally classify every edge in this provenance graph as KEEP, DROP, or UNCERTAIN, but report only DROP edges.")
         .append(System.lineSeparator())
         .append(System.lineSeparator())
         .append("Output format:")
         .append(System.lineSeparator())
         .append("DECISIONS")
         .append(System.lineSeparator())
         .append("DROP <edge_rank> :: <short reason>")
         .append(System.lineSeparator())
         .append("or, if no edge is dropped:")
         .append(System.lineSeparator())
         .append("NO_DROP")
         .append(System.lineSeparator())
         .append("SUMMARY <one short sentence>")
         .append(System.lineSeparator())
         .append(System.lineSeparator())
         .append("Rules:")
         .append(System.lineSeparator())
         .append("1. Internally assign KEEP, DROP, or UNCERTAIN to every provided edge_rank.")
         .append(System.lineSeparator())
         .append("2. Output only edges internally classified as DROP; omit KEEP and UNCERTAIN edges.")
         .append(System.lineSeparator())
         .append("3. If no edge is internally classified as DROP, output NO_DROP as the only line in DECISIONS.")
         .append(System.lineSeparator())
         .append("4. Every DROP line must exactly use DROP <edge_rank> :: <non-empty short reason>.")
         .append(System.lineSeparator())
         .append("5. Do not invent extra edge ranks, output KEEP or UNCERTAIN lines, or mix NO_DROP with DROP lines.")
         .append(System.lineSeparator())
         .append("6. The goal is to reduce noise in this graph, not to rewrite the graph.")
         .append(System.lineSeparator())
         .append("7. Judge each edge by its role in the causal story, not by process name or tool name alone.")
         .append(System.lineSeparator())
         .append("8. DROP only when the edge is clearly redundant, mirrored, bookkeeping-only, stale-context, or support-context without a meaningful state change.")
         .append(System.lineSeparator())
         .append("9. Do not classify an edge as mirrored or reverse-direction noise only because the opposite direction also exists; the dropped direction must be clearly only a restatement with no distinct stage transition, downstream dependency, or handoff.")
         .append(System.lineSeparator())
         .append("10. If the edge might represent real execution advancement, data movement, artifact creation, artifact transformation, or external communication, and you are not sure, classify it as UNCERTAIN and omit it.")
         .append(System.lineSeparator())
         .append("11. Do not output bullets, numbering prefixes, JSON, or prose inside DECISIONS other than DROP lines or NO_DROP.")
         .append(System.lineSeparator())
         .append("12. Keep the required SUMMARY section after DECISIONS.")
         .append(System.lineSeparator())
         .append(System.lineSeparator())
         .append("Selected attack-entry candidates:")
         .append(System.lineSeparator())
         ;
      appendSelectedEntries(builder, entries);
      builder
         .append(System.lineSeparator())
         .append("Anomaly node:")
         .append(System.lineSeparator())
         .append(formatNode(anomalyNode))
         .append(System.lineSeparator())
         .append(System.lineSeparator())
         .append("Field meanings:")
         .append(System.lineSeparator())
         .append("- node_type: File, Process, or Network")
         .append(System.lineSeparator())
         .append("- signature: node identifier in the form id: signature")
         .append(System.lineSeparator())
         .append("- event_type: provenance event on the edge")
         .append(System.lineSeparator())
         .append(System.lineSeparator())
         .append("Graph edges:")
         .append(System.lineSeparator());

      for (LlmNoiseGraphEdge graphEdge : graphEdges) {
         builder.append("Edge #").append(graphEdge.getEdgeRank()).append(System.lineSeparator());
         builder.append(graphEdge.getCompactEdgeString()).append(System.lineSeparator()).append(System.lineSeparator());
      }

      return builder.toString();
   }

   public String buildCoreUserPrompt(LlmAttackStoryContext context, List<LlmNoiseGraphEdge> graphEdges) {
      LlmAttackStoryContext safeContext = context == null
         ? LlmAttackStoryContext.fromSingleEntry(null, null)
         : context;
      return buildCoreUserPrompt(safeContext.getSelectedEntries(), safeContext.getAnomalyNode(), graphEdges);
   }

   public String buildCoreBatchUserPrompt(
      EntityNode entry,
      EntityNode anomalyNode,
      List<LlmNoiseGraphEdge> batchEdges,
      int batchIndex,
      int totalBatches,
      String previousSummary
   ) {
      return buildCoreBatchUserPrompt(
         entry == null ? Collections.<EntityNode>emptyList() : Collections.singletonList(entry),
         anomalyNode, batchEdges, batchIndex, totalBatches, previousSummary
      );
   }

   public String buildCoreBatchUserPrompt(
      List<EntityNode> entries,
      EntityNode anomalyNode,
      List<LlmNoiseGraphEdge> batchEdges,
      int batchIndex,
      int totalBatches,
      String previousSummary
   ) {
      StringBuilder builder = new StringBuilder();
      builder.append("Task: internally classify only CURRENT_BATCH edges as KEEP, DROP, or UNCERTAIN, report only DROP edges, then update the running graph summary.")
         .append(System.lineSeparator())
         .append(System.lineSeparator())
         .append("Output format:")
         .append(System.lineSeparator())
         .append("DECISIONS")
         .append(System.lineSeparator())
         .append("DROP <edge_rank> :: <short reason>")
         .append(System.lineSeparator())
         .append("or, if no edge is dropped:")
         .append(System.lineSeparator())
         .append("NO_DROP")
         .append(System.lineSeparator())
         .append("UPDATED_SUMMARY")
         .append(System.lineSeparator())
         .append("<concise cumulative summary of all processed batches so far>")
         .append(System.lineSeparator())
         .append(System.lineSeparator())
         .append("Rules:")
         .append(System.lineSeparator())
         .append("1. Internally classify every edge in CURRENT_BATCH as KEEP, DROP, or UNCERTAIN.")
         .append(System.lineSeparator())
         .append("2. Output only DROP edges from CURRENT_BATCH; omit KEEP and UNCERTAIN edges.")
         .append(System.lineSeparator())
         .append("3. If no edge is internally classified as DROP, output NO_DROP as the only line in DECISIONS.")
         .append(System.lineSeparator())
         .append("4. Every DROP line must exactly use DROP <edge_rank> :: <non-empty short reason>.")
         .append(System.lineSeparator())
         .append("5. Do not output decisions for edges outside CURRENT_BATCH, output KEEP or UNCERTAIN lines, or mix NO_DROP with DROP lines.")
         .append(System.lineSeparator())
         .append("6. Judge each edge by its role in the causal story, not by process name or tool name alone.")
         .append(System.lineSeparator())
         .append("7. DROP only when the edge is clearly redundant, mirrored, bookkeeping-only, stale-context, or support-context without a meaningful state change.")
         .append(System.lineSeparator())
         .append("8. Do not classify an edge as mirrored or reverse-direction noise only because the opposite direction also exists; the dropped direction must be clearly only a restatement with no distinct stage transition, downstream dependency, or handoff.")
         .append(System.lineSeparator())
         .append("9. If the edge might represent real execution advancement, data movement, artifact creation, artifact transformation, or external communication, and you are not sure, classify it as UNCERTAIN and omit it.")
         .append(System.lineSeparator())
         .append("10. UPDATED_SUMMARY must combine Previous running summary with evidence from CURRENT_BATCH.")
         .append(System.lineSeparator())
         .append("11. UPDATED_SUMMARY should preserve known attack stages, important artifacts, repeated noise patterns, and unresolved uncertain regions.")
         .append(System.lineSeparator())
         .append("12. Do not output bullets, numbering prefixes, JSON, or prose inside DECISIONS other than DROP lines or NO_DROP.")
         .append(System.lineSeparator())
         .append(System.lineSeparator())
         .append("Batch:")
         .append(System.lineSeparator())
         .append(batchIndex)
         .append(" of ")
         .append(totalBatches)
         .append(System.lineSeparator())
         .append(System.lineSeparator())
         .append("Selected attack-entry candidates:")
         .append(System.lineSeparator())
         ;
      appendSelectedEntries(builder, entries);
      builder
         .append(System.lineSeparator())
         .append("Anomaly node:")
         .append(System.lineSeparator())
         .append(formatNode(anomalyNode))
         .append(System.lineSeparator())
         .append(System.lineSeparator())
         .append("Previous running summary:")
         .append(System.lineSeparator())
         .append(previousSummary == null || previousSummary.trim().isEmpty() ? "<empty>" : previousSummary.trim())
         .append(System.lineSeparator())
         .append(System.lineSeparator())
         .append("Field meanings:")
         .append(System.lineSeparator())
         .append("- node_type: File, Process, or Network")
         .append(System.lineSeparator())
         .append("- signature: node identifier in the form id: signature")
         .append(System.lineSeparator())
         .append("- event_type: provenance event on the edge")
         .append(System.lineSeparator())
         .append(System.lineSeparator())
         .append("CURRENT_BATCH edges:")
         .append(System.lineSeparator());

      for (LlmNoiseGraphEdge graphEdge : batchEdges) {
         builder.append("Edge #").append(graphEdge.getEdgeRank()).append(System.lineSeparator());
         builder.append(graphEdge.getCompactEdgeString()).append(System.lineSeparator()).append(System.lineSeparator());
      }

      return builder.toString();
   }

   public String buildCoreBatchUserPrompt(
      LlmAttackStoryContext context,
      List<LlmNoiseGraphEdge> batchEdges,
      int batchIndex,
      int totalBatches,
      String previousSummary
   ) {
      LlmAttackStoryContext safeContext = context == null
         ? LlmAttackStoryContext.fromSingleEntry(null, null)
         : context;
      return buildCoreBatchUserPrompt(
         safeContext.getSelectedEntries(),
         safeContext.getAnomalyNode(),
         batchEdges,
         batchIndex,
         totalBatches,
         previousSummary
      );
   }

   public String buildCoreSliceUserPrompt(
      LlmAttackStoryContext context,
      List<LlmNoiseGraphEdge> sliceEdges,
      int sliceIndex,
      int totalSlices
   ) {
      LlmAttackStoryContext safeContext = context == null
         ? LlmAttackStoryContext.fromSingleEntry(null, null)
         : context;
      StringBuilder builder = new StringBuilder();
      builder.append("Task: internally classify only CURRENT_SLICE edges as KEEP, DROP, or UNCERTAIN, then report only DROP edges.")
         .append(System.lineSeparator())
         .append(System.lineSeparator())
         .append("Output format:")
         .append(System.lineSeparator())
         .append("DECISIONS")
         .append(System.lineSeparator())
         .append("DROP <edge_rank> :: <short reason>")
         .append(System.lineSeparator())
         .append("or, if no edge is dropped:")
         .append(System.lineSeparator())
         .append("NO_DROP")
         .append(System.lineSeparator())
         .append(System.lineSeparator())
         .append("Rules:")
         .append(System.lineSeparator())
         .append("1. Internally classify every edge in CURRENT_SLICE as KEEP, DROP, or UNCERTAIN.")
         .append(System.lineSeparator())
         .append("2. Output only DROP edges from CURRENT_SLICE; omit KEEP and UNCERTAIN edges.")
         .append(System.lineSeparator())
         .append("3. If no edge is internally classified as DROP, output NO_DROP as the only line after DECISIONS.")
         .append(System.lineSeparator())
         .append("4. Every DROP line must exactly use DROP <edge_rank> :: <non-empty short reason>.")
         .append(System.lineSeparator())
         .append("5. Do not output decisions for edges outside CURRENT_SLICE, output KEEP or UNCERTAIN lines, or mix NO_DROP with DROP lines.")
         .append(System.lineSeparator())
         .append("6. Judge each edge by its role in the causal story, not by process name or tool name alone.")
         .append(System.lineSeparator())
         .append("7. DROP only when the edge is clearly redundant, mirrored, bookkeeping-only, stale-context, or support-context without a meaningful state change.")
         .append(System.lineSeparator())
         .append("8. Do not classify an edge as mirrored or reverse-direction noise only because the opposite direction also exists; the dropped direction must be clearly only a restatement with no distinct stage transition, downstream dependency, or handoff.")
         .append(System.lineSeparator())
         .append("9. If the edge might represent real execution advancement, data movement, artifact creation, artifact transformation, or external communication, and you are not sure, classify it as UNCERTAIN and omit it.")
         .append(System.lineSeparator())
         .append("10. Do not output sections, prose, bullets, numbering prefixes, JSON, or any text after the DECISIONS lines.")
         .append(System.lineSeparator())
         .append(System.lineSeparator())
         .append("Slice:")
         .append(System.lineSeparator())
         .append(sliceIndex)
         .append(" of ")
         .append(totalSlices)
         .append(System.lineSeparator())
         .append(System.lineSeparator())
         .append("Selected attack-entry candidates:")
         .append(System.lineSeparator());
      appendSelectedEntries(builder, safeContext.getSelectedEntries());
      builder
         .append(System.lineSeparator())
         .append("Anomaly node:")
         .append(System.lineSeparator())
         .append(formatNode(safeContext.getAnomalyNode()))
         .append(System.lineSeparator())
         .append(System.lineSeparator())
         .append("Field meanings:")
         .append(System.lineSeparator())
         .append("- node_type: File, Process, or Network")
         .append(System.lineSeparator())
         .append("- signature: node identifier in the form id: signature")
         .append(System.lineSeparator())
         .append("- event_type: provenance event on the edge")
         .append(System.lineSeparator())
         .append(System.lineSeparator())
         .append("CURRENT_SLICE edges:")
         .append(System.lineSeparator());

      for (LlmNoiseGraphEdge graphEdge : sliceEdges) {
         builder.append("Edge #").append(graphEdge.getEdgeRank()).append(System.lineSeparator());
         builder.append(graphEdge.getCompactEdgeString()).append(System.lineSeparator()).append(System.lineSeparator());
      }

      return builder.toString();
   }

   private static void appendSelectedEntries(StringBuilder builder, List<EntityNode> entries) {
      if (entries == null || entries.isEmpty()) {
         builder.append("<none>").append(System.lineSeparator());
         return;
      }
      for (int i = 0; i < entries.size(); i++) {
         builder.append("Candidate #")
            .append(i + 1)
            .append(" ")
            .append(formatNode(entries.get(i)))
            .append(System.lineSeparator());
      }
   }

   private static String formatNode(EntityNode node) {
      if (node == null) {
         return "[Unknown|]";
      }
      return "[" + resolveNodeType(node) + "|" + node.getSignature() + "]";
   }

   private static String resolveNodeType(EntityNode node) {
      if (node == null) {
         return "Unknown";
      }
      if (node.getN() != null) {
         return "Network";
      }
      if (node.getP() != null) {
         return "Process";
      }
      if (node.getF() != null) {
         return "File";
      }
      return "Unknown";
   }
}
