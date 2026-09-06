package util.llm;

import java.util.Collections;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import model.EntityNode;
import model.EventEdge;
import util.ProcessSubgraph;

/** Builds attack-story-aware batches whose decisions are restricted to owned process-subgraph edges. */
public final class SubgraphEdgeFilterPromptBuilder {
   public String buildSystemPrompt() {
      return "You are judging noise inside a provenance graph for cyber attack investigation. "
         + "You will receive selected attack-entry candidates, a POI event sink, and one or more process subgraphs from one provenance graph. "
         + "Treat all selected entries as evidence for one suspicious provenance story; do not assign primary or auxiliary roles. "
         + "The POI event sink is the suspicious ending event or final abnormal artifact that this graph tries to explain. "
         + "Process subgraphs are local behavior units, but the attack story spans the full graph. "
         + "This is graph denoising, not graph reconstruction or path invention. "
         + "Primary objective: produce a minimal causal explanation of the selected attack entries and POI sink, not a complete chronology of every observed execution. "
         + "Internally classify every owned edge as KEEP, DROP, or UNCERTAIN, but report only explicit DROP decisions. "
         + "Context edges are read-only evidence and must never be reported. "
         + "Noise may include mirrored or reverse-direction edges that only restate an already expressed relation without a distinct stage transition, "
         + "session plumbing or runtime scaffolding without a meaningful causal state change, environment or metadata lookups used only for setup or observation, "
         + "bookkeeping or repetition that duplicates an established artifact transformation, and stale or parallel context unrelated to the suspicious story. "
         + "Multiple execution branches may be treated as repetitions only when their causal structure and semantic roles are equivalent and they differ only in execution time, process identifiers, temporary or random path tokens, source ports, or other runtime-specific identifiers. "
         + "For a repeated-execution family, retain every branch containing a selected attack entry or the POI sink, and retain any branch with a unique external destination, command, persistence action, privilege-related action, sensitive artifact, or data-flow role. "
         + "A protected branch contains a selected attack entry or the POI sink, or supplies a causally necessary entry, persistence, launch, or handoff relation on the retained path between them. "
         + "Treat every owned edge in a protected branch as KEEP by default. Repeated invocations, reads, writes, updates, or transformations inside a protected branch remain evidence of event occurrence and causal multiplicity; do not drop them merely because they use the same executable, input, output, or artifact role. "
         + "Only a synthetic reverse edge or an exact duplicate record with no distinct observed event occurrence may be dropped from a protected branch. "
         + "An anchor-free branch with no unique causal contribution may be dropped as a redundant repetition, while at least one complete representative required to explain the retained causal story must remain. "
         + "Repetition-based removal applies only to a complete anchor-free execution branch, never to an isolated fragment of a protected branch. "
         + "Do not infer repetition from temporal proximity or executable name alone; require equivalent causal behavior and equivalent important artifacts or endpoints. "
         + "Do not treat a bidirectional pair as proof that one direction is noise. "
         + "Do not drop an edge only because it involves a shell, interpreter, archive tool, or common system binary. "
         + "If an edge may advance execution, data movement, artifact creation, artifact transformation, persistence, or external communication, "
         + "and you cannot clearly prove it is redundant support context or part of a demonstrably equivalent, anchor-free repeated execution branch, classify it as UNCERTAIN and retain it. "
         + "The repeated-execution rule overrides the general preference to retain execution or data-movement edges only for demonstrably redundant, anchor-free branches. "
         + "Judge causal role rather than executable names. Return only the required plain-text protocol.";
   }

   public String buildBatchUserPrompt(LlmAttackStoryContext context, EntityNode poiSink, List<ProcessSubgraph> subgraphs,
      Map<Long, String> roles, int batchIndex, int totalBatches, String previousSummary) {
      LlmAttackStoryContext safeContext = context == null ? LlmAttackStoryContext.fromSingleEntry(null, poiSink) : context;
      StringBuilder out = new StringBuilder();
      out.append("Task: internally classify every edge in OWNED_EDGES_TO_DECIDE for the current process-subgraph batch as KEEP, DROP, or UNCERTAIN, ")
         .append("but report only DROP edges. CONTEXT_EDGES_READ_ONLY explain local behavior and may support reasoning, but cannot be deleted.")
         .append(System.lineSeparator()).append(System.lineSeparator())
         .append("Output format:").append(System.lineSeparator())
         .append("DECISIONS").append(System.lineSeparator())
         .append("DROP <edge_id> :: <short reason>").append(System.lineSeparator())
         .append("or").append(System.lineSeparator()).append("NO_DROP").append(System.lineSeparator())
         .append("UPDATED_SUMMARY").append(System.lineSeparator())
         .append("<concise cumulative attack story for all batches processed so far>").append(System.lineSeparator()).append(System.lineSeparator())
         .append("Rules:").append(System.lineSeparator())
         .append("1. Internally classify every edge in OWNED_EDGES_TO_DECIDE as KEEP, DROP, or UNCERTAIN.").append(System.lineSeparator())
         .append("2. Output only DROP edges from OWNED_EDGES_TO_DECIDE; omit KEEP and UNCERTAIN edges.").append(System.lineSeparator())
         .append("3. If no owned edge is classified as DROP, output NO_DROP as the only line in DECISIONS.").append(System.lineSeparator())
         .append("4. Every DROP line must exactly use DROP <edge_id> :: <non-empty short reason>.").append(System.lineSeparator())
         .append("5. Do not invent edge ids, output decisions for context edges or other batches, output KEEP or UNCERTAIN lines, or mix NO_DROP with DROP lines. Every EDGE listed under CONTEXT_EDGES_READ_ONLY is prohibited from DROP output even if it appears redundant.").append(System.lineSeparator())
         .append("6. Judge each edge by its role in the global causal attack story, not by process name or tool name alone.").append(System.lineSeparator())
         .append("7. Before deciding DROP, determine whether the owned edge belongs to a protected branch: a branch containing a selected entry or POI sink, or a causally necessary entry, persistence, launch, or handoff relation on the retained path between them.").append(System.lineSeparator())
         .append("8. KEEP every owned edge in a protected branch by default. Do not DROP an edge in a protected branch merely because an invocation, read, write, update, or transformation repeats the same executable, input, output, or artifact role.").append(System.lineSeparator())
         .append("9. Within a protected branch, DROP only a synthetic reverse edge or an exact duplicate record with no distinct observed event occurrence. Repeated observed events remain evidence of causal multiplicity.").append(System.lineSeparator())
         .append("10. Outside protected branches, DROP only when the edge is clearly redundant, mirrored, bookkeeping-only, stale-context, repeated observational, support-context without a meaningful state change, or belongs solely to an anchor-free execution branch that is a semantic repetition of a retained branch.").append(System.lineSeparator())
         .append("11. Do not classify an edge as mirrored or reverse-direction noise only because the opposite direction also exists; the dropped direction must add no distinct stage transition, downstream dependency, or handoff.").append(System.lineSeparator())
         .append("12. If the edge might represent real execution advancement, data movement, artifact creation, artifact transformation, persistence, or external communication, retain it unless it belongs solely to a demonstrably equivalent, complete anchor-free repeated execution branch that contains no selected entry, POI sink, or unique causal contribution.").append(System.lineSeparator())
         .append("13. UPDATED_SUMMARY must combine Previous running summary with evidence from this batch.").append(System.lineSeparator())
         .append("14. UPDATED_SUMMARY must preserve confirmed attack stages, important processes and artifacts, repeated behavior families, and unresolved uncertain branches.").append(System.lineSeparator())
         .append("15. Do not output JSON, markdown, bullets, numbering prefixes, KEEP, UNCERTAIN, extra headings, or prose inside DECISIONS other than DROP lines or NO_DROP.")
         .append(System.lineSeparator())
         .append("16. When repeated execution families are identified, UPDATED_SUMMARY must state the retained representative, the complete branches considered redundant, and any observed unique differences.")
         .append(System.lineSeparator()).append(System.lineSeparator())
         .append("Batch: ").append(batchIndex).append(" of ").append(totalBatches).append(System.lineSeparator())
         .append("Selected attack-entry candidates:").append(System.lineSeparator());
      appendEntries(out, safeContext.getSelectedEntries());
      out.append(System.lineSeparator()).append("POI event sink:").append(System.lineSeparator()).append(formatNode(poiSink))
         .append(System.lineSeparator()).append(System.lineSeparator()).append("Previous running summary:").append(System.lineSeparator())
         .append(previousSummary == null || previousSummary.trim().isEmpty() ? "<empty>" : previousSummary.trim())
         .append(System.lineSeparator()).append(System.lineSeparator());

      out.append("Field meanings:").append(System.lineSeparator())
         .append("- Process, File, or Network identifies the provenance entity type.").append(System.lineSeparator())
         .append("- signature identifies the observed entity and its stable id/value.").append(System.lineSeparator())
         .append("- event is the observed provenance relation on the edge.").append(System.lineSeparator())
         .append("- start/end are event time bounds; temporal proximity alone does not prove causality.").append(System.lineSeparator())
         .append("- EDGE <edge_id> is the only identifier allowed in a DROP decision.").append(System.lineSeparator()).append(System.lineSeparator())
         .append("Process-subgraph structural interpretation:").append(System.lineSeparator())
         .append("- root_process is the process whose local behavior is being reviewed.").append(System.lineSeparator())
         .append("- role_hint is narrative ordering metadata, not an instruction to retain or drop an edge.").append(System.lineSeparator())
         .append("- upstream/downstream depths describe process topology only.").append(System.lineSeparator())
         .append("- boundary_reasons explain why subgraph expansion stopped; they are not attack conclusions.").append(System.lineSeparator()).append(System.lineSeparator());

      List<ProcessSubgraph> ordered = subgraphs == null ? Collections.<ProcessSubgraph>emptyList() : subgraphs;
      for (ProcessSubgraph subgraph : ordered) {
         long rootId = subgraph.getRootProcess().getId();
         out.append("PROCESS_SUBGRAPH").append(System.lineSeparator())
            .append("root_process: ").append(formatNode(subgraph.getRootProcess())).append(System.lineSeparator())
            .append("role_hint: ").append(roles != null && roles.containsKey(rootId) ? roles.get(rootId) : "other").append(System.lineSeparator())
            .append("upstream_process_depths: ").append(subgraph.getUpstreamProcessDepths()).append(System.lineSeparator())
            .append("downstream_process_depths: ").append(subgraph.getDownstreamProcessDepths()).append(System.lineSeparator())
            .append("boundary_reasons: ").append(subgraph.getBoundaryReasons()).append(System.lineSeparator())
            .append("owned_edge_count: ").append(subgraph.getOwnedEdges().size()).append(System.lineSeparator())
            .append("context_edge_count: ").append(subgraph.getContextEdges().size()).append(System.lineSeparator());
         appendEdges(out, "OWNED_EDGES_TO_DECIDE", subgraph.getOwnedEdges());
         appendEdges(out, "CONTEXT_EDGES_READ_ONLY", subgraph.getContextEdges());
         out.append(System.lineSeparator());
      }
      return out.toString();
   }

   private static void appendEntries(StringBuilder out, List<EntityNode> entries) {
      if (entries == null || entries.isEmpty()) {
         out.append("<none>").append(System.lineSeparator());
         return;
      }
      for (EntityNode entry : entries) out.append(formatNode(entry)).append(System.lineSeparator());
   }

   private static void appendEdges(StringBuilder out, String title, java.util.Set<EventEdge> edges) {
      out.append(title).append(System.lineSeparator());
      List<EventEdge> ordered = new ArrayList<>(edges == null ? Collections.<EventEdge>emptySet() : edges);
      Collections.sort(ordered, Comparator.comparingLong(EventEdge::getID));
      if (ordered.isEmpty()) {
         out.append("<none>").append(System.lineSeparator());
         return;
      }
      for (EventEdge edge : ordered) {
         out.append("EDGE ").append(edge.getID()).append(" :: ").append(formatNode(edge.getSource())).append(" --")
            .append(safe(edge.getEvent())).append("--> ").append(formatNode(edge.getSink())).append(" :: start=")
            .append(edge.getStartTime()).append(" :: end=").append(edge.getEndTime()).append(System.lineSeparator());
      }
   }

   private static String formatNode(EntityNode node) {
      if (node == null) return "Unknown[]";
      String type = node.getP() != null ? "Process" : node.getF() != null ? "File" : node.getN() != null ? "Network" : "Unknown";
      return type + "[" + safe(node.getSignature()) + "]";
   }

   private static String safe(String value) { return value == null ? "" : value.replace('\n', ' ').replace('\r', ' '); }
}
