package util.llm;

import java.math.BigDecimal;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Set;
import model.EntityNode;
import model.EventEdge;
import org.jgrapht.graph.DirectedPseudograph;
import util.ProcessSubgraph;
import util.ProcessSubgraphBuildResult;
import util.SubgraphConfig;

/** Applies attack-story-aware DROP-only filtering where every edge is decided only by its owner process subgraph. */
public final class SubgraphLlmEdgeFilter {
   private static final int UNREACHABLE = Integer.MAX_VALUE / 4;
   private final LlmConnectivityProbe connectivityProbe;
   private final SubgraphEdgeFilterPromptBuilder promptBuilder;

   public SubgraphLlmEdgeFilter() { this(new LlmConnectivityProbe(), new SubgraphEdgeFilterPromptBuilder()); }

   public SubgraphLlmEdgeFilter(LlmConnectivityProbe connectivityProbe, SubgraphEdgeFilterPromptBuilder promptBuilder) {
      this.connectivityProbe = connectivityProbe;
      this.promptBuilder = promptBuilder;
   }

   public SubgraphLlmEdgeFilterResult filter(DirectedPseudograph<EntityNode, EventEdge> graph, ProcessSubgraphBuildResult subgraphs,
      LlmAttackStoryContext context, EntityNode poiSink, SubgraphConfig config) {
      DirectedPseudograph<EntityNode, EventEdge> safeGraph = graph == null
         ? new DirectedPseudograph<EntityNode, EventEdge>(EventEdge.class) : graph;
      LlmAttackStoryContext safeContext = context == null ? LlmAttackStoryContext.fromSingleEntry(null, poiSink) : context;
      List<EntityNode> entries = safeContext.getSelectedEntries();
      int batchSize = config == null ? 15 : Math.max(1, config.getLlmEdgeFilterBatchSize());
      boolean enabled = config != null;
      String degradedReason = "";
      if (!enabled) degradedReason = config == null ? "LLM subgraph noise filtering requires subgraph configuration."
         : "LLM subgraph noise filtering is disabled by configuration.";
      if (!hasUniqueEdgeIds(safeGraph)) {
         degradedReason = "The global rule-filtered graph contains duplicate EventEdge IDs; skipped LLM DROP to avoid ambiguous deletion.";
         enabled = false;
      }

      LlmConfig llmConfig = null;
      if (enabled && !safeGraph.edgeSet().isEmpty()) {
         try {
            llmConfig = LlmConfig.load();
         } catch (RuntimeException ex) {
            degradedReason = "LLM configuration is unavailable; retained the global rule-filtered graph. " + describe(ex);
            enabled = false;
         }
      }

      NarrativeOrder narrativeOrder = orderSubgraphs(safeGraph, subgraphs, entries, poiSink);
      List<SubgraphLlmEdgeFilterResult.BatchResult> batches = new ArrayList<>();
      List<SubgraphLlmEdgeFilterResult.DecisionRecord> decisions = new ArrayList<>();
      DirectedPseudograph<EntityNode, EventEdge> working = copyGraph(safeGraph);
      String systemPrompt = this.promptBuilder.buildSystemPrompt();
      String runningSummary = "";

      if (enabled && llmConfig != null) {
         int totalBatches = (narrativeOrder.subgraphs.size() + batchSize - 1) / batchSize;
         System.out.println("LLM subgraph noise filter input: nodes=" + safeGraph.vertexSet().size() + ", edges="
            + safeGraph.edgeSet().size() + ", subgraphs=" + narrativeOrder.subgraphs.size() + ", batch_size=" + batchSize
            + ", batches=" + totalBatches);
         for (int start = 0, batchIndex = 1; start < narrativeOrder.subgraphs.size(); start += batchSize, batchIndex++) {
            List<ProcessSubgraph> batch = narrativeOrder.subgraphs.subList(start, Math.min(start + batchSize, narrativeOrder.subgraphs.size()));
            BatchInput input = BatchInput.from(batch, narrativeOrder.roles);
            String previousSummary = runningSummary;
            String userPrompt = this.promptBuilder.buildBatchUserPrompt(safeContext, poiSink, batch, narrativeOrder.roles,
               batchIndex, totalBatches, previousSummary);
            String rawResponse = "";
            String status = "success";
            int invalid = 0;
            int outside = 0;
            int contextOnly = 0;
            int duplicate = 0;
            String updatedSummary = previousSummary;
            try {
               LlmConnectivityProbe.LlmChatResult response = this.connectivityProbe.chatCompletionSingleAttempt(llmConfig, systemPrompt, userPrompt);
               rawResponse = response.getMessageText() == null ? "" : response.getMessageText().trim();
               SubgraphEdgeFilterLineParser.ParseResult parsed = SubgraphEdgeFilterLineParser.parse(rawResponse, input.ownedEdgeIds, input.contextEdgeIds);
               invalid = parsed.getInvalidLineCount();
               outside = parsed.getOutsideBatchIdCount();
               contextOnly = parsed.getContextOnlyIdCount();
               duplicate = parsed.getDuplicateDropCount();
               if (!parsed.isValidProtocol()) {
                  status = "unparseable_response_retained";
               } else {
                  updatedSummary = parsed.getUpdatedSummary();
                  for (Map.Entry<Long, String> rejected : parsed.getRejectedDrops().entrySet()) {
                     decisions.add(new SubgraphLlmEdgeFilterResult.DecisionRecord(batchIndex, rejected.getKey(),
                        input.ownerFor(rejected.getKey()), "", rejected.getValue()));
                  }
                  applyBatchSuggestions(working, parsed.getDrops(), input, batchIndex, decisions);
                  runningSummary = updatedSummary;
               }
            } catch (RuntimeException ex) {
               status = "request_failed_retained: " + describe(ex);
               rawResponse = status;
            }
            batches.add(new SubgraphLlmEdgeFilterResult.BatchResult(batchIndex, input.rootIds, input.rootRoles,
               input.ownedEdgeIds.size(), input.contextEdgeIds.size(), previousSummary, updatedSummary, userPrompt, rawResponse,
               status, invalid, outside, contextOnly, duplicate));
            System.out.println("LLM subgraph noise filter batch=" + batchIndex + "/" + totalBatches + ", roots=" + input.rootIds
               + ", owned_edges=" + input.ownedEdgeIds.size() + ", context_edges=" + input.contextEdgeIds.size()
               + ", suggested_drops=" + countBatchDecisions(decisions, batchIndex) + ", status=" + status);
         }
      } else {
         int totalBatches = (narrativeOrder.subgraphs.size() + batchSize - 1) / batchSize;
         System.out.println("LLM subgraph noise filter input: nodes=" + safeGraph.vertexSet().size() + ", edges="
            + safeGraph.edgeSet().size() + ", subgraphs=" + narrativeOrder.subgraphs.size() + ", batch_size=" + batchSize
            + ", batches=" + totalBatches + ", status=retained_without_llm");
      }

      Set<EntityNode> anchors = new LinkedHashSet<>();
      anchors.addAll(entries);
      if (poiSink != null) anchors.add(poiSink);
      GraphBuild retained = removeNonAnchorIsolates(working, safeGraph, anchors);
      int removedDisconnectedNodes = pruneDisconnectedComponents(retained.graph, entries, poiSink);
      System.out.println("LLM subgraph noise filter result: suggested_drops=" + decisions.size() + ", accepted_drops="
         + acceptedCount(decisions) + ", retained_edges=" + retained.graph.edgeSet().size() + ", removed_isolated_nodes="
         + retained.removedIsolatedNodes + ", removed_disconnected_nodes=" + removedDisconnectedNodes
         + ", retained_anchor_nodes=" + retained.retainedAnchorNodes + ", degraded_reason=" + degradedReason);
      return new SubgraphLlmEdgeFilterResult(retained.graph, systemPrompt, batches, decisions, degradedReason, enabled,
          safeGraph.vertexSet().size(), safeGraph.edgeSet().size(), narrativeOrder.subgraphs.size(), batchSize,
          retained.removedIsolatedNodes, removedDisconnectedNodes, retained.retainedAnchorNodes);
   }

   private static void applyBatchSuggestions(DirectedPseudograph<EntityNode, EventEdge> working, Map<Long, String> suggestions,
      BatchInput input, int batchIndex, List<SubgraphLlmEdgeFilterResult.DecisionRecord> decisions) {
      if (suggestions.isEmpty()) return;
      List<Long> ids = new ArrayList<>(suggestions.keySet());
      Collections.sort(ids);
      for (Long edgeId : ids) {
         EventEdge edge = findEdgeById(working, edgeId);
         if (edge == null) {
            decisions.add(new SubgraphLlmEdgeFilterResult.DecisionRecord(batchIndex, edgeId, input.ownerFor(edgeId),
               suggestions.get(edgeId), "rejected_edge_not_present"));
            continue;
         }
         working.removeEdge(edge);
         decisions.add(new SubgraphLlmEdgeFilterResult.DecisionRecord(batchIndex, edgeId, input.ownerFor(edgeId),
            suggestions.get(edgeId), "accepted"));
      }
   }

   private static EventEdge findEdgeById(DirectedPseudograph<EntityNode, EventEdge> graph, long edgeId) {
      for (EventEdge edge : graph.edgeSet()) if (edge.getID() == edgeId) return edge;
      return null;
   }

   private static NarrativeOrder orderSubgraphs(DirectedPseudograph<EntityNode, EventEdge> graph, ProcessSubgraphBuildResult result,
      List<EntityNode> entries, EntityNode poiSink) {
      List<ProcessSubgraph> values = new ArrayList<>();
      if (result != null) values.addAll(result.getSubgraphs().values());
      Map<Long, Set<Long>> outgoing = processAdjacency(graph, false);
      Map<Long, Set<Long>> incoming = processAdjacency(graph, true);
      Set<Long> entryRoots = processAnchors(graph, entries, true);
      Set<Long> poiRoots = processAnchors(graph, poiSink == null ? Collections.<EntityNode>emptyList() : Collections.singletonList(poiSink), false);
      Map<Long, Integer> entryDistances = bfsDistances(outgoing, entryRoots);
      Map<Long, Integer> poiDistances = bfsDistances(incoming, poiRoots);
      List<RankedSubgraph> ranked = new ArrayList<>();
      Map<Long, String> roles = new LinkedHashMap<>();
      for (ProcessSubgraph subgraph : values) {
         long rootId = subgraph.getRootProcess().getId();
         int entryDistance = distance(entryDistances, rootId);
         int poiDistance = distance(poiDistances, rootId);
         String role = role(entryDistance, poiDistance);
         roles.put(rootId, role);
         ranked.add(new RankedSubgraph(subgraph, role, entryDistance, poiDistance, earliestOwnedTime(subgraph)));
      }
      Collections.sort(ranked, RankedSubgraph.ORDER);
      List<ProcessSubgraph> ordered = new ArrayList<>();
      for (RankedSubgraph item : ranked) ordered.add(item.subgraph);
      return new NarrativeOrder(ordered, roles);
   }

   private static Map<Long, Set<Long>> processAdjacency(DirectedPseudograph<EntityNode, EventEdge> graph, boolean reverse) {
      Map<Long, Set<Long>> values = new LinkedHashMap<>();
      for (EntityNode node : graph.vertexSet()) if (isProcess(node)) values.put(node.getId(), new LinkedHashSet<Long>());
      for (EventEdge edge : graph.edgeSet()) {
         if (!isProcess(edge.getSource()) || !isProcess(edge.getSink())) continue;
         long from = reverse ? edge.getSink().getId() : edge.getSource().getId();
         long to = reverse ? edge.getSource().getId() : edge.getSink().getId();
         if (!values.containsKey(from)) values.put(from, new LinkedHashSet<Long>());
         values.get(from).add(to);
      }
      return values;
   }

   private static Set<Long> processAnchors(DirectedPseudograph<EntityNode, EventEdge> graph, List<EntityNode> nodes, boolean entryDirection) {
      Set<Long> result = new LinkedHashSet<>();
      if (nodes == null) return result;
      for (EntityNode node : nodes) {
         if (node == null || !graph.containsVertex(node)) continue;
         if (isProcess(node)) result.add(node.getId());
         if (entryDirection) {
            boolean projected = false;
            for (EventEdge edge : graph.outgoingEdgesOf(node)) if (isProcess(edge.getSink())) result.add(edge.getSink().getId());
            for (EventEdge edge : graph.outgoingEdgesOf(node)) if (isProcess(edge.getSink())) projected = true;
            if (!projected) for (EventEdge edge : graph.incomingEdgesOf(node)) if (isProcess(edge.getSource())) result.add(edge.getSource().getId());
         } else {
            boolean projected = false;
            for (EventEdge edge : graph.incomingEdgesOf(node)) if (isProcess(edge.getSource())) result.add(edge.getSource().getId());
            for (EventEdge edge : graph.incomingEdgesOf(node)) if (isProcess(edge.getSource())) projected = true;
            if (!projected) for (EventEdge edge : graph.outgoingEdgesOf(node)) if (isProcess(edge.getSink())) result.add(edge.getSink().getId());
         }
      }
      return result;
   }

   private static Map<Long, Integer> bfsDistances(Map<Long, Set<Long>> adjacency, Set<Long> starts) {
      Map<Long, Integer> distances = new HashMap<>();
      Queue<Long> queue = new ArrayDeque<>();
      for (Long start : starts) { distances.put(start, 0); queue.add(start); }
      while (!queue.isEmpty()) {
         Long current = queue.remove();
         Set<Long> neighbors = adjacency.get(current);
         if (neighbors == null) continue;
         for (Long next : neighbors) if (!distances.containsKey(next)) { distances.put(next, distances.get(current) + 1); queue.add(next); }
      }
      return distances;
   }

   private static String role(int entryDistance, int poiDistance) {
      if (entryDistance <= 1) return "entry-adjacent";
      if (entryDistance < UNREACHABLE && poiDistance < UNREACHABLE) return "bridge";
      if (poiDistance <= 1) return "poi-adjacent";
      return "other";
   }
   private static int distance(Map<Long, Integer> values, long id) { return values.containsKey(id) ? values.get(id) : UNREACHABLE; }
   private static BigDecimal earliestOwnedTime(ProcessSubgraph subgraph) {
      BigDecimal result = null;
      for (EventEdge edge : subgraph.getOwnedEdges()) if (edge.getStartTime() != null && (result == null || edge.getStartTime().compareTo(result) < 0)) result = edge.getStartTime();
      return result == null ? new BigDecimal(Long.MAX_VALUE) : result;
   }
   private static boolean isProcess(EntityNode node) { return node != null && node.getP() != null; }

   private static boolean hasUniqueEdgeIds(DirectedPseudograph<EntityNode, EventEdge> graph) {
      Set<Long> ids = new LinkedHashSet<>();
      for (EventEdge edge : graph.edgeSet()) if (!ids.add(edge.getID())) return false;
      return true;
   }

   private static DirectedPseudograph<EntityNode, EventEdge> copyGraph(DirectedPseudograph<EntityNode, EventEdge> graph) {
      DirectedPseudograph<EntityNode, EventEdge> copy = new DirectedPseudograph<>(EventEdge.class);
      for (EntityNode node : graph.vertexSet()) copy.addVertex(node);
      for (EventEdge edge : graph.edgeSet()) copy.addEdge(edge.getSource(), edge.getSink(), edge);
      return copy;
   }

   static int pruneDisconnectedComponents(
      DirectedPseudograph<EntityNode, EventEdge> graph, List<EntityNode> entries, EntityNode poiSink
   ) {
      return LlmNoiseGraphSelector.retainSharedWeaklyConnectedComponent(graph, entries, poiSink);
   }

   private static GraphBuild removeNonAnchorIsolates(DirectedPseudograph<EntityNode, EventEdge> graph,
      DirectedPseudograph<EntityNode, EventEdge> source, Set<EntityNode> anchors) {
      DirectedPseudograph<EntityNode, EventEdge> retained = copyGraph(graph);
      int removed = 0;
      for (EntityNode node : new ArrayList<EntityNode>(retained.vertexSet())) {
         if (retained.edgesOf(node).isEmpty() && !anchors.contains(node)) { retained.removeVertex(node); removed++; }
      }
      for (EntityNode anchor : anchors) if (anchor != null && !retained.containsVertex(anchor)) retained.addVertex(anchor);
      int retainedAnchors = 0;
      for (EntityNode anchor : anchors) if (anchor != null && retained.containsVertex(anchor) && retained.edgesOf(anchor).isEmpty()) retainedAnchors++;
      return new GraphBuild(retained, removed, retainedAnchors);
   }

   private static int countBatchDecisions(List<SubgraphLlmEdgeFilterResult.DecisionRecord> decisions, int batchIndex) {
      int count = 0;
      for (SubgraphLlmEdgeFilterResult.DecisionRecord ignored : decisions) {
         if (ignored.getBatchIndex() == batchIndex) count++;
      }
      return count;
   }
   private static int acceptedCount(List<SubgraphLlmEdgeFilterResult.DecisionRecord> decisions) {
      int count = 0;
      for (SubgraphLlmEdgeFilterResult.DecisionRecord decision : decisions) if (decision.isAccepted()) count++;
      return count;
   }
   private static String describe(Exception ex) {
      String message = ex == null || ex.getMessage() == null ? "Unknown failure" : ex.getMessage().replaceAll("(?i)(api[_-]?key|authorization|bearer)\\s*[:=]?\\s*\\S+", "$1=[redacted]");
      return ex == null ? message : ex.getClass().getSimpleName() + ": " + message;
   }

   private static final class NarrativeOrder {
      private final List<ProcessSubgraph> subgraphs;
      private final Map<Long, String> roles;
      private NarrativeOrder(List<ProcessSubgraph> subgraphs, Map<Long, String> roles) { this.subgraphs = subgraphs; this.roles = roles; }
   }
   private static final class RankedSubgraph {
      private static final Comparator<RankedSubgraph> ORDER = new Comparator<RankedSubgraph>() {
         public int compare(RankedSubgraph left, RankedSubgraph right) {
            int role = Integer.compare(roleOrder(left.role), roleOrder(right.role));
            if (role != 0) return role;
            int entry = Integer.compare(left.entryDistance, right.entryDistance);
            if (entry != 0) return entry;
            int time = left.earliestTime.compareTo(right.earliestTime);
            if (time != 0) return time;
            return Long.compare(left.subgraph.getRootProcess().getId(), right.subgraph.getRootProcess().getId());
         }
      };
      private final ProcessSubgraph subgraph;
      private final String role;
      private final int entryDistance;
      private final int poiDistance;
      private final BigDecimal earliestTime;
      private RankedSubgraph(ProcessSubgraph subgraph, String role, int entryDistance, int poiDistance, BigDecimal earliestTime) {
         this.subgraph = subgraph; this.role = role; this.entryDistance = entryDistance; this.poiDistance = poiDistance; this.earliestTime = earliestTime;
      }
      private static int roleOrder(String role) {
         if ("entry-adjacent".equals(role)) return 0;
         if ("bridge".equals(role)) return 1;
         if ("poi-adjacent".equals(role)) return 2;
         return 3;
      }
   }
   private static final class GraphBuild {
      private final DirectedPseudograph<EntityNode, EventEdge> graph;
      private final int removedIsolatedNodes;
      private final int retainedAnchorNodes;
      private GraphBuild(DirectedPseudograph<EntityNode, EventEdge> graph, int removedIsolatedNodes, int retainedAnchorNodes) {
         this.graph = graph; this.removedIsolatedNodes = removedIsolatedNodes; this.retainedAnchorNodes = retainedAnchorNodes;
      }
   }
   private static final class BatchInput {
      private final List<Long> rootIds = new ArrayList<>();
      private final Map<Long, String> rootRoles = new LinkedHashMap<>();
      private final Set<Long> ownedEdgeIds = new LinkedHashSet<>();
      private final Set<Long> contextEdgeIds = new LinkedHashSet<>();
      private final Map<Long, Long> ownerRoots = new LinkedHashMap<>();
      static BatchInput from(List<ProcessSubgraph> subgraphs, Map<Long, String> roles) {
         BatchInput result = new BatchInput();
         for (ProcessSubgraph subgraph : subgraphs) {
            long root = subgraph.getRootProcess().getId();
            result.rootIds.add(root);
            result.rootRoles.put(root, roles != null && roles.containsKey(root) ? roles.get(root) : "other");
            for (EventEdge edge : subgraph.getOwnedEdges()) { result.ownedEdgeIds.add(edge.getID()); result.ownerRoots.put(edge.getID(), root); }
            for (EventEdge edge : subgraph.getContextEdges()) result.contextEdgeIds.add(edge.getID());
         }
         return result;
      }
      private long ownerFor(long edgeId) { return ownerRoots.containsKey(edgeId) ? ownerRoots.get(edgeId) : -1L; }
   }
}
