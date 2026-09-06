package util.llm;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import model.EntityNode;
import model.EventEdge;
import org.jgrapht.graph.DirectedPseudograph;

public class LlmNoiseGraphSelector {
   private static final Pattern DROP_LINE_PATTERN = Pattern.compile(
      "^DROP\\s+([1-9]\\d*)\\s+::\\s+(\\S(?:.*\\S)?)$"
   );

   public enum NoiseGraphStage {
      CORE
   }

   private final LlmConnectivityProbe connectivityProbe;
   private final LlmNoiseGraphPromptBuilder promptBuilder;

   public LlmNoiseGraphSelector() {
      this(new LlmConnectivityProbe(), new LlmNoiseGraphPromptBuilder());
   }

   public LlmNoiseGraphSelector(LlmConnectivityProbe connectivityProbe, LlmNoiseGraphPromptBuilder promptBuilder) {
      this.connectivityProbe = connectivityProbe;
      this.promptBuilder = promptBuilder;
   }

   public LlmNoiseGraphResult classifyGraph(
      NoiseGraphStage stage,
      EntityNode entry,
      EntityNode anomalyNode,
      DirectedPseudograph<EntityNode, EventEdge> graph,
      String ignoredSummary
   ) {
      return classifyGraph(stage, LlmAttackStoryContext.fromSingleEntry(entry, anomalyNode), graph, ignoredSummary);
   }

   public LlmNoiseGraphResult classifyGraph(
      NoiseGraphStage stage,
      LlmAttackStoryContext context,
      DirectedPseudograph<EntityNode, EventEdge> graph,
      String ignoredSummary
   ) {
      List<LlmNoiseGraphEdge> graphEdges = serializeFullGraphEdges(graph);
      String systemPrompt = this.promptBuilder.buildCoreSystemPrompt();

      if (graphEdges.isEmpty()) {
         String userPrompt = this.promptBuilder.buildCoreUserPrompt(context, graphEdges);
         LlmNoiseGraphQuestionRecord questionRecord = new LlmNoiseGraphQuestionRecord("", "", "", systemPrompt, userPrompt);
         return new LlmNoiseGraphResult(questionRecord, graphEdges, new ArrayList<>(), "Graph has no edges.", "", 0, false, false);
      }

      LlmConfig config = LlmConfig.load();
      if (config.getNoiseMode() == LlmConfig.NoiseMode.SUBGRAPH) {
         throw new IllegalStateException("subgraph noise mode is handled by Main on the global merged graph.");
      }
      int partitionEdgeLimit = config.getNoiseMode() == LlmConfig.NoiseMode.BATCH
         ? Math.max(1, config.getNoiseBatchSize())
         : config.getNoiseMode() == LlmConfig.NoiseMode.SLICE
            ? config.getNoiseSliceSize()
            : graphEdges.size();
      System.out.println(
         "LLM noise strategy="
            + config.getNoiseMode().getConfigValue()
            + ", input_edges="
            + graphEdges.size()
            + ", partition_edge_limit="
            + partitionEdgeLimit
      );
      if (config.getNoiseMode() == LlmConfig.NoiseMode.BATCH) {
         return classifyGraphInBatches(stage, context, graphEdges, systemPrompt, config);
      }
      if (config.getNoiseMode() == LlmConfig.NoiseMode.SLICE) {
         return classifyGraphInSlices(stage, context, graphEdges, systemPrompt, config);
      }

      String userPrompt = this.promptBuilder.buildCoreUserPrompt(context, graphEdges);
      LlmNoiseGraphQuestionRecord questionRecord = new LlmNoiseGraphQuestionRecord(
         config.getProvider(),
         config.getEndpoint(),
         config.getModel(),
         systemPrompt,
         userPrompt
      );

      LlmNoiseGraphResult result;
      try {
         LlmConnectivityProbe.LlmChatResult chatResult = this.connectivityProbe.chatCompletion(config, systemPrompt, userPrompt);
         result = parseResponse(stage, questionRecord, graphEdges, chatResult, config.getNoiseMode(), 1);
      } catch (RuntimeException ex) {
         result = fallbackResult(stage, questionRecord, graphEdges, ex.getMessage(), 0, false, config.getNoiseMode(), 1);
      }
      logPartitionResult(config.getNoiseMode(), 1, 1, graphEdges.size(), result.getDroppedEdgeCount(), result.isFallbackUsed());
      return result;
   }

   private LlmNoiseGraphResult classifyGraphInBatches(
      NoiseGraphStage stage,
      LlmAttackStoryContext context,
      List<LlmNoiseGraphEdge> graphEdges,
      String systemPrompt,
      LlmConfig config
   ) {
      int batchSize = Math.max(1, config.getNoiseBatchSize());
      int totalBatches = (graphEdges.size() + batchSize - 1) / batchSize;
      List<LlmNoiseGraphDrop> mergedDrops = new ArrayList<>();
      List<LlmNoiseGraphBatchResult> batchResults = new ArrayList<>();
      List<LlmNoiseGraphBatchPromptRecord> batchPrompts = new ArrayList<>();
      String runningSummary = "";
      boolean fallbackUsed = false;
      int successfulRequestCount = 0;
      int fallbackPartitionCount = 0;
      StringBuilder rawResponses = new StringBuilder();

      for (int start = 0, batchIndex = 1; start < graphEdges.size(); start += batchSize, batchIndex++) {
         int end = Math.min(start + batchSize, graphEdges.size());
         List<LlmNoiseGraphEdge> batchEdges = graphEdges.subList(start, end);
         String previousSummary = runningSummary;
         String userPrompt = this.promptBuilder.buildCoreBatchUserPrompt(context, batchEdges, batchIndex, totalBatches, previousSummary);
         batchPrompts.add(new LlmNoiseGraphBatchPromptRecord(batchIndex, totalBatches, userPrompt));
         LlmNoiseGraphBatchResult batchResult;

         try {
            LlmConnectivityProbe.LlmChatResult chatResult = this.connectivityProbe.chatCompletion(config, systemPrompt, userPrompt);
            batchResult = parseBatchResponse(
               stage,
               batchIndex,
               batchEdges,
               previousSummary,
               chatResult,
               config.getNoiseRunningSummaryMaxChars()
            );
            batchResults.add(batchResult);
            mergedDrops.addAll(batchResult.getDroppedEdges());
            runningSummary = truncateSummary(batchResult.getUpdatedSummary(), config.getNoiseRunningSummaryMaxChars());
            fallbackUsed = fallbackUsed || batchResult.isFallbackUsed();
            successfulRequestCount++;
            appendRawBatchResponse(rawResponses, batchIndex, chatResult.getMessageText());
         } catch (RuntimeException ex) {
            batchResult = fallbackBatchResult(
               stage,
               batchIndex,
               batchEdges,
               previousSummary,
               previousSummary,
               ex.getMessage(),
               0,
               config.getNoiseRunningSummaryMaxChars()
            );
            batchResults.add(batchResult);
            mergedDrops.addAll(batchResult.getDroppedEdges());
            fallbackUsed = true;
            fallbackPartitionCount++;
            appendRawBatchResponse(rawResponses, batchIndex, ex.getMessage());
         }
         logPartitionResult(
            config.getNoiseMode(), batchIndex, totalBatches, batchEdges.size(), batchResult.getDroppedEdgeCount(), batchResult.isFallbackUsed()
         );

      }

      LlmNoiseGraphQuestionRecord questionRecord = new LlmNoiseGraphQuestionRecord(
         config.getProvider(),
         config.getEndpoint(),
         config.getModel(),
         systemPrompt,
         "",
         batchPrompts
      );

      return new LlmNoiseGraphResult(
         questionRecord,
         graphEdges,
         mergedDrops,
         runningSummary,
         rawResponses.toString(),
         0,
         fallbackUsed,
         true,
         batchResults,
         config.getNoiseMode(),
         totalBatches,
         null,
         batchSize,
         totalBatches,
         successfulRequestCount,
         fallbackPartitionCount
      );
   }

   private LlmNoiseGraphResult classifyGraphInSlices(
      NoiseGraphStage stage,
      LlmAttackStoryContext context,
      List<LlmNoiseGraphEdge> graphEdges,
      String systemPrompt,
      LlmConfig config
   ) {
      int sliceSize = config.getNoiseSliceSize();
      int totalSlices = (graphEdges.size() + sliceSize - 1) / sliceSize;
      List<LlmNoiseGraphDrop> mergedDrops = new ArrayList<>();
      List<LlmNoiseGraphBatchResult> sliceResults = new ArrayList<>();
      List<LlmNoiseGraphBatchPromptRecord> slicePrompts = new ArrayList<>();
      boolean fallbackUsed = false;
      int successfulRequestCount = 0;
      int fallbackPartitionCount = 0;
      StringBuilder rawResponses = new StringBuilder();

      for (int start = 0, sliceIndex = 1; start < graphEdges.size(); start += sliceSize, sliceIndex++) {
         int end = Math.min(start + sliceSize, graphEdges.size());
         List<LlmNoiseGraphEdge> sliceEdges = graphEdges.subList(start, end);
         String userPrompt = this.promptBuilder.buildCoreSliceUserPrompt(context, sliceEdges, sliceIndex, totalSlices);
         slicePrompts.add(new LlmNoiseGraphBatchPromptRecord(sliceIndex, totalSlices, userPrompt));
         LlmNoiseGraphBatchResult sliceResult;

         try {
            LlmConnectivityProbe.LlmChatResult chatResult = this.connectivityProbe.chatCompletion(config, systemPrompt, userPrompt);
            sliceResult = parseSliceResponse(stage, sliceIndex, sliceEdges, chatResult);
            sliceResults.add(sliceResult);
            mergedDrops.addAll(sliceResult.getDroppedEdges());
            fallbackUsed = fallbackUsed || sliceResult.isFallbackUsed();
            successfulRequestCount++;
            appendRawSliceResponse(rawResponses, sliceIndex, chatResult.getMessageText());
         } catch (RuntimeException ex) {
            sliceResult = fallbackBatchResult(
               stage,
               sliceIndex,
               sliceEdges,
               "",
               "",
               ex.getMessage(),
               0,
               0
            );
            sliceResults.add(sliceResult);
            fallbackUsed = true;
            fallbackPartitionCount++;
            appendRawSliceResponse(rawResponses, sliceIndex, ex.getMessage());
         }
         logPartitionResult(
            config.getNoiseMode(), sliceIndex, totalSlices, sliceEdges.size(), sliceResult.getDroppedEdgeCount(), sliceResult.isFallbackUsed()
         );
      }

      LlmNoiseGraphQuestionRecord questionRecord = new LlmNoiseGraphQuestionRecord(
         config.getProvider(),
         config.getEndpoint(),
         config.getModel(),
         systemPrompt,
         "",
         slicePrompts
      );

      return new LlmNoiseGraphResult(
         questionRecord,
         graphEdges,
         mergedDrops,
         "",
         rawResponses.toString(),
         0,
         fallbackUsed,
         true,
         sliceResults,
         config.getNoiseMode(),
         totalSlices,
         sliceSize,
         sliceSize,
         totalSlices,
         successfulRequestCount,
         fallbackPartitionCount
      );
   }

   public static List<LlmNoiseGraphEdge> serializeFullGraphEdges(DirectedPseudograph<EntityNode, EventEdge> graph) {
      List<EventEdge> orderedEdges = new ArrayList<>(graph.edgeSet());
      orderedEdges.sort(
         Comparator.comparingLong((EventEdge edge) -> edge.getSource().getId())
            .thenComparingLong(edge -> edge.getSink().getId())
            .thenComparingLong(EventEdge::getID)
      );

      List<LlmNoiseGraphEdge> result = new ArrayList<>();
      int rank = 1;
      for (EventEdge edge : orderedEdges) {
         result.add(new LlmNoiseGraphEdge(rank++, edge));
      }
      return result;
   }

   public static DirectedPseudograph<EntityNode, EventEdge> applyReportedDrops(
      NoiseGraphStage stage,
      DirectedPseudograph<EntityNode, EventEdge> graph,
      List<LlmNoiseGraphEdge> graphEdges,
      LlmNoiseGraphResult result,
      EntityNode entry,
      EntityNode anomalyNode
   ) {
      return applyReportedDrops(
         stage,
         graph,
         graphEdges,
         result,
         LlmAttackStoryContext.fromSingleEntry(entry, anomalyNode)
      );
   }

   public static DirectedPseudograph<EntityNode, EventEdge> applyReportedDrops(
      NoiseGraphStage stage,
      DirectedPseudograph<EntityNode, EventEdge> graph,
      List<LlmNoiseGraphEdge> graphEdges,
      LlmNoiseGraphResult result,
      LlmAttackStoryContext context
   ) {
      DirectedPseudograph<EntityNode, EventEdge> pruned = new DirectedPseudograph(EventEdge.class);
      for (EntityNode node : graph.vertexSet()) {
         pruned.addVertex(node);
      }

      Set<Integer> droppedRanks = result.getDroppedEdgeRanks();
      for (LlmNoiseGraphEdge graphEdge : graphEdges) {
         EventEdge edge = graphEdge.getEdge();
         if (!droppedRanks.contains(graphEdge.getEdgeRank())) {
            if (!pruned.containsVertex(edge.getSource())) {
               pruned.addVertex(edge.getSource());
            }
            if (!pruned.containsVertex(edge.getSink())) {
               pruned.addVertex(edge.getSink());
            }
            pruned.addEdge(edge.getSource(), edge.getSink(), edge);
         }
      }

      retainSharedWeaklyConnectedComponent(pruned, context == null ? Collections.<EntityNode>emptyList() : context.getSelectedEntries(), context == null ? null : context.getAnomalyNode());
      return pruned;
   }

   public static int retainSharedWeaklyConnectedComponent(
      DirectedPseudograph<EntityNode, EventEdge> graph,
      EntityNode entry,
      EntityNode anomalyNode
   ) {
      EntityNode entryNode = findGraphNode(graph, entry);
      EntityNode anomaly = findGraphNode(graph, anomalyNode);
      if (entryNode == null || anomaly == null) {
         return 0;
      }

      Set<EntityNode> keeperComponent = findWeaklyConnectedComponentContaining(graph, entryNode);
      if (keeperComponent == null || !keeperComponent.contains(anomaly)) {
         return 0;
      }

      List<EntityNode> toRemove = new ArrayList<>();
      for (EntityNode node : new ArrayList<>(graph.vertexSet())) {
         if (!keeperComponent.contains(node)) {
            toRemove.add(node);
         }
      }

      for (EntityNode node : toRemove) {
         graph.removeVertex(node);
      }
      return toRemove.size();
   }

   public static int retainSharedWeaklyConnectedComponent(
      DirectedPseudograph<EntityNode, EventEdge> graph,
      List<EntityNode> entries,
      EntityNode anomalyNode
   ) {
      EntityNode anomaly = findGraphNode(graph, anomalyNode);
      if (anomaly == null || entries == null || entries.isEmpty()) {
         return 0;
      }

      Set<EntityNode> keeperComponent = findWeaklyConnectedComponentContaining(graph, anomaly);
      if (keeperComponent == null || !containsAnyNode(keeperComponent, entries)) {
         return 0;
      }

      List<EntityNode> toRemove = new ArrayList<>();
      for (EntityNode node : new ArrayList<>(graph.vertexSet())) {
         if (!keeperComponent.contains(node)) {
            toRemove.add(node);
         }
      }
      for (EntityNode node : toRemove) {
         graph.removeVertex(node);
      }
      return toRemove.size();
   }

   private static boolean containsAnyNode(Set<EntityNode> nodes, List<EntityNode> targets) {
      for (EntityNode target : targets) {
         if (findGraphNodeInSet(nodes, target) != null) {
            return true;
         }
      }
      return false;
   }

   private static EntityNode findGraphNodeInSet(Set<EntityNode> nodes, EntityNode target) {
      if (target == null) {
         return null;
      }
      for (EntityNode node : nodes) {
         if (isSameNode(node, target)) {
            return node;
         }
      }
      return null;
   }

   private static boolean isSameNode(EntityNode left, EntityNode right) {
      return left != null && right != null && left.getId() == right.getId();
   }

   private static EntityNode findGraphNode(DirectedPseudograph<EntityNode, EventEdge> graph, EntityNode target) {
      if (target == null) {
         return null;
      }
      for (EntityNode node : graph.vertexSet()) {
         if (isSameNode(node, target)) {
            return node;
         }
      }
      return null;
   }

   private static Set<EntityNode> findWeaklyConnectedComponentContaining(
      DirectedPseudograph<EntityNode, EventEdge> graph,
      EntityNode start
   ) {
      if (start == null || !graph.containsVertex(start)) {
         return null;
      }

      Set<EntityNode> visited = new HashSet<>();
      ArrayDeque<EntityNode> queue = new ArrayDeque<>();
      visited.add(start);
      queue.add(start);

      while (!queue.isEmpty()) {
         EntityNode current = queue.removeFirst();
         for (EventEdge edge : graph.outgoingEdgesOf(current)) {
            EntityNode next = edge.getSink();
            if (visited.add(next)) {
               queue.addLast(next);
            }
         }
         for (EventEdge edge : graph.incomingEdgesOf(current)) {
            EntityNode next = edge.getSource();
            if (visited.add(next)) {
               queue.addLast(next);
            }
         }
      }

      return visited;
   }

   private static LlmNoiseGraphResult parseResponse(
      NoiseGraphStage stage,
      LlmNoiseGraphQuestionRecord questionRecord,
      List<LlmNoiseGraphEdge> graphEdges,
      LlmConnectivityProbe.LlmChatResult chatResult,
      LlmConfig.NoiseMode noiseMode,
      int llmRequestCount
   ) {
      try {
         return parseResult(stage, questionRecord, graphEdges, chatResult, noiseMode, llmRequestCount);
      } catch (RuntimeException ex) {
         return fallbackResult(
            stage,
            questionRecord,
            graphEdges,
            chatResult.getMessageText(),
            chatResult.getStatusCode(),
            true,
            noiseMode,
            llmRequestCount
         );
      }
   }

   private static LlmNoiseGraphResult parseResult(
      NoiseGraphStage stage,
      LlmNoiseGraphQuestionRecord questionRecord,
      List<LlmNoiseGraphEdge> graphEdges,
      LlmConnectivityProbe.LlmChatResult chatResult,
      LlmConfig.NoiseMode noiseMode,
      int llmRequestCount
   ) {
      String messageText = chatResult.getMessageText() == null ? "" : chatResult.getMessageText().trim();
      ParsedNoiseResponse parsedResponse = parseNoiseResponse(messageText, "SUMMARY");
      List<LlmNoiseGraphDrop> droppedEdges = materializeDrops(graphEdges, parsedResponse.dropReasons);

      return new LlmNoiseGraphResult(
         questionRecord,
         graphEdges,
         droppedEdges,
         parsedResponse.summary,
         messageText,
         chatResult.getStatusCode(),
         false,
         true,
         new ArrayList<LlmNoiseGraphBatchResult>(),
         noiseMode,
         llmRequestCount,
         null,
         graphEdges.size(),
         1,
         1,
         0
      );
   }

   private static LlmNoiseGraphBatchResult parseBatchResponse(
      NoiseGraphStage stage,
      int batchIndex,
      List<LlmNoiseGraphEdge> batchEdges,
      String previousSummary,
      LlmConnectivityProbe.LlmChatResult chatResult,
      int maxSummaryChars
   ) {
      String messageText = chatResult.getMessageText() == null ? "" : chatResult.getMessageText().trim();
      ParsedNoiseResponse parsedResponse = parseNoiseResponse(messageText, "UPDATED_SUMMARY");
      List<LlmNoiseGraphDrop> droppedEdges = materializeDrops(batchEdges, parsedResponse.dropReasons);

      return new LlmNoiseGraphBatchResult(
         batchIndex,
         batchEdges.get(0).getEdgeRank(),
         batchEdges.get(batchEdges.size() - 1).getEdgeRank(),
         previousSummary,
         truncateSummary(parsedResponse.summary, maxSummaryChars),
         messageText,
         chatResult.getStatusCode(),
         false,
         droppedEdges
      );
   }

   private static LlmNoiseGraphBatchResult parseSliceResponse(
      NoiseGraphStage stage,
      int sliceIndex,
      List<LlmNoiseGraphEdge> sliceEdges,
      LlmConnectivityProbe.LlmChatResult chatResult
   ) {
      String messageText = chatResult.getMessageText() == null ? "" : chatResult.getMessageText().trim();
      ParsedNoiseResponse parsedResponse = parseNoiseResponse(messageText, null);
      List<LlmNoiseGraphDrop> droppedEdges = materializeDrops(sliceEdges, parsedResponse.dropReasons);

      return new LlmNoiseGraphBatchResult(
         sliceIndex,
         sliceEdges.get(0).getEdgeRank(),
         sliceEdges.get(sliceEdges.size() - 1).getEdgeRank(),
         "",
         "",
         messageText,
         chatResult.getStatusCode(),
         false,
         droppedEdges
      );
   }

   private static LlmNoiseGraphBatchResult fallbackBatchResult(
      NoiseGraphStage stage,
      int batchIndex,
      List<LlmNoiseGraphEdge> batchEdges,
      String previousSummary,
      String updatedSummary,
      String rawResponseText,
      int statusCode,
      int maxSummaryChars
   ) {
      return new LlmNoiseGraphBatchResult(
         batchIndex,
         batchEdges.get(0).getEdgeRank(),
         batchEdges.get(batchEdges.size() - 1).getEdgeRank(),
         previousSummary,
         truncateSummary(updatedSummary, maxSummaryChars),
         rawResponseText,
         statusCode,
         true,
         Collections.<LlmNoiseGraphDrop>emptyList()
      );
   }

   private static String truncateSummary(String summary, int maxChars) {
      if (summary == null) {
         return "";
      }
      String trimmed = summary.trim();
      if (maxChars <= 0 || trimmed.length() <= maxChars) {
         return trimmed;
      }
      return trimmed.substring(0, maxChars).trim();
   }

   private static void appendRawBatchResponse(StringBuilder builder, int batchIndex, String rawResponse) {
      if (builder.length() > 0) {
         builder.append(System.lineSeparator()).append(System.lineSeparator());
      }
      builder.append("=== BATCH ").append(batchIndex).append(" ===").append(System.lineSeparator());
      builder.append(rawResponse == null ? "" : rawResponse.trim());
   }

   private static void appendRawSliceResponse(StringBuilder builder, int sliceIndex, String rawResponse) {
      if (builder.length() > 0) {
         builder.append(System.lineSeparator()).append(System.lineSeparator());
      }
      builder.append("=== SLICE ").append(sliceIndex).append(" ===").append(System.lineSeparator());
      builder.append(rawResponse == null ? "" : rawResponse.trim());
   }

   private static void logPartitionResult(
      LlmConfig.NoiseMode noiseMode,
      int partitionIndex,
      int partitionCount,
      int inputEdgeCount,
      int droppedEdgeCount,
      boolean fallbackUsed
   ) {
      System.out.println(
         "LLM noise partition: mode="
            + noiseMode.getConfigValue()
            + ", partition="
            + partitionIndex
            + "/"
            + partitionCount
            + ", input_edges="
            + inputEdgeCount
            + ", dropped_edges="
            + droppedEdgeCount
            + ", retained_edges="
            + Math.max(0, inputEdgeCount - droppedEdgeCount)
            + ", fallback="
            + fallbackUsed
      );
   }

   private static ParsedNoiseResponse parseNoiseResponse(String messageText, String summaryHeader) {
      Map<Integer, String> dropReasons = new LinkedHashMap<>();
      String summary = "";
      boolean decisionsSeen = false;
      boolean inDecisions = false;
      boolean inSummary = false;
      boolean noDropSeen = false;

      for (String rawLine : messageText.split("\\R")) {
         String line = rawLine.trim();
         if (line.isEmpty()) continue;
         if ("DECISIONS".equals(line)) {
            if (decisionsSeen) throw new IllegalStateException("DECISIONS section was repeated.");
            decisionsSeen = true;
            inDecisions = true;
            inSummary = false;
            continue;
         }
         if (summaryHeader != null && line.regionMatches(true, 0, summaryHeader, 0, summaryHeader.length())) {
            if (!decisionsSeen) throw new IllegalStateException(summaryHeader + " appeared before DECISIONS.");
            inDecisions = false;
            inSummary = true;
            String inlineSummary = line.substring(summaryHeader.length()).trim();
            if (!inlineSummary.isEmpty() && summary.isEmpty()) summary = inlineSummary;
            continue;
         }
         if (inDecisions) {
            if ("NO_DROP".equals(line)) {
               if (noDropSeen || !dropReasons.isEmpty()) throw new IllegalStateException("NO_DROP cannot be combined with DROP lines.");
               noDropSeen = true;
               continue;
            }
            Matcher matcher = DROP_LINE_PATTERN.matcher(line);
            if (!matcher.matches()) throw new IllegalStateException("Invalid DECISIONS line: " + line);
            if (noDropSeen) throw new IllegalStateException("DROP cannot be combined with NO_DROP.");
            int edgeRank = Integer.parseInt(matcher.group(1));
            String reason = matcher.group(2).trim();
            if (dropReasons.put(edgeRank, reason) != null) throw new IllegalStateException("DROP rank was repeated: " + edgeRank);
            continue;
         }
         if (inSummary && summary.isEmpty()) {
            summary = line;
            continue;
         }
         if (!inSummary) throw new IllegalStateException("Expected DECISIONS section before: " + line);
      }

      if (!decisionsSeen || (!noDropSeen && dropReasons.isEmpty())) {
         throw new IllegalStateException("DECISIONS must contain DROP lines or NO_DROP.");
      }
      return new ParsedNoiseResponse(dropReasons, summary);
   }

   private static List<LlmNoiseGraphDrop> materializeDrops(
      List<LlmNoiseGraphEdge> graphEdges,
      Map<Integer, String> dropReasons
   ) {
      Set<Integer> knownRanks = new HashSet<>();
      for (LlmNoiseGraphEdge graphEdge : graphEdges) knownRanks.add(graphEdge.getEdgeRank());
      for (Integer edgeRank : dropReasons.keySet()) {
         if (!knownRanks.contains(edgeRank)) throw new IllegalStateException("DROP rank is outside the current graph: " + edgeRank);
      }

      List<LlmNoiseGraphDrop> drops = new ArrayList<>();
      for (LlmNoiseGraphEdge graphEdge : graphEdges) {
         int edgeRank = graphEdge.getEdgeRank();
         String reason = dropReasons.get(edgeRank);
         if (reason != null) drops.add(new LlmNoiseGraphDrop(graphEdge.getEdge().getID(), edgeRank, reason));
      }
      return drops;
   }

   private static final class ParsedNoiseResponse {
      private final Map<Integer, String> dropReasons;
      private final String summary;

      private ParsedNoiseResponse(Map<Integer, String> dropReasons, String summary) {
         this.dropReasons = dropReasons;
         this.summary = summary == null ? "" : summary;
      }
   }

   private static LlmNoiseGraphResult fallbackResult(
      NoiseGraphStage stage,
      LlmNoiseGraphQuestionRecord questionRecord,
      List<LlmNoiseGraphEdge> graphEdges,
      String rawResponseText,
      int statusCode,
      boolean llmInvoked,
      LlmConfig.NoiseMode noiseMode,
      int llmRequestCount
   ) {
      return new LlmNoiseGraphResult(
         questionRecord,
         graphEdges,
         Collections.<LlmNoiseGraphDrop>emptyList(),
         "Fallback retained all edges.",
         rawResponseText,
         statusCode,
         true,
         llmInvoked,
         new ArrayList<LlmNoiseGraphBatchResult>(),
         noiseMode,
         llmRequestCount,
         null,
         graphEdges.size(),
         1,
         0,
         1
      );
   }
}
