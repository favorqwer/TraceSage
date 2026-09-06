package util.llm;

import model.EntityNode;
import model.EventEdge;
import org.jgrapht.graph.DirectedPseudograph;

public class LlmCoreNoiseFilter {
   private final LlmNoiseGraphSelector noiseGraphSelector;

   public LlmCoreNoiseFilter() {
      this(new LlmNoiseGraphSelector());
   }

   public LlmCoreNoiseFilter(LlmNoiseGraphSelector noiseGraphSelector) {
      this.noiseGraphSelector = noiseGraphSelector;
   }

   public LlmCoreNoiseFilterResult filter(
      EntityNode entry,
      EntityNode anomalyNode,
      DirectedPseudograph<EntityNode, EventEdge> filteredIntersectGraph
   ) {
      return filter(LlmAttackStoryContext.fromSingleEntry(entry, anomalyNode), filteredIntersectGraph);
   }

   public LlmCoreNoiseFilterResult filter(
      LlmAttackStoryContext context,
      DirectedPseudograph<EntityNode, EventEdge> filteredIntersectGraph
   ) {
      return filter(context, filteredIntersectGraph, true);
   }

   /**
    * Classifies an intersection graph after an optional deterministic cleanup stage.
    */
   public LlmCoreNoiseFilterResult filter(
      LlmAttackStoryContext context,
      DirectedPseudograph<EntityNode, EventEdge> filteredIntersectGraph,
      boolean applyPrefilter
   ) {
      DirectedPseudograph<EntityNode, EventEdge> safeCoreGraph = emptyGraphIfNull(filteredIntersectGraph);
      LlmConfig config = LlmConfig.load();
      DirectedPseudograph<EntityNode, EventEdge> graphForCoreClassification = safeCoreGraph;
      if (applyPrefilter && config.isPrefilterEnabled()) {
         LlmEdgePrefilter prefilter = new LlmEdgePrefilter();
         LlmEdgePrefilter.GraphPrefilterResult prefilterResult = prefilter.filterGraph(safeCoreGraph);
         System.out.println("LLM core prefilter summary: " + LlmEdgePrefilter.summarize(prefilterResult));
         graphForCoreClassification = prefilterResult.getKeepGraph();
      }

      LlmNoiseGraphResult coreResult = this.noiseGraphSelector.classifyGraph(
         LlmNoiseGraphSelector.NoiseGraphStage.CORE,
         context,
         graphForCoreClassification,
         ""
      );
      DirectedPseudograph<EntityNode, EventEdge> coreFilteredGraph = LlmNoiseGraphSelector.applyReportedDrops(
         LlmNoiseGraphSelector.NoiseGraphStage.CORE,
         graphForCoreClassification,
         LlmNoiseGraphSelector.serializeFullGraphEdges(graphForCoreClassification),
         coreResult,
         context
      );

      return new LlmCoreNoiseFilterResult(coreResult, coreFilteredGraph, coreFilteredGraph);
   }

   private static DirectedPseudograph<EntityNode, EventEdge> emptyGraphIfNull(DirectedPseudograph<EntityNode, EventEdge> graph) {
      return graph == null ? new DirectedPseudograph(EventEdge.class) : graph;
   }

   public static final class LlmCoreNoiseFilterResult {
      private final LlmNoiseGraphResult coreResult;
      private final DirectedPseudograph<EntityNode, EventEdge> coreFilteredGraph;
      private final DirectedPseudograph<EntityNode, EventEdge> finalGraph;

      private LlmCoreNoiseFilterResult(
         LlmNoiseGraphResult coreResult,
         DirectedPseudograph<EntityNode, EventEdge> coreFilteredGraph,
         DirectedPseudograph<EntityNode, EventEdge> finalGraph
      ) {
         this.coreResult = coreResult;
         this.coreFilteredGraph = coreFilteredGraph;
         this.finalGraph = finalGraph;
      }

      public LlmNoiseGraphResult getCoreResult() {
         return this.coreResult;
      }

      public DirectedPseudograph<EntityNode, EventEdge> getCoreFilteredGraph() {
         return this.coreFilteredGraph;
      }

      public DirectedPseudograph<EntityNode, EventEdge> getFinalGraph() {
         return this.finalGraph;
      }
   }
}
