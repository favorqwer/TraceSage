package util;

import util.llm.LlmConfig;

public final class SubgraphConfig {
   private final int maxUpstreamDepth;
   private final int maxDownstreamDepth;
   private final double processDegreeQuantile;
   private final int processDegreeMinimum;
   private final int processDegreeMaximum;
   private final int llmEdgeFilterBatchSize;

   private SubgraphConfig(int maxUpstreamDepth, int maxDownstreamDepth, double processDegreeQuantile, int processDegreeMinimum,
      int processDegreeMaximum, int llmEdgeFilterBatchSize) {
      this.maxUpstreamDepth = maxUpstreamDepth;
      this.maxDownstreamDepth = maxDownstreamDepth;
      this.processDegreeQuantile = processDegreeQuantile;
      this.processDegreeMinimum = processDegreeMinimum;
      this.processDegreeMaximum = processDegreeMaximum;
      this.llmEdgeFilterBatchSize = llmEdgeFilterBatchSize;
   }

   public static SubgraphConfig fromLlmConfig(LlmConfig config) {
      if (config == null) throw new IllegalArgumentException("LLM config is required for subgraph noise mode.");
      return new SubgraphConfig(
         config.getSubgraphMaxUpstreamDepth(),
         config.getSubgraphMaxDownstreamDepth(),
         config.getSubgraphProcessDegreeQuantile(),
         config.getSubgraphProcessDegreeMinimum(),
         config.getSubgraphProcessDegreeMaximum(),
         config.getSubgraphEdgeFilterBatchSize()
      );
   }

   public int getMaxUpstreamDepth() { return this.maxUpstreamDepth; }
   public int getMaxDownstreamDepth() { return this.maxDownstreamDepth; }
   public double getProcessDegreeQuantile() { return this.processDegreeQuantile; }
   public int getProcessDegreeMinimum() { return this.processDegreeMinimum; }
   public int getProcessDegreeMaximum() { return this.processDegreeMaximum; }
   public int getLlmEdgeFilterBatchSize() { return this.llmEdgeFilterBatchSize; }
}
