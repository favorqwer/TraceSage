package util;

import java.util.Collections;
import java.util.ArrayList;
import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;
import model.EventEdge;

public final class ProcessSubgraphBuildResult {
   private final Map<Long, ProcessSubgraph> subgraphs;
   private final Map<EventEdge, Long> ownerProcessIds;
   private final int upstreamDegreeThreshold;
   private final int downstreamDegreeThreshold;
   private final Map<String, Integer> pruningHitCounts;
   private final Map<String, Integer> pruningSubgraphCounts;
   private final Map<String, Integer> edgeTypeCounts;
   private final Map<Integer, Integer> upstreamDepthCounts;
   private final Map<Integer, Integer> downstreamDepthCounts;
   private final List<Long> upstreamMaxDepthRootIds;
   private final List<Long> downstreamMaxDepthRootIds;
   private final Map<Long, Integer> upstreamDegrees;
   private final Map<Long, Integer> downstreamDegrees;
   private final Map<Long, String> processLabels;

   ProcessSubgraphBuildResult(Map<Long, ProcessSubgraph> subgraphs, Map<EventEdge, Long> ownerProcessIds,
      int upstreamDegreeThreshold, int downstreamDegreeThreshold, Map<String, Integer> pruningHitCounts,
      Map<String, Integer> pruningSubgraphCounts, Map<String, Integer> edgeTypeCounts,
      Map<Integer, Integer> upstreamDepthCounts, Map<Integer, Integer> downstreamDepthCounts,
      List<Long> upstreamMaxDepthRootIds, List<Long> downstreamMaxDepthRootIds, Map<Long, Integer> upstreamDegrees,
      Map<Long, Integer> downstreamDegrees, Map<Long, String> processLabels) {
      this.subgraphs = Collections.unmodifiableMap(new LinkedHashMap<>(subgraphs));
      this.ownerProcessIds = Collections.unmodifiableMap(new LinkedHashMap<>(ownerProcessIds));
      this.upstreamDegreeThreshold = upstreamDegreeThreshold;
      this.downstreamDegreeThreshold = downstreamDegreeThreshold;
      this.pruningHitCounts = Collections.unmodifiableMap(new LinkedHashMap<>(pruningHitCounts));
      this.pruningSubgraphCounts = Collections.unmodifiableMap(new LinkedHashMap<>(pruningSubgraphCounts));
      this.edgeTypeCounts = Collections.unmodifiableMap(new LinkedHashMap<>(edgeTypeCounts));
      this.upstreamDepthCounts = Collections.unmodifiableMap(new LinkedHashMap<>(upstreamDepthCounts));
      this.downstreamDepthCounts = Collections.unmodifiableMap(new LinkedHashMap<>(downstreamDepthCounts));
      this.upstreamMaxDepthRootIds = Collections.unmodifiableList(new ArrayList<>(upstreamMaxDepthRootIds));
      this.downstreamMaxDepthRootIds = Collections.unmodifiableList(new ArrayList<>(downstreamMaxDepthRootIds));
      this.upstreamDegrees = Collections.unmodifiableMap(new LinkedHashMap<>(upstreamDegrees));
      this.downstreamDegrees = Collections.unmodifiableMap(new LinkedHashMap<>(downstreamDegrees));
      this.processLabels = Collections.unmodifiableMap(new LinkedHashMap<>(processLabels));
   }

   public Map<Long, ProcessSubgraph> getSubgraphs() { return this.subgraphs; }
   public Map<EventEdge, Long> getOwnerProcessIds() { return this.ownerProcessIds; }
   public int getUpstreamDegreeThreshold() { return this.upstreamDegreeThreshold; }
   public int getDownstreamDegreeThreshold() { return this.downstreamDegreeThreshold; }
   public Map<String, Integer> getPruningHitCounts() { return this.pruningHitCounts; }
   public Map<String, Integer> getPruningSubgraphCounts() { return this.pruningSubgraphCounts; }
   public Map<String, Integer> getEdgeTypeCounts() { return this.edgeTypeCounts; }
   public Map<Integer, Integer> getUpstreamDepthCounts() { return this.upstreamDepthCounts; }
   public Map<Integer, Integer> getDownstreamDepthCounts() { return this.downstreamDepthCounts; }
   public List<Long> getUpstreamMaxDepthRootIds() { return this.upstreamMaxDepthRootIds; }
   public List<Long> getDownstreamMaxDepthRootIds() { return this.downstreamMaxDepthRootIds; }
   public Map<Long, Integer> getUpstreamDegrees() { return this.upstreamDegrees; }
   public Map<Long, Integer> getDownstreamDegrees() { return this.downstreamDegrees; }
   public Map<Long, String> getProcessLabels() { return this.processLabels; }
}
