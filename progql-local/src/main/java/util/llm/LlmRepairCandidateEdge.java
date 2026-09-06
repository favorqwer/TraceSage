package util.llm;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.LinkedHashSet;
import model.EventEdge;
import model.EntityNode;
import util.CanonicalEdgeIdentity;

public class LlmRepairCandidateEdge {
   private final int rank;
   private final int distance;
   private final EventEdge edge;
   private final String compactEdgeString;
   private final int primaryAnchorRank;
   private final long primaryAnchorNodeId;
   private final String primaryAnchorSignature;
   private final List<Integer> sourceAnchorRanks;
   private final List<String> gapIds;
   private final String semanticSignals;
   private final List<Long> equivalentEdgeIds;

   public LlmRepairCandidateEdge(
      int rank,
      int distance,
      EventEdge edge,
      int primaryAnchorRank,
      long primaryAnchorNodeId,
      String primaryAnchorSignature,
      List<Integer> sourceAnchorRanks
   ) {
      this(rank, distance, edge, primaryAnchorRank, primaryAnchorNodeId, primaryAnchorSignature, sourceAnchorRanks,
         Collections.<String>emptyList(), "local_fallback");
   }

   public LlmRepairCandidateEdge(
      int rank,
      int distance,
      EventEdge edge,
      int primaryAnchorRank,
      long primaryAnchorNodeId,
      String primaryAnchorSignature,
      List<Integer> sourceAnchorRanks,
      List<String> gapIds,
      String semanticSignals
   ) {
      this(rank, distance, edge, primaryAnchorRank, primaryAnchorNodeId, primaryAnchorSignature, sourceAnchorRanks,
         gapIds, semanticSignals, Collections.singletonList(edge == null ? 0L : edge.getID()));
   }

   public LlmRepairCandidateEdge(
      int rank,
      int distance,
      EventEdge edge,
      int primaryAnchorRank,
      long primaryAnchorNodeId,
      String primaryAnchorSignature,
      List<Integer> sourceAnchorRanks,
      List<String> gapIds,
      String semanticSignals,
      List<Long> equivalentEdgeIds
   ) {
      this.rank = rank;
      this.distance = distance;
      this.edge = edge;
      this.compactEdgeString = LlmNoiseGraphEdge.formatCompactEdge(edge);
      this.primaryAnchorRank = primaryAnchorRank;
      this.primaryAnchorNodeId = primaryAnchorNodeId;
      this.primaryAnchorSignature = primaryAnchorSignature == null ? "" : primaryAnchorSignature;
      this.sourceAnchorRanks = sourceAnchorRanks == null ? Collections.emptyList() : new ArrayList<>(sourceAnchorRanks);
      this.gapIds = gapIds == null ? Collections.<String>emptyList() : new ArrayList<>(gapIds);
      this.semanticSignals = semanticSignals == null || semanticSignals.trim().isEmpty() ? "local_fallback" : semanticSignals.trim();
      this.equivalentEdgeIds = equivalentEdgeIds == null ? Collections.<Long>emptyList() : new ArrayList<>(new LinkedHashSet<>(equivalentEdgeIds));
   }

   public int getRank() {
      return this.rank;
   }

   public String getToken() {
      return formatToken(this.rank);
   }

   public static String formatToken(int rank) {
      return String.format(Locale.ROOT, "C%03d", rank);
   }

   public static String edgeKey(EventEdge edge) {
      return CanonicalEdgeIdentity.key(edge);
   }

   public int getDistance() {
      return this.distance;
   }

   public EventEdge getEdge() {
      return this.edge;
   }

   public String getCompactEdgeString() {
      return this.compactEdgeString;
   }

   public int getPrimaryAnchorRank() {
      return this.primaryAnchorRank;
   }

   public long getPrimaryAnchorNodeId() {
      return this.primaryAnchorNodeId;
   }

   public String getPrimaryAnchorSignature() {
      return this.primaryAnchorSignature;
   }

   public List<Integer> getSourceAnchorRanks() {
      return this.sourceAnchorRanks;
   }

   public List<String> getGapIds() { return this.gapIds; }
   public String getSemanticSignals() { return this.semanticSignals; }
   public List<Long> getEquivalentEdgeIds() { return this.equivalentEdgeIds; }

   public String toLine() {
      return "Candidate "
         + getToken()
         + System.lineSeparator()
         + "provenance_edge_id="
         + this.edge.getID()
         + System.lineSeparator()
         + "equivalent_edge_ids="
         + this.equivalentEdgeIds
         + System.lineSeparator()
         + "equivalent_event_count="
         + this.equivalentEdgeIds.size()
         + System.lineSeparator()
         + "source_node_id="
         + this.edge.getSource().getId()
         + System.lineSeparator()
         + "sink_node_id="
         + this.edge.getSink().getId()
         + System.lineSeparator()
         + "gap_ids="
         + formatGapIds(this.gapIds)
         + System.lineSeparator()
         + "anchor_node_id="
         + this.primaryAnchorNodeId
         + System.lineSeparator()
         + "anchor=Node#"
         + this.primaryAnchorRank
         + " anchors="
         + formatAnchorRanks(this.sourceAnchorRanks)
         + " distance="
         + this.distance
         + System.lineSeparator()
         + "semantic_signals="
         + this.semanticSignals
         + System.lineSeparator()
         + "edge="
         + this.compactEdgeString;
   }

   private static String formatGapIds(List<String> ids) {
      if (ids == null || ids.isEmpty()) return "none";
      StringBuilder builder = new StringBuilder();
      for (String id : ids) {
         if (id == null || id.trim().isEmpty()) continue;
         if (builder.length() > 0) builder.append(",");
         builder.append(id.trim());
      }
      return builder.length() == 0 ? "none" : builder.toString();
   }

   private static String formatAnchorRanks(List<Integer> anchorRanks) {
      if (anchorRanks == null || anchorRanks.isEmpty()) {
         return "none";
      }
      StringBuilder builder = new StringBuilder();
      for (Integer anchorRank : anchorRanks) {
         if (anchorRank == null) {
            continue;
         }
         if (builder.length() > 0) {
            builder.append(",");
         }
         builder.append("Node#").append(anchorRank.intValue());
      }
      return builder.length() == 0 ? "none" : builder.toString();
   }
}
