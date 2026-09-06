package util.llm;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import model.EntityNode;
import model.EventEdge;
import org.json.JSONArray;
import org.json.JSONObject;
import org.jgrapht.graph.DirectedPseudograph;

public final class LlmEvidencePath {
   private final int pathRank;
   private final double baseScore;
   private final double selectionScore;
   private final double maxOverlap;
   private final DirectedPseudograph<EntityNode, EventEdge> graph;
   private final List<EntityNode> orderedNodes;
   private final List<EventEdge> orderedEdges;

   public LlmEvidencePath(
      int pathRank,
      double baseScore,
      double selectionScore,
      double maxOverlap,
      DirectedPseudograph<EntityNode, EventEdge> graph,
      List<EntityNode> orderedNodes,
      List<EventEdge> orderedEdges
   ) {
      this.pathRank = pathRank;
      this.baseScore = baseScore;
      this.selectionScore = selectionScore;
      this.maxOverlap = maxOverlap;
      this.graph = graph == null ? new DirectedPseudograph(EventEdge.class) : graph;
      this.orderedNodes = Collections.unmodifiableList(new ArrayList<>(orderedNodes == null ? Collections.<EntityNode>emptyList() : orderedNodes));
      this.orderedEdges = Collections.unmodifiableList(new ArrayList<>(orderedEdges == null ? Collections.<EventEdge>emptyList() : orderedEdges));
   }

   public int getPathRank() {
      return this.pathRank;
   }

   public double getBaseScore() {
      return this.baseScore;
   }

   public double getSelectionScore() {
      return this.selectionScore;
   }

   public double getMaxOverlap() {
      return this.maxOverlap;
   }

   public DirectedPseudograph<EntityNode, EventEdge> getGraph() {
      return this.graph;
   }

   public List<EntityNode> getOrderedNodes() {
      return this.orderedNodes;
   }

   public List<EventEdge> getOrderedEdges() {
      return this.orderedEdges;
   }

   public JSONObject toJsonObject() {
      JSONArray nodes = new JSONArray();
      for (EntityNode node : this.orderedNodes) {
         nodes.put(new JSONObject().put("id", node.getId()).put("signature", node.getSignature()));
      }

      JSONArray edges = new JSONArray();
      for (EventEdge edge : this.orderedEdges) {
         JSONObject edgeJson = new JSONObject()
            .put("id", edge.getID())
            .put("source_id", edge.getSource().getId())
            .put("sink_id", edge.getSink().getId())
            .put("event", edge.getEvent());
         BigDecimal start = edge.getStartTime();
         BigDecimal end = edge.getEndTime();
         edgeJson.put("start_time", start == null ? JSONObject.NULL : start);
         edgeJson.put("end_time", end == null ? JSONObject.NULL : end);
         edges.put(edgeJson);
      }

      return new JSONObject()
         .put("path_rank", this.pathRank)
         .put("base_score", this.baseScore)
         .put("selection_score", this.selectionScore)
         .put("max_overlap", this.maxOverlap)
         .put("nodes", nodes)
         .put("edges", edges);
   }
}
