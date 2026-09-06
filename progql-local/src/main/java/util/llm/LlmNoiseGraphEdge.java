package util.llm;

import java.util.Locale;
import model.EntityNode;
import model.EventEdge;
import org.json.JSONObject;

public class LlmNoiseGraphEdge {
   private final int edgeRank;
   private final EventEdge edge;
   private final String compactEdgeString;

   public LlmNoiseGraphEdge(int edgeRank, EventEdge edge) {
      this.edgeRank = edgeRank;
      this.edge = edge;
      this.compactEdgeString = formatCompactEdge(edge);
   }

   public int getEdgeRank() {
      return this.edgeRank;
   }

   public EventEdge getEdge() {
      return this.edge;
   }

   public String getCompactEdgeString() {
      return this.compactEdgeString;
   }

   public JSONObject toJsonObject() {
      return new JSONObject()
         .put("edge_rank", this.edgeRank)
         .put("edge_id", this.edge.getID())
         .put("event_type", this.edge.getEvent())
         .put("source_node", formatNode(this.edge.getSource()))
         .put("sink_node", formatNode(this.edge.getSink()))
         .put("compact_edge", this.compactEdgeString);
   }

   public static String formatCompactEdge(EventEdge edge) {
      return formatCompactNode(edge.getSource()) + "--" + edge.getEvent() + "-->" + formatCompactNode(edge.getSink());
   }

   private static String formatCompactNode(EntityNode node) {
      return "[" + resolveNodeType(node) + "|" + node.getSignature() + "]";
   }

   private static JSONObject formatNode(EntityNode node) {
      return new JSONObject()
         .put("id", node.getId())
         .put("type", resolveNodeType(node))
         .put("signature", node.getSignature())
         .put("reputation", Double.parseDouble(String.format(Locale.US, "%.6f", node.getReputation())));
   }

   private static String resolveNodeType(EntityNode node) {
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
