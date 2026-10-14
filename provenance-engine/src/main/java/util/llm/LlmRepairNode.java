package util.llm;

import model.EntityNode;

public class LlmRepairNode {
   private final int rank;
   private final EntityNode node;

   public LlmRepairNode(int rank, EntityNode node) {
      this.rank = rank;
      this.node = node;
   }

   public int getRank() {
      return this.rank;
   }

   public EntityNode getNode() {
      return this.node;
   }

   public String toLine() {
      return "Node #" + this.rank + " " + formatNode(this.node);
   }

   private static String formatNode(EntityNode node) {
      if (node == null) {
         return "[Unknown|]";
      }
      return "[" + resolveNodeType(node) + "|" + node.getSignature() + "]";
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
