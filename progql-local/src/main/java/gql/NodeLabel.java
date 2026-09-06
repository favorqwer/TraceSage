package gql;

public class NodeLabel extends Clause {
   String nodeLabel;

   public NodeLabel(String nodeLabel) {
      this.nodeLabel = nodeLabel;
   }

   public String getNodeLabel() {
      return this.nodeLabel;
   }

   public void setNodeLabel(String nodeLabel) {
      this.nodeLabel = nodeLabel;
   }

   @Override
   public String toString() {
      return this.nodeLabel;
   }
}
