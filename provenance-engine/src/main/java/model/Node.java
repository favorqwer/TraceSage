package model;

import org.neo4j.graphdb.Label;

public class Node {
   public String nodeName;
   public Label nodeLabel;

   public Node(Node.MyLabels label) {
      this.nodeLabel = label;
   }

   public Node(String nodeName, Node.MyLabels label) {
      this.nodeName = nodeName;
      this.nodeLabel = label;
   }

   public static enum MyLabels implements Label {
      File,
      Process,
      Network;
   }
}
