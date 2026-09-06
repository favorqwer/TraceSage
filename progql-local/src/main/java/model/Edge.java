package model;

public class Edge {
   String edgeName;
   String property;

   public Edge(String edgeName) {
      this.edgeName = edgeName;
   }

   public String getEdgeName() {
      return this.edgeName;
   }

   public String getProperty() {
      return this.property;
   }

   public void setProperty(String property) {
      this.property = property;
   }
}
