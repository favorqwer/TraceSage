package traversal;

import traversal.neo4j.Neo4jTraversal;
import traversal.neo4jserver.Neo4jServerTraversal;

public class DBTraversalFactory {
   public DBTraversal getInstance(String db) {
      if (db.equalsIgnoreCase("neo4j")) {
         return new Neo4jTraversal();
      } else if (db.equalsIgnoreCase("neo4jserver")) {
         return new Neo4jServerTraversal();
      } else {
         return null;
      }
   }
}
