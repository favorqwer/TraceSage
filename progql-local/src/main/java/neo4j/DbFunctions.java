package neo4j;

import java.io.File;
import java.util.Map;
import java.util.Map.Entry;
import org.neo4j.driver.Driver;
import org.neo4j.driver.Result;
import org.neo4j.driver.Session;
import org.neo4j.graphdb.GraphDatabaseService;
import org.neo4j.graphdb.Transaction;
import org.neo4j.graphdb.factory.GraphDatabaseFactory;

public class DbFunctions {
   public static GraphDatabaseService initDatabase(File databaseDirectory) {
      return new GraphDatabaseFactory().newEmbeddedDatabase(databaseDirectory);
   }

   public static void registerShutdownHook(final GraphDatabaseService graphDb) {
      Runtime.getRuntime().addShutdownHook(new Thread() {
         @Override
         public void run() {
            graphDb.shutdown();
         }
      });
   }

   public static void execute(Driver driver, String cypherQuery) {
      String rows = "";
      Session session = driver.session();

      for (Result result = session.run(cypherQuery); result.hasNext(); rows = rows + "\n") {
         Map<String, Object> row = result.next().asMap();

         for (Entry<String, Object> column : row.entrySet()) {
            rows = rows + column.getKey() + ": " + column.getValue() + ";";
         }
      }

      session.close();
   }

   public static void embeddedExecute(GraphDatabaseService graphDb, String cypherQuery) {
      try (Transaction tx = graphDb.beginTx(); org.neo4j.graphdb.Result result = graphDb.execute(cypherQuery)) {
         String rows = "";
         while (result.hasNext()) {
            Map<String, Object> row = result.next();
            for (Entry<String, Object> column : row.entrySet()) {
               rows = rows + column.getKey() + ": " + column.getValue() + "; ";
            }
            rows = rows + "\n";
         }
      }
   }
}
