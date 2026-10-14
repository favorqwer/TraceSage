package traversal.neo4jserver;

import java.util.List;
import java.util.Map;
import org.neo4j.driver.Record;
import org.neo4j.driver.Session;

/**
 * Thin wrapper over a Neo4j driver session. Every query is fully materialized
 * into a record list so callers never touch live cursors and each traversal
 * step sees a stable snapshot; this mirrors the JDBC PreparedStatement ->
 * ResultSet flow of the relational expanders.
 */
public class Neo4jSession implements AutoCloseable {
   private final Session session;

   public Neo4jSession(Session session) {
      this.session = session;
   }

   public List<Record> run(String cypher) {
      return this.session.run(cypher).list();
   }

   public List<Record> run(String cypher, Map<String, Object> parameters) {
      return this.session.run(cypher, parameters).list();
   }

   public <T> List<Record> run(String cypher, String key, T value) {
      return this.session.run(cypher, Map.of(key, value)).list();
   }

   @Override
   public void close() {
      this.session.close();
   }
}
