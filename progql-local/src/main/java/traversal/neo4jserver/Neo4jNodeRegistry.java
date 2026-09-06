package traversal.neo4jserver;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import model.EntityNode;
import model.FileEntity;
import model.NetworkEntity;
import model.ProcessEntity;
import org.neo4j.driver.Record;
import org.neo4j.driver.Value;

/**
 * Deterministic numeric identity for Neo4j graph vertices.
 *
 * The engine (EntityNode equality, edge keys, baseline artifacts) is built on
 * long vertex ids. The sysdig-parser Neo4j store keys vertices by their
 * content key (Process: process_id = pid+name, File: path, Network:
 * "lip:lport->rip:rport") and carries no numeric id, so at initialization the
 * registry enumerates every vertex once, in a content-determined order
 * (label, then MERGE key ascending), and assigns ids 1..N. The same store
 * content therefore always yields the same ids on every machine and re-run.
 *
 * The registry also caches key -> EntityNode so that repeated Cypher results
 * map to the same EntityNode instance (required by EntityNode.equals).
 */
public class Neo4jNodeRegistry {
   public static final String LABEL_PROCESS = "Process";
   public static final String LABEL_FILE = "File";
   public static final String LABEL_NETWORK = "Network";

   private final Map<String, Long> idByKey = new HashMap<>();
   private final Map<String, String> labelByKey = new HashMap<>();
   private final Map<Long, EntityNode> nodeById = new HashMap<>();
   private final Map<Long, String> keyById = new HashMap<>();

   /** Loads all vertices from the store and assigns deterministic ids. */
   public void load(Neo4jSession sessions) {
      long nextId = 1L;
      nextId = this.loadLabel(sessions, LABEL_PROCESS, "process_id", nextId);
      nextId = this.loadLabel(sessions, LABEL_FILE, "file_id", nextId);
      this.loadLabel(sessions, LABEL_NETWORK, "network_id", nextId);
   }

   private long loadLabel(Neo4jSession sessions, String label, String keyProp, long nextId) {
      List<Record> records = sessions.run(
         "MATCH (n:" + label + ") RETURN n." + keyProp + " AS key, n AS vertex ORDER BY key"
      );
      for (Record record : records) {
         String key = record.get("key").asString();
         String composite = label + "|" + key;
         this.idByKey.put(composite, nextId);
         this.labelByKey.put(composite, label);
         this.keyById.put(nextId, composite);
         nextId++;
      }
      return nextId;
   }

   public int size() {
      return this.idByKey.size();
   }

   /** Materializes (and caches) the EntityNode for one vertex key. */
   public EntityNode nodeByKey(String label, String key, Map<String, Object> properties) {
      String composite = label + "|" + key;
      Long id = this.idByKey.get(composite);
      if (id == null) {
         System.err.println("Neo4j vertex not registered during id assignment: " + composite);
         return null;
      }

      EntityNode cached = this.nodeById.get(id);
      if (cached != null) {
         return cached;
      }

      EntityNode node = this.buildNode(label, properties, id);
      if (node != null) {
         this.nodeById.put(id, node);
      }
      return node;
   }

   /** Convenience overload when only the key is known (properties re-read lazily). */
   public EntityNode nodeByKey(String label, String key, Neo4jSession sessions) {
      String composite = label + "|" + key;
      Long id = this.idByKey.get(composite);
      if (id == null) {
         return null;
      }
      EntityNode cached = this.nodeById.get(id);
      if (cached != null) {
         return cached;
      }
      List<Record> records = sessions.run(
         "MATCH (n:" + label + " {" + keyProperty(label) + ": $key}) RETURN n LIMIT 1", "key", key
      );
      if (records.isEmpty()) {
         return null;
      }
      return this.nodeByKey(label, key, records.get(0).get("n").asMap());
   }

   public EntityNode nodeById(long id, Neo4jSession sessions) {
      EntityNode cached = this.nodeById.get(id);
      if (cached != null) {
         return cached;
      }
      String composite = this.keyById.get(id);
      if (composite == null) {
         return null;
      }
      int split = composite.indexOf('|');
      return this.nodeByKey(composite.substring(0, split), composite.substring(split + 1), sessions);
   }

   public String keyOf(long id) {
      String composite = this.keyById.get(id);
      return composite == null ? null : composite.substring(composite.indexOf('|') + 1);
   }

   public String labelOf(long id) {
      String composite = this.keyById.get(id);
      return composite == null ? null : composite.substring(0, composite.indexOf('|'));
   }

   public List<Long> allIds(String label) {
      List<Long> ids = new ArrayList<>();
      for (Map.Entry<String, Long> entry : this.idByKey.entrySet()) {
         if (entry.getKey().startsWith(label + "|")) {
            ids.add(entry.getValue());
         }
      }
      ids.sort(Long::compare);
      return ids;
   }

   public static String keyProperty(String label) {
      switch (label) {
         case LABEL_PROCESS:
            return "process_id";
         case LABEL_FILE:
            return "file_id";
         case LABEL_NETWORK:
            return "network_id";
         default:
            throw new IllegalArgumentException("Unknown vertex label: " + label);
      }
   }

   private EntityNode buildNode(String label, Map<String, Object> properties, long id) {
      if (LABEL_PROCESS.equals(label)) {
         String pid = stringValue(properties, "pid");
         String name = stringValue(properties, "name");
         String exePath = stringValue(properties, "exepath");
         ProcessEntity p = new ProcessEntity(pid, "", "", "", name, id, exePath, "", "", 0L, "", "");
         return new EntityNode(p);
      }
      if (LABEL_FILE.equals(label)) {
         String path = stringValue(properties, "path");
         FileEntity f = new FileEntity("", "", path, id, "", "");
         return new EntityNode(f);
      }
      if (LABEL_NETWORK.equals(label)) {
         NetworkEntity n = new NetworkEntity(
            stringValue(properties, "lip"),
            stringValue(properties, "rip"),
            stringValue(properties, "lport"),
            stringValue(properties, "rport"),
            id,
            "",
            ""
         );
         return new EntityNode(n);
      }
      return null;
   }

   private static String stringValue(Map<String, Object> properties, String key) {
      Object value = properties.get(key);
      return value == null ? "" : value.toString();
   }

   /** Utility used when a Cypher row hands back a full node value. */
   public static Map<String, Object> valueMap(Value nodeValue) {
      return nodeValue.asMap();
   }
}
