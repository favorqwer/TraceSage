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
 * long vertex ids. The provenance-parser Neo4j store keys vertices by their
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
      String procCypher = "MATCH (n:" + LABEL_PROCESS + ") RETURN CASE "
         + "WHEN n.process_id IS NOT NULL THEN n.process_id "
         + "ELSE coalesce(n.host_id, '') + '|' + coalesce(n.container_id, '') + '|' + toString(n.pid) + '|' + toString(n.start_ns) END AS key, "
         + "n AS vertex ORDER BY key";
      nextId = this.loadLabelCypher(sessions, LABEL_PROCESS, procCypher, nextId);

      String fileCypher = "MATCH (n:" + LABEL_FILE + ") RETURN CASE "
         + "WHEN n.file_id IS NOT NULL THEN n.file_id "
         + "ELSE coalesce(n.host_id, '') + '|' + coalesce(n.container_id, '') + '|' + coalesce(n.path, '') END AS key, "
         + "n AS vertex ORDER BY key";
      nextId = this.loadLabelCypher(sessions, LABEL_FILE, fileCypher, nextId);

      String netCypher = "MATCH (n:" + LABEL_NETWORK + ") RETURN CASE "
         + "WHEN n.network_id IS NOT NULL THEN n.network_id "
         + "ELSE coalesce(n.host_id, '') + '|' + coalesce(n.endpoints, '') END AS key, "
         + "n AS vertex ORDER BY key";
      this.loadLabelCypher(sessions, LABEL_NETWORK, netCypher, nextId);
   }

   private long loadLabelCypher(Neo4jSession sessions, String label, String cypher, long nextId) {
      List<Record> records = sessions.run(cypher);
      for (Record record : records) {
         String key = record.get("key").asString();
         String composite = label + "|" + key;
         this.idByKey.put(composite, nextId);
         this.labelByKey.put(composite, label);
         this.keyById.put(nextId, composite);
         EntityNode node = this.buildNode(label, record.get("vertex").asMap(), nextId);
         if (node != null) {
            this.nodeById.put(nextId, node);
         }
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
      Map<String, Object> params = new HashMap<>();
      String matchPattern = matchCurClause("n", label, key, params);
      List<Record> records = sessions.run(
         "MATCH " + matchPattern + " RETURN n LIMIT 1", params
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
         String exePath = stringValue(properties, "exe_path");
         if (exePath.isEmpty()) {
            exePath = stringValue(properties, "exepath");
         }
         String name = stringValue(properties, "name");
         if (name.isEmpty() && !exePath.isEmpty() && !exePath.equals("<NA>")) {
            int lastSlash = exePath.lastIndexOf('/');
            name = (lastSlash >= 0) ? exePath.substring(lastSlash + 1) : exePath;
         }
         if (exePath.isEmpty() && name.isEmpty()) {
            String cmdline = stringValue(properties, "cmdline");
            if (!cmdline.isEmpty()) {
               String first = cmdline.trim().split("\\s+")[0];
               if (first.startsWith("/")) {
                  exePath = first;
                  name = first.substring(first.lastIndexOf('/') + 1);
               }
            }
         }
         if (exePath.isEmpty() && name.isEmpty()) {
            exePath = "<NA>";
         }
         ProcessEntity p = new ProcessEntity(pid, "", "", "", name, id, exePath, "", "", 0L, "", "");
         return new EntityNode(p);
      }
      if (LABEL_FILE.equals(label)) {
         String path = stringValue(properties, "path");
         FileEntity f = new FileEntity("", "", path, id, "", "");
         return new EntityNode(f);
      }
      if (LABEL_NETWORK.equals(label)) {
         String endpoints = stringValue(properties, "endpoints");
         String lip = "", lport = "", rip = "", rport = "";
         if (!endpoints.isEmpty() && endpoints.contains("->")) {
            String[] parts = endpoints.split("->");
            if (parts.length == 2) {
               int colon1 = parts[0].lastIndexOf(':');
               if (colon1 > 0) {
                  lip = parts[0].substring(0, colon1);
                  lport = parts[0].substring(colon1 + 1);
               }
               int colon2 = parts[1].lastIndexOf(':');
               if (colon2 > 0) {
                  rip = parts[1].substring(0, colon2);
                  rport = parts[1].substring(colon2 + 1);
               }
            }
         } else {
            lip = stringValue(properties, "lip");
            rip = stringValue(properties, "rip");
            lport = stringValue(properties, "lport");
            rport = stringValue(properties, "rport");
         }
         NetworkEntity n = new NetworkEntity(lip, rip, lport, rport, id, "", "");
         return new EntityNode(n);
      }
      return null;
   }

   /**
    * Constructs a parameterized MATCH pattern that accurately hits Neo4j's
    * composite unique constraints (proc_key, file_key, net_key) for the new schema,
    * while falling back to single property match for the legacy schema.
    */
   public static String matchCurClause(String alias, String label, String key, Map<String, Object> params) {
      if (LABEL_PROCESS.equals(label)) {
         if (key.contains("|")) {
            String[] parts = key.split("\\|", 4);
            params.put(alias + "_h", parts[0]);
            params.put(alias + "_c", parts[1]);
            params.put(alias + "_pid", Long.parseLong(parts[2]));
            params.put(alias + "_start_ns", Long.parseLong(parts[3]));
            return "(" + alias + ":Process {host_id: $" + alias + "_h, container_id: $" + alias + "_c, pid: $" + alias + "_pid, start_ns: $" + alias + "_start_ns})";
         } else {
            params.put(alias + "_key", key);
            return "(" + alias + ":Process {process_id: $" + alias + "_key})";
         }
      } else if (LABEL_FILE.equals(label)) {
         if (key.contains("|")) {
            String[] parts = key.split("\\|", 3);
            params.put(alias + "_h", parts[0]);
            params.put(alias + "_c", parts[1]);
            params.put(alias + "_path", parts[2]);
            return "(" + alias + ":File {host_id: $" + alias + "_h, container_id: $" + alias + "_c, path: $" + alias + "_path})";
         } else {
            params.put(alias + "_key", key);
            return "(" + alias + ":File {file_id: $" + alias + "_key})";
         }
      } else {
         if (key.contains("|")) {
            String[] parts = key.split("\\|", 2);
            params.put(alias + "_h", parts[0]);
            params.put(alias + "_endpoints", parts[1]);
            return "(" + alias + ":Network {host_id: $" + alias + "_h, endpoints: $" + alias + "_endpoints})";
         } else {
            params.put(alias + "_key", key);
            return "(" + alias + ":Network {network_id: $" + alias + "_key})";
         }
      }
   }

   /**
    * Cypher expression projecting the deterministic node key across both new
    * composite schema and legacy single property schema.
    */
   public static String keyProjection(String alias, String label) {
      if (LABEL_PROCESS.equals(label)) {
         return "CASE WHEN " + alias + ".process_id IS NOT NULL THEN " + alias + ".process_id "
              + "ELSE coalesce(" + alias + ".host_id, '') + '|' + coalesce(" + alias + ".container_id, '') + '|' + toString(" + alias + ".pid) + '|' + toString(" + alias + ".start_ns) END";
      } else if (LABEL_FILE.equals(label)) {
         return "CASE WHEN " + alias + ".file_id IS NOT NULL THEN " + alias + ".file_id "
              + "ELSE coalesce(" + alias + ".host_id, '') + '|' + coalesce(" + alias + ".container_id, '') + '|' + coalesce(" + alias + ".path, '') END";
      } else {
         return "CASE WHEN " + alias + ".network_id IS NOT NULL THEN " + alias + ".network_id "
              + "ELSE coalesce(" + alias + ".host_id, '') + '|' + coalesce(" + alias + ".endpoints, '') END";
      }
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
