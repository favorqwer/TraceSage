package traversal.neo4jserver;

import gql.Expression;
import gql.Match;
import gql.Property;
import gql.TraversalExpression;
import java.io.IOException;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import main.Main;
import model.Edge;
import model.EntityNode;
import model.EventEdge;
import model.PoiEventInfo;
import org.jgrapht.graph.DirectedPseudograph;
import org.neo4j.driver.AuthTokens;
import org.neo4j.driver.Driver;
import org.neo4j.driver.Record;
import org.neo4j.driver.SessionConfig;
import traversal.DBTraversal;

/**
 * Investigation traversal against the TraceSage Neo4j server store
 * (sysdig-parser import: :Process/:File/:Network vertices, p2p/p2f/f2p/p2n/n2p
 * event relationships).
 *
 * POI/with-clause branches:
 * - POI branch: resolve the POI event from the parsed MATCH (label pair maps
 *   to one of the five directed relationship types; optype maps to syscall,
 *   amount to bytes; Network ip props drop the "/32" or "/128" cidr suffix),
 *   pick the max/min row over the traversal property, then run the
 *   causal expander from the POI node.
 * - With-clause branch: threshold over all outgoing events of a numeric node
 *   id, then a forward causal expansion.
 *
 * Vertex ids are assigned deterministically by Neo4jNodeRegistry so that edge
 * keys and baseline artifacts stay reproducible across runs and machines.
 * Connection settings come from the environment or a .env file
 * (NEO4J_URI / NEO4J_USER / NEO4J_PASSWORD / NEO4J_DATABASE); nothing is
 * hardcoded.
 */
public class Neo4jServerTraversal implements DBTraversal {
   private static Driver driver;
   private static String uri;
   private static String database;
   private Neo4jSession sessions;
   private Neo4jNodeRegistry registry = new Neo4jNodeRegistry();

   @Override
   public void initial(String dbStr) {
      if (driver == null) {
         loadConnectionSettings();
         driver = org.neo4j.driver.GraphDatabase.driver(uri, AuthTokens.basic(envOr("NEO4J_USER", "neo4j"), envOr("NEO4J_PASSWORD", "")));
         try {
            driver.verifyConnectivity();
         } catch (Exception ex) {
            throw new IllegalStateException("Failed to connect to Neo4j server: " + uri, ex);
         }
         // The Bolt driver owns non-daemon event-loop threads; without an
         // explicit close the JVM hangs after main returns.
         Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            Driver d = driver;
            driver = null;
            if (d != null) {
               d.close();
            }
         }));
      }
      if (this.sessions == null) {
         this.sessions = new Neo4jSession(driver.session(SessionConfig.forDatabase(database)));
         this.registry.load(this.sessions);
         System.out.println(
            "Neo4j connected: " + uri + "/" + database + ", vertices registered: " + this.registry.size()
         );
      }
   }

   public void close() {
      if (this.sessions != null) {
         this.sessions.close();
         this.sessions = null;
      }
      Driver d = driver;
      driver = null;
      if (d != null) {
         d.close();
      }
   }

   public String connectionDescription() {
      return uri + "/" + database;
   }

   private static void loadConnectionSettings() {
      uri = envOr("NEO4J_URI", "bolt://localhost:7687");
      database = envOr("NEO4J_DATABASE", "neo4j");
      if (System.getenv("NEO4J_PASSWORD") == null) {
         loadDotEnv();
      }
      if (envOr("NEO4J_PASSWORD", "") == null || envOr("NEO4J_PASSWORD", "").isEmpty()) {
         throw new IllegalStateException(
            "Neo4j credentials not configured. Set NEO4J_PASSWORD (and optionally NEO4J_URI/NEO4J_USER/NEO4J_DATABASE) in the environment or .env."
         );
      }
   }

   /** Minimal .env loader: KEY=VALUE lines, looked up in cwd and its parents. */
   private static void loadDotEnv() {
      Path dir = Paths.get(System.getProperty("user.dir")).toAbsolutePath();
      for (int i = 0; i < 4 && dir != null; i++) {
         Path envFile = dir.resolve(".env");
         if (Files.isRegularFile(envFile)) {
            try {
               for (String line : Files.readAllLines(envFile, StandardCharsets.UTF_8)) {
                  String trimmed = line.trim();
                  if (trimmed.isEmpty() || trimmed.startsWith("#") || !trimmed.contains("=")) {
                     continue;
                  }
                  int split = trimmed.indexOf('=');
                  String key = trimmed.substring(0, split).trim();
                  String value = trimmed.substring(split + 1).trim();
                  if (System.getenv(key) == null) {
                     System.setProperty("progql.env." + key, value);
                  }
               }
               return;
            } catch (IOException ignored) {
               return;
            }
         }
         dir = dir.getParent();
      }
   }

   /** Environment first, then values picked up from .env. */
   private static String envOr(String key, String fallback) {
      String value = System.getenv(key);
      if (value == null) {
         value = System.getProperty("progql.env." + key);
      }
      return value == null ? fallback : value;
   }

   @Override
   public DirectedPseudograph<EntityNode, EventEdge> traverse(
      String pattern, EntityNode forwardEntry, Edge edge, String direction, Expression exprInWhere, boolean isWithClause, Match match
   ) {
      DirectedPseudograph<EntityNode, EventEdge> jg = new DirectedPseudograph(EventEdge.class);
      long edgeTime = 0L;
      String property = "";
      long startTime = 0L;
      long endTime = 0L;
      long size = 0L;
      boolean backward = direction != null && direction.toLowerCase().contains("backward");
      boolean forward = direction != null && direction.toLowerCase().contains("forward");
      TraversalExpression traversalExpr = exprInWhere.getTraversalExpression();
      boolean hasMaxTraversal = traversalExpr != null && traversalExpr.getMax() != null;
      boolean hasMinTraversal = traversalExpr != null && traversalExpr.getMin() != null;
      if (hasMaxTraversal) {
         edgeTime = 0L;
         property = traversalExpr.getMax().getCollect().getPropertyExpression().getPropertyLookup().toString();
      } else if (hasMinTraversal) {
         edgeTime = Long.MAX_VALUE;
         property = traversalExpr.getMin().getCollect().getPropertyExpression().getPropertyLookup().toString();
      }

      if (!isWithClause) {
         // --- POI resolution from the parsed MATCH ---
         gql.NodePattern srcPattern = match.getPattern().getPatternPart().getNodePattern();
         gql.NodePattern dstPattern = match.getPattern().getPatternPart().getPatternElementChain().getNodePattern();
         String srcLabel = srcPattern.getLabel().getNodeLabel();
         String dstLabel = dstPattern.getLabel().getNodeLabel();
         String relationshipType = mapRelationType(srcLabel, dstLabel);
         String eventKey = match.getPattern().getPatternPart().getPatternElementChain().getRelationshipPattern().getDetail().getMapLiteral().getPropertyKeyname();
         String eventValue = match.getPattern()
            .getPatternPart()
            .getPatternElementChain()
            .getRelationshipPattern()
            .getDetail()
            .getMapLiteral()
            .getLiteral()
            .replaceAll("^\"|\"$", "");
         String neoEventKey = mapEventProperty(eventKey);

         Map<String, Object> vertexParams = new HashMap<>();
         StringBuilder vertexMatch = new StringBuilder();
         List<Property> props = dstPattern.getPropertyLst();
         if (props != null) {
            int paramIndex = 0;
            for (Property p : props) {
               String neoKey = mapVertexProperty(p.getPropertyKeyname());
               if (neoKey == null) {
                  continue;
               }
               String value = p.getExpression().replaceAll("^\"|\"$", "");
               if (neoKey.endsWith("ip")) {
                  value = stripCidrSuffix(value);
               }
               String paramName = "vp" + paramIndex++;
               vertexMatch.append(neoKey).append(": $").append(paramName).append(", ");
               vertexParams.put(paramName, value);
            }
            if (vertexMatch.length() > 0) {
               vertexMatch.setLength(vertexMatch.length() - 2);
            }
         }

         String poiCypher = "MATCH (src:" + srcLabel + ")-[st:" + relationshipType + "]->(dst:" + dstLabel
            + " {" + vertexMatch + "}) WHERE st." + neoEventKey + " = $eventValue "
            + "RETURN st.event_id AS eventid, st.syscall AS optype, coalesce(st.bytes, 0) AS amount, "
            + "st.starttime AS starttime, st.endtime AS endtime, "
            + "src." + Neo4jNodeRegistry.keyProperty(srcLabel) + " AS srckey, "
            + "dst." + Neo4jNodeRegistry.keyProperty(dstLabel) + " AS dstkey "
            + "ORDER BY eventid";
         vertexParams.put("eventValue", eventValue);

         List<Record> records = this.sessions.run(poiCypher, vertexParams);
         String selectedSrcKey = null;
         String selectedDstKey = null;
         for (Record record : records) {
            long candidate = property.isEmpty()
               ? record.get(backward ? "endtime" : "starttime").asLong()
               : record.get(property).asLong();
            boolean improved = hasMaxTraversal
               ? edgeTime < candidate
               : hasMinTraversal ? edgeTime > candidate
               : backward ? edgeTime < record.get("endtime").asLong()
               : forward && edgeTime > record.get("starttime").asLong();
            if (improved) {
               edgeTime = candidate;
               size = record.get("amount").asLong();
               startTime = record.get("starttime").asLong();
               endTime = record.get("endtime").asLong();
               selectedSrcKey = record.get("srckey").asString();
               selectedDstKey = record.get("dstkey").asString();
            }
         }

         if (selectedSrcKey == null || selectedDstKey == null) {
            System.err.println("No matching POI node found for " + direction + " traversal.");
            return jg;
         }

         EntityNode poiSourceNode = this.registry.nodeByKey(srcLabel, selectedSrcKey, this.sessions);
         EntityNode poiSinkNode = this.registry.nodeByKey(dstLabel, selectedDstKey, this.sessions);
         EntityNode startNode = backward ? poiSinkNode : poiSourceNode;
         if (startNode == null) {
            System.err.println("No matching POI node found for " + direction + " traversal.");
            return jg;
         }

         System.out.println("startNode: " + startNode.getId());
         Main.poiEdge.setPoiAmount(Double.valueOf((double)size));
         String poiSTStr = String.valueOf(startTime);
         BigDecimal poiStarttime = new BigDecimal(poiSTStr.substring(0, 10) + "." + poiSTStr.substring(10));
         Main.poiEdge.setPoiStarttime(poiStarttime);
         String poiETStr = String.valueOf(endTime);
         BigDecimal poiEndtime = new BigDecimal(poiETStr.substring(0, 10) + "." + poiETStr.substring(10));
         Main.poiEdge.setPoiEndtime(poiEndtime);
         String poiEventType = "optype".equalsIgnoreCase(eventKey) ? eventValue : null;
         Main.poiEventInfo = poiSourceNode == null || poiSinkNode == null
            ? null
            : new PoiEventInfo(poiSourceNode.getSignature(), poiSinkNode.getSignature(), poiEventType, poiStarttime, poiEndtime);
         Main.highRP = new String[]{startNode.getSignature()};
         Main.detection = startNode.getSignature();

         if (backward) {
            new Neo4jBackwardExpander(startNode, edgeTime, edge, exprInWhere, jg, this.sessions, this.registry).expand();
         } else if (forward) {
            new Neo4jForwardExpander(startNode, edgeTime, edge, exprInWhere, jg, this.sessions, this.registry).expand();
         }
      } else {
         // --- with-clause forward expansion from a numeric vertex id ---
         if (hasMaxTraversal) {
            edgeTime = 0L;
         } else if (hasMinTraversal) {
            edgeTime = Long.MAX_VALUE;
         }

         long nodeId = Long.parseLong(pattern.substring(pattern.indexOf(58) + 1, pattern.indexOf(125)));
         EntityNode startNode = this.registry.nodeById(nodeId, this.sessions);
         if (startNode == null) {
            System.err.println("No matching start node found for forward traversal.");
            return jg;
         }

         String label = this.registry.labelOf(nodeId);
         String key = this.registry.keyOf(nodeId);
         String thresholdCypher = "MATCH (n:" + label + " {" + Neo4jNodeRegistry.keyProperty(label)
            + ": $key})-[r]->() RETURN r.starttime AS starttime, r.endtime AS endtime";
         for (Record record : this.sessions.run(thresholdCypher, "key", key)) {
            long candidate = record.get(property).asLong();
            if (hasMaxTraversal && edgeTime < candidate) {
               edgeTime = candidate;
            } else if (hasMinTraversal && edgeTime > candidate) {
               edgeTime = candidate;
            }
         }

         new Neo4jForwardExpander(startNode, edgeTime, edge, exprInWhere, jg, this.sessions, this.registry).expand();
      }

      return jg;
   }

   /** Label pair -> one of the five directed sysdig relationship types. */
   static String mapRelationType(String srcLabel, String dstLabel) {
      if (Neo4jNodeRegistry.LABEL_PROCESS.equals(srcLabel) && Neo4jNodeRegistry.LABEL_PROCESS.equals(dstLabel)) {
         return "p2p";
      }
      if (Neo4jNodeRegistry.LABEL_PROCESS.equals(srcLabel) && Neo4jNodeRegistry.LABEL_FILE.equals(dstLabel)) {
         return "p2f";
      }
      if (Neo4jNodeRegistry.LABEL_FILE.equals(srcLabel) && Neo4jNodeRegistry.LABEL_PROCESS.equals(dstLabel)) {
         return "f2p";
      }
      if (Neo4jNodeRegistry.LABEL_PROCESS.equals(srcLabel) && Neo4jNodeRegistry.LABEL_NETWORK.equals(dstLabel)) {
         return "p2n";
      }
      if (Neo4jNodeRegistry.LABEL_NETWORK.equals(srcLabel) && Neo4jNodeRegistry.LABEL_PROCESS.equals(dstLabel)) {
         return "n2p";
      }
      throw new IllegalArgumentException("Unsupported pattern endpoints: (" + srcLabel + ")-[]->(" + dstLabel + ")");
   }

   /** PG event column -> Neo4j relationship property. */
   static String mapEventProperty(String columnName) {
      switch (columnName.toLowerCase()) {
         case "optype":
            return "syscall";
         case "amount":
            return "bytes";
         case "eventno":
            return "event_id";
         default:
            return columnName;
      }
   }

   /** PG vertex column -> Neo4j vertex property (null when not represented). */
   static String mapVertexProperty(String columnName) {
      switch (columnName.toLowerCase()) {
         case "srcip":
            return "lip";
         case "srcport":
            return "lport";
         case "dstip":
            return "rip";
         case "dstport":
            return "rport";
         case "name":
            return "path";
         case "exename":
            return "exepath";
         default:
            return columnName;
      }
   }

   private static String stripCidrSuffix(String value) {
      if (value.endsWith("/32")) {
         return value.substring(0, value.length() - 3);
      }
      if (value.endsWith("/128")) {
         return value.substring(0, value.length() - 4);
      }
      return value;
   }
}
