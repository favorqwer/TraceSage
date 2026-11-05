package traversal.neo4j;

import gql.Expression;
import gql.Match;
import gql.TraversalExpression;
import java.io.File;
import java.math.BigDecimal;
import java.util.Date;
import java.util.Iterator;
import java.util.concurrent.TimeUnit;
import main.Main;
import model.Edge;
import model.EntityNode;
import model.EventEdge;
import model.FileEntity;
import model.NetworkEntity;
import model.ProcessEntity;
import org.jgrapht.graph.DirectedPseudograph;
import org.neo4j.graphdb.GraphDatabaseService;
import org.neo4j.graphdb.Label;
import org.neo4j.graphdb.Node;
import org.neo4j.graphdb.Path;
import org.neo4j.graphdb.Relationship;
import org.neo4j.graphdb.RelationshipType;
import org.neo4j.graphdb.Result;
import org.neo4j.graphdb.Transaction;
import org.neo4j.graphdb.factory.GraphDatabaseFactory;
import org.neo4j.graphdb.traversal.Evaluators;
import org.neo4j.graphdb.traversal.TraversalDescription;
import org.neo4j.graphdb.traversal.Uniqueness;
import traversal.DBTraversal;

public class Neo4jTraversal implements DBTraversal {
   static File databaseDirectory;
   static GraphDatabaseService graphDb;

   @Override
   public void initial(String dbStr) {
      databaseDirectory = new File(dbStr);
      graphDb = new GraphDatabaseFactory().newEmbeddedDatabase(databaseDirectory);
      registerShutdownHook(graphDb);
   }

   @Override
   public DirectedPseudograph<EntityNode, EventEdge> traverse(
      String pattern, EntityNode forwardEntry, Edge edge, String direction, Expression exprInWhere, boolean isWithClause, Match match
   ) {
      System.out.println("Neo4j traverse called!");
      DirectedPseudograph<EntityNode, EventEdge> jg = new DirectedPseudograph<>(EventEdge.class);
      Node startNode = null;
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
         System.out.println("pattern: " + pattern);
         try (Transaction tx = graphDb.beginTx(); Result result = graphDb.execute("MATCH e=" + pattern + " RETURN e")) {
            Iterator<Path> paths = result.columnAs("e");
            while (paths.hasNext()) {
               Path path = paths.next();
               for (Relationship relationship : path.relationships()) {
                  if (hasMaxTraversal) {
                     long candidate = ((Number)relationship.getProperty(property)).longValue();
                     if (edgeTime >= candidate) {
                        continue;
                     }

                     edgeTime = candidate;
                     size = relationship.hasProperty("amount") ? ((Number)relationship.getProperty("amount")).longValue() : 0L;
                     startTime = ((Number)relationship.getProperty("starttime")).longValue();
                     endTime = ((Number)relationship.getProperty("endtime")).longValue();
                     startNode = backward ? relationship.getEndNode() : relationship.getStartNode();
                     continue;
                  }

                  if (hasMinTraversal) {
                     long candidate = ((Number)relationship.getProperty(property)).longValue();
                     if (edgeTime <= candidate) {
                        continue;
                     }

                     edgeTime = candidate;
                     size = relationship.hasProperty("amount") ? ((Number)relationship.getProperty("amount")).longValue() : 0L;
                     startTime = ((Number)relationship.getProperty("starttime")).longValue();
                     endTime = ((Number)relationship.getProperty("endtime")).longValue();
                     startNode = backward ? relationship.getEndNode() : relationship.getStartNode();
                     continue;
                  }

                  if (backward) {
                     long candidate = ((Number)relationship.getProperty("endtime")).longValue();
                     if (edgeTime >= candidate) {
                        continue;
                     }

                     edgeTime = candidate;
                     size = relationship.hasProperty("amount") ? ((Number)relationship.getProperty("amount")).longValue() : 0L;
                     startTime = ((Number)relationship.getProperty("starttime")).longValue();
                     endTime = ((Number)relationship.getProperty("endtime")).longValue();
                     startNode = relationship.getEndNode();
                  } else if (forward) {
                     if (edgeTime == 0L) {
                        edgeTime = Long.MAX_VALUE;
                     }

                     long candidate = ((Number)relationship.getProperty("starttime")).longValue();
                     if (edgeTime <= candidate) {
                        continue;
                     }

                     edgeTime = candidate;
                     size = relationship.hasProperty("amount") ? ((Number)relationship.getProperty("amount")).longValue() : 0L;
                     startTime = ((Number)relationship.getProperty("starttime")).longValue();
                     endTime = ((Number)relationship.getProperty("endtime")).longValue();
                     startNode = relationship.getStartNode();
                  }
               }
            }

            if (startNode != null) {
               Main.poiEdge.setPoiAmount(Double.valueOf((double)size));
               Main.poiEdge.setPoiStarttime(toDecimalTimestamp(startTime));
               Main.poiEdge.setPoiEndtime(toDecimalTimestamp(endTime));
               String signature = getEntityNode(startNode).getSignature();
               Main.highRP = new String[]{signature};
               Main.detection = signature;
               System.out.println("startNode: " + startNode.getProperty("id"));
            }
         }
      } else {
         Date startDate = new Date();
         if (hasMaxTraversal) {
            edgeTime = 0L;
         } else if (hasMinTraversal) {
            edgeTime = Long.MAX_VALUE;
         }

         try (Transaction tx = graphDb.beginTx(); Result result = graphDb.execute("MATCH e=" + pattern + " RETURN e")) {
            Iterator<Path> paths = result.columnAs("e");
            while (paths.hasNext()) {
               Path path = paths.next();
               for (Relationship relationship : path.relationships()) {
                  if (hasMaxTraversal) {
                     long candidate = ((Number)relationship.getProperty(property)).longValue();
                     if (edgeTime < candidate) {
                        edgeTime = candidate;
                     }

                     startNode = relationship.getStartNode();
                  } else if (hasMinTraversal) {
                     long candidate = ((Number)relationship.getProperty(property)).longValue();
                     if (edgeTime > candidate) {
                        edgeTime = candidate;
                     }

                     startNode = relationship.getStartNode();
                  } else {
                     startNode = relationship.getStartNode();
                  }
               }
            }
         }

         Date endDate = new Date();
         long diff = endDate.getTime() - startDate.getTime();
         long seconds = TimeUnit.MILLISECONDS.toSeconds(diff);
         System.out.println("Neo4j - Forward Cypher executed " + seconds + " s.");
      }

      TraversalDescription description = null;
      try (Transaction tx = graphDb.beginTx()) {
         if (backward) {
            description = graphDb.traversalDescription().breadthFirst().expand(new DepimpactBackwardExpander(edgeTime, edge, exprInWhere, jg)).uniqueness(Uniqueness.NODE_GLOBAL);
            if (Main.depth != null && !Main.depth.isEmpty()) {
               description = description.evaluator(Evaluators.toDepth(Integer.parseInt(Main.depth)));
            }
         } else if (forward) {
            description = graphDb.traversalDescription().breadthFirst().expand(new DepimpactForwardExpander(edgeTime, edge, exprInWhere, jg)).uniqueness(Uniqueness.NODE_GLOBAL);
         }

         if (startNode != null && description != null) {
            for (Node ignored : description.traverse(startNode).nodes()) {
            }
         }
      }

      return jg;
   }

   private static BigDecimal toDecimalTimestamp(long timestamp) {
      String raw = String.valueOf(timestamp);
      if (raw.length() <= 10) {
         return new BigDecimal(raw);
      } else {
         return new BigDecimal(raw.substring(0, 10) + "." + raw.substring(10));
      }
   }

   private static void registerShutdownHook(final GraphDatabaseService graphDb) {
      System.out.println("registerShutdownHook...");
      Runtime.getRuntime().addShutdownHook(new Thread() {
         @Override
         public void run() {
            graphDb.shutdown();
         }
      });
   }

   public static EntityNode getEntityNode(Node n) {
      EntityNode node = null;
      if (n.hasLabel(Neo4jTraversal.MyLabel.File)) {
         FileEntity f = new FileEntity("", "", n.getProperty("name").toString(), (Long)n.getProperty("id"), n.getProperty("hostname").toString(), "");
         node = new EntityNode(f);
      } else if (n.hasLabel(Neo4jTraversal.MyLabel.Process)) {
         String exePath = n.getProperty("exename").toString();
         String reducedExepath = !exePath.isEmpty() && exePath.contains(" ") ? exePath.substring(0, exePath.indexOf(" ")) : exePath;
         ProcessEntity p = new ProcessEntity(
            n.getProperty("pid").toString(), "", "", "", "", (Long)n.getProperty("id"), reducedExepath, n.getProperty("hostname").toString(), "", 0L, "", ""
         );
         node = new EntityNode(p);
      } else if (n.hasLabel(Neo4jTraversal.MyLabel.Network)) {
         NetworkEntity network = new NetworkEntity(
            n.hasProperty("srcip") ? n.getProperty("srcip").toString() : "",
            n.hasProperty("dstip") ? n.getProperty("dstip").toString() : "",
            n.hasProperty("srcport") ? n.getProperty("srcport").toString() : "",
            n.hasProperty("dstport") ? n.getProperty("dstport").toString() : "",
            (Long)n.getProperty("id"),
            n.getProperty("hostname").toString(),
            ""
         );
         node = new EntityNode(network);
      }

      return node;
   }

   public static enum MyLabel implements Label {
      File,
      Process,
      Network;
   }

   public static enum MyRelationshipType implements RelationshipType {
      FileEvent,
      ProcessEvent,
      NetworkEvent;
   }
}
