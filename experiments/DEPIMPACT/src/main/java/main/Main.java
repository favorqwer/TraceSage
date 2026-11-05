package main;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import model.EntityNode;
import model.EventEdge;
import model.FileEntity;
import model.NetworkEntity;
import model.POIEdge;
import model.PoiEventInfo;
import model.ProcessEntity;
import org.jgrapht.graph.DirectedPseudograph;
import org.neo4j.graphdb.Node;
import traversal.neo4j.Neo4jTraversal;
import util.GraphOperations;

/**
 * Core engine configuration and static context holder for graph traversal and operations.
 */
public class Main {
   public static POIEdge poiEdge = null;
   public static PoiEventInfo poiEventInfo = null;
   public static String[] highRP = new String[0];
   public static String[] midRP = new String[0];
   public static String[] lowRP = new String[0];
   public static String detection = "";
   public static String depth = "";
   static String db = "postgres";

   public static DirectedPseudograph<EntityNode, EventEdge> createUnionJg(
      DirectedPseudograph<EntityNode, EventEdge> jg1, DirectedPseudograph<EntityNode, EventEdge> jg2
   ) {
      return GraphOperations.union(jg1, jg2);
   }

   public static DirectedPseudograph<EntityNode, EventEdge> createIntersectJg(
      DirectedPseudograph<EntityNode, EventEdge> jg1, DirectedPseudograph<EntityNode, EventEdge> jg2
   ) {
      return GraphOperations.intersection(jg1, jg2);
   }

   public static double getEntryCompositeScore(EntityNode entry) {
      return entry == null ? 0.0 : entry.getReputation();
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

   public static EntityNode getNodeById(int id, Connection conn) {
      EntityNode node = null;
      if (id <= 0 || conn == null) {
         return null;
      }

      String sql = "";
      String nodeType = "";
      sql = "Select id, 'f' as nodetype From file Where id=? Union Select id, 'n' as nodetype From network Where id=? Union Select id, 'p' as nodetype From process Where id=?";
      try (PreparedStatement stmt = conn.prepareStatement(sql)) {
         stmt.setInt(1, id);
         stmt.setInt(2, id);
         stmt.setInt(3, id);
         try (ResultSet rs = stmt.executeQuery()) {
            if (rs.next()) {
               nodeType = rs.getString("nodetype");
            }
         }
      } catch (SQLException var104) {
         var104.printStackTrace();
      }

      if (nodeType.equals("p")) {
         sql = "Select * From process Where id=?";
      } else if (nodeType.equals("f")) {
         sql = "Select * From file Where id=?";
      } else if (nodeType.equals("n")) {
         if ("postgres".equals(db) || "neo4jpostgres".equals(db)) {
            sql = "Select id, dstip::cidr as dstip, dstport, hostname, srcip::cidr as srcip, srcport From network Where id=?";
         } else {
            sql = "Select id, dstip as dstip, dstport, hostname, srcip as srcip, srcport From network Where id=?";
         }
      } else {
         return null;
      }

      try (PreparedStatement stmt = conn.prepareStatement(sql)) {
         stmt.setInt(1, id);
         try (ResultSet rs = stmt.executeQuery()) {
            if (rs.next()) {
               switch (nodeType.hashCode()) {
                  case 102:
                     if (nodeType.equals("f")) {
                        FileEntity f = new FileEntity("", "", rs.getString("name"), (long)rs.getInt("id"), rs.getString("hostname"), "");
                        node = new EntityNode(f);
                     }
                     break;
                  case 110:
                     if (nodeType.equals("n")) {
                        NetworkEntity n = new NetworkEntity(
                           rs.getString("srcip"),
                           rs.getString("dstip"),
                           String.valueOf(rs.getInt("srcport")),
                           String.valueOf(rs.getInt("dstport")),
                           (long)rs.getInt("id"),
                           rs.getString("hostname"),
                           ""
                        );
                        node = new EntityNode(n);
                     }
                     break;
                  case 112:
                     if (nodeType.equals("p")) {
                        ProcessEntity p = new ProcessEntity(
                           String.valueOf(rs.getInt("pid")),
                           "",
                           "",
                           "",
                           "",
                           (long)rs.getInt("id"),
                           rs.getString("exename"),
                           rs.getString("hostname"),
                           "",
                           0L,
                           "",
                           ""
                        );
                        node = new EntityNode(p);
                     }
               }
            }
         }
      } catch (SQLException var99) {
         var99.printStackTrace();
      }

      return node;
   }
}
