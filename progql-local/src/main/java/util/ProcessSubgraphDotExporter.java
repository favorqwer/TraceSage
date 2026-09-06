package util;

import java.io.IOException;
import java.io.Writer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import model.EntityNode;
import model.EventEdge;

public final class ProcessSubgraphDotExporter {
   public void export(ProcessSubgraphBuildResult result, Writer writer) throws IOException {
      writer.write("digraph process_subgraphs {\n");
      writer.write("  rankdir=LR;\n  graph [fontname=\"Helvetica\"];\n  node [fontname=\"Helvetica\", shape=box];\n  edge [fontname=\"Helvetica\"];\n");
      List<ProcessSubgraph> subgraphs = new ArrayList<>(result.getSubgraphs().values());
      Collections.sort(subgraphs, Comparator.comparingLong(subgraph -> subgraph.getRootProcess().getId()));
      for (ProcessSubgraph subgraph : subgraphs) writeSubgraph(subgraph, result.getOwnerProcessIds(), writer);
      writer.write("}\n");
   }

   private void writeSubgraph(ProcessSubgraph subgraph, Map<EventEdge, Long> owners, Writer writer) throws IOException {
      long rootId = subgraph.getRootProcess().getId();
      writer.write("  subgraph cluster_process_" + rootId + " {\n");
      writer.write("    label=\"Process " + rootId + " | owned=" + subgraph.getOwnedEdges().size() + " | context="
         + subgraph.getContextEdges().size() + " | boundaries=" + escape(join(subgraph.getBoundaryReasons())) + "\";\n");
      writer.write("    color=\"#5B8FF9\"; style=rounded;\n");
      List<EventEdge> edges = allEdges(subgraph);
      for (EventEdge edge : edges) {
         writeNode(rootId, edge.getSource(), edge.getSource().getId() == rootId, writer);
         writeNode(rootId, edge.getSink(), edge.getSink().getId() == rootId, writer);
      }
      for (EventEdge edge : edges) {
         boolean owned = subgraph.getOwnedEdges().contains(edge);
         Long owner = owners.get(edge);
         String style = owned ? "solid" : "dashed";
         String color = owned ? "#D97706" : "#9CA3AF";
         String role = owned ? "owned" : "context";
         String label = "edge=" + edge.getID() + " role=" + role + " event=" + safe(edge.getEvent())
            + " time=" + edge.getStartTime() + " owner=" + (owner == null ? "?" : owner);
         writer.write("    p" + rootId + "_n" + edge.getSource().getId() + " -> p" + rootId + "_n" + edge.getSink().getId()
            + " [label=\"" + escape(label) + "\", color=\"" + color + "\", style=\"" + style + "\"];\n");
      }
      writer.write("  }\n");
   }

   private List<EventEdge> allEdges(ProcessSubgraph subgraph) {
      List<EventEdge> edges = new ArrayList<>();
      edges.addAll(subgraph.getOwnedEdges());
      edges.addAll(subgraph.getContextEdges());
      Collections.sort(edges, Comparator.comparingLong(EventEdge::getID));
      return edges;
   }

   private void writeNode(long rootId, EntityNode node, boolean root, Writer writer) throws IOException {
      String shape = node.getP() != null ? "box" : node.getF() != null ? "note" : "ellipse";
      String color = root ? "#2563EB" : "#374151";
      String style = root ? "bold" : "solid";
      String label = type(node) + "\\n" + safe(node.getSignature());
      writer.write("    p" + rootId + "_n" + node.getId() + " [label=\"" + escape(label) + "\", shape=" + shape
         + ", color=\"" + color + "\", style=\"" + style + "\"];\n");
   }

   private static String type(EntityNode node) {
      return node.getP() != null ? "Process" : node.getF() != null ? "File" : node.getN() != null ? "Network" : "Unknown";
   }

   private static String join(Set<String> values) {
      if (values == null || values.isEmpty()) return "none";
      List<String> ordered = new ArrayList<>(values);
      Collections.sort(ordered);
      StringBuilder builder = new StringBuilder();
      for (String value : ordered) {
         if (builder.length() > 0) builder.append(",");
         builder.append(value);
      }
      return builder.toString();
   }

   private static String safe(String value) { return value == null ? "" : value; }
   private static String escape(String value) { return safe(value).replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", ""); }
}
