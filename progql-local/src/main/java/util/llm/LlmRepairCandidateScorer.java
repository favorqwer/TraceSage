package util.llm;

import java.util.Locale;
import model.EntityNode;
import model.EventEdge;
import org.jgrapht.graph.DirectedPseudograph;

/** Shared semantic ordering for repair candidates. Lower values are higher priority. */
final class LlmRepairCandidateScorer {
   private LlmRepairCandidateScorer() { }

   static int priority(EventEdge edge, DirectedPseudograph<EntityNode, EventEdge> current,
      DirectedPseudograph<EntityNode, EventEdge> candidateGraph) {
      if (edge == null) return 4;
      if (closesFileProcessFileFlow(edge, current)) return 0;
      if (readsSensitiveDataIntoEgressProcess(edge, current, candidateGraph)) return 1;
      boolean sourceKnown = current != null && current.containsVertex(edge.getSource());
      boolean sinkKnown = current != null && current.containsVertex(edge.getSink());
      if (sourceKnown != sinkKnown) return 2;
      if (sourceKnown) return 3;
      return 4;
   }

   static int eventPriority(EventEdge edge) {
      String event = eventName(edge);
      if ("read".equals(event) || "readv".equals(event) || "pread".equals(event) || "preadv".equals(event)
         || "write".equals(event) || "writev".equals(event) || "pwrite".equals(event) || "pwritev".equals(event)
         || "recvfrom".equals(event) || "recvmsg".equals(event) || "sendto".equals(event) || "sendmsg".equals(event)) {
         return 0;
      }
      return "execve".equals(event) ? 1 : 2;
   }

   static int systemDependencyPenalty(EventEdge edge) {
      return isSystemDependencyPath(edge == null ? null : edge.getSource()) || isSystemDependencyPath(edge == null ? null : edge.getSink()) ? 1 : 0;
   }

   static String stableKey(EventEdge edge) {
      if (edge == null) return "";
      return nodeKey(edge.getSource())
         + "|" + eventName(edge)
         + "|" + nodeKey(edge.getSink())
         + "|" + edge.getID()
         + "|" + edge.getStartns()
         + "|" + edge.getEndns();
   }

   static boolean isSensitiveDataPath(EntityNode node) {
      String value = normalizedSignatureValue(node);
      return !value.isEmpty()
         && ("/etc/passwd".equals(value)
            || "/etc/group".equals(value)
            || value.contains("shadow")
            || value.contains("credential")
            || value.contains("secret")
            || value.contains("token")
            || value.contains("password")
            || value.contains("/.ssh/")
            || value.endsWith(".key")
            || value.endsWith(".pem")
            || value.endsWith(".crt")
            || value.endsWith(".cert"));
   }

   private static boolean closesFileProcessFileFlow(EventEdge input, DirectedPseudograph<EntityNode, EventEdge> current) {
      if (!isFileRead(input) || !isFile(input.getSource()) || !isProcess(input.getSink()) || current == null) return false;
      for (EventEdge output : current.edgeSet()) {
         if (!isFileWrite(output) || !isProcess(output.getSource()) || !isFile(output.getSink())) continue;
         if (input.getSink().getId() != output.getSource().getId()) continue;
         if (input.getSource().getId() == output.getSink().getId()) continue;
         if (occursBefore(input, output)) return true;
      }
      return false;
   }

   private static boolean readsSensitiveDataIntoEgressProcess(EventEdge input,
      DirectedPseudograph<EntityNode, EventEdge> current,
      DirectedPseudograph<EntityNode, EventEdge> candidateGraph) {
      return isFileRead(input)
         && isFile(input.getSource())
         && isProcess(input.getSink())
         && isSensitiveDataPath(input.getSource())
         && hasOutboundNetworkEvent(input.getSink(), input, current, candidateGraph);
   }

   private static boolean hasOutboundNetworkEvent(EntityNode process, EventEdge input,
      DirectedPseudograph<EntityNode, EventEdge> first,
      DirectedPseudograph<EntityNode, EventEdge> second) {
      return hasOutboundNetworkEvent(process, input, first)
         || (second != first && hasOutboundNetworkEvent(process, input, second));
   }

   private static boolean hasOutboundNetworkEvent(EntityNode process, EventEdge input,
      DirectedPseudograph<EntityNode, EventEdge> graph) {
      if (process == null || graph == null || !graph.containsVertex(process)) return false;
      for (EventEdge edge : graph.outgoingEdgesOf(process)) {
         if (isNetwork(edge.getSink()) && isOutboundNetworkEvent(edge) && occursBefore(input, edge)) return true;
      }
      return false;
   }

   private static boolean isFileRead(EventEdge edge) {
      String event = eventName(edge);
      return "read".equals(event) || "readv".equals(event) || "pread".equals(event) || "preadv".equals(event);
   }

   private static boolean isFileWrite(EventEdge edge) {
      String event = eventName(edge);
      return "write".equals(event) || "writev".equals(event) || "pwrite".equals(event) || "pwritev".equals(event);
   }

   private static boolean isOutboundNetworkEvent(EventEdge edge) {
      String event = eventName(edge);
      return "sendto".equals(event) || "sendmsg".equals(event) || "connect".equals(event)
         || "write".equals(event) || "writev".equals(event) || "write_socket_params".equals(event);
   }

   private static boolean isFile(EntityNode node) { return node != null && node.getF() != null; }
   private static boolean isProcess(EntityNode node) { return node != null && node.getP() != null; }
   private static boolean isNetwork(EntityNode node) { return node != null && node.getN() != null; }

   private static boolean isSystemDependencyPath(EntityNode node) {
      String value = normalizedSignatureValue(node);
      return !value.isEmpty()
         && (value.startsWith("/lib/")
            || value.startsWith("/lib64/")
            || value.startsWith("/usr/lib/")
            || value.startsWith("/usr/lib64/")
            || value.startsWith("/proc/")
            || value.startsWith("/dev/")
            || value.startsWith("/usr/share/")
            || value.contains("/security/pam_")
            || value.contains("/pam.d/")
            || value.contains("/locale/")
            || value.contains("locale")
            || value.contains("nsswitch")
            || value.contains("libnss")
            || value.contains("ld-linux")
            || value.contains("ld.so")
            || value.endsWith(".so")
            || value.contains(".so."));
   }

   private static boolean occursBefore(EventEdge first, EventEdge second) {
      return first.getEndns() <= second.getStartns();
   }

   private static String nodeKey(EntityNode node) {
      if (node == null) return "Unknown|";
      String type = node.getF() != null ? "File" : node.getP() != null ? "Process" : node.getN() != null ? "Network" : "Unknown";
      return type + "|" + normalizedSignatureValue(node);
   }

   private static String eventName(EventEdge edge) {
      return edge == null || edge.getEvent() == null ? "" : edge.getEvent().trim().toLowerCase(Locale.ROOT);
   }

   private static String normalizedSignatureValue(EntityNode node) {
      if (node == null || node.getSignature() == null) return "";
      String signature = node.getSignature().trim().toLowerCase(Locale.ROOT);
      int colonIndex = signature.indexOf(": ");
      return colonIndex >= 0 ? signature.substring(colonIndex + 2).trim() : signature;
   }
}
