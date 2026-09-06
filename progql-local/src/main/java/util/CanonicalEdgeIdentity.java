package util;

import model.EventEdge;

/** Stable identity for one raw provenance event across graph stages. */
public final class CanonicalEdgeIdentity {
   private CanonicalEdgeIdentity() {
   }

   public static String key(EventEdge edge) {
      if (edge == null) {
         return "";
      }
      return normalize(edge.getHost())
         + "|"
         + nodeId(edge.getSource() == null ? -1L : edge.getSource().getId())
         + "|"
         + nodeId(edge.getSink() == null ? -1L : edge.getSink().getId())
         + "|"
         + edge.getID();
   }

   private static String nodeId(long id) {
      return Long.toString(id);
   }

   private static String normalize(String value) {
      return value == null ? "" : value.trim();
   }
}
