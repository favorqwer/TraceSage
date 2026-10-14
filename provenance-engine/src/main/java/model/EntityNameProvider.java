package model;

import org.jgrapht.ext.ComponentNameProvider;

public class EntityNameProvider implements ComponentNameProvider<EntityNode> {
   public String getName(EntityNode n) {
      String sig = n.getSignature();
      if (sig.startsWith("=")) {
         sig = sig.substring(1);
      }

      return sig + " | " + String.format("%.5f", n.reputation);
   }
}
