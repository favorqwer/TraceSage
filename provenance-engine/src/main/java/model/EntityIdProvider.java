package model;

import org.jgrapht.ext.ComponentNameProvider;

public class EntityIdProvider implements ComponentNameProvider<EntityNode> {
   public String getName(EntityNode n) {
      return "" + n.getId();
   }
}
