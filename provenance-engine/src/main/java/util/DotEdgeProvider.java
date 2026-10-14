package util;

import java.util.Map;
import model.EntityNode;
import model.EventEdge;
import org.jgrapht.ext.EdgeProvider;

public class DotEdgeProvider implements EdgeProvider<EntityNode, EventEdge> {
   public EventEdge buildEdge(EntityNode from, EntityNode to, String label, Map<String, String> attributes) {
      return new EventEdge(from, to);
   }
}
