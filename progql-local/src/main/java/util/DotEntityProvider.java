package util;

import java.util.Map;
import model.EntityNode;
import org.jgrapht.ext.VertexProvider;

public class DotEntityProvider implements VertexProvider<EntityNode> {
   public EntityNode buildVertex(String label, Map<String, String> attributes) {
      long id = Long.parseLong(label);
      double reputation = 0.0;
      String signature = attributes.get("name");
      return new EntityNode(id, reputation, signature, attributes);
   }
}
