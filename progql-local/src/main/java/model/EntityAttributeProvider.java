package model;

import java.util.HashMap;
import java.util.Map;
import org.jgrapht.ext.ComponentAttributeProvider;

public class EntityAttributeProvider implements ComponentAttributeProvider<EntityNode> {
   public Map<String, String> getComponentAttributes(EntityNode n) {
      HashMap<String, String> map = new HashMap<>();
      if (n.attributes == null) {
         if (n.getP() != null) {
            map.put("shape", "box");
         }

         if (n.getF() != null) {
            map.put("shape", "ellipse");
         }

         if (n.getN() != null) {
            map.put("shape", "parallelogram");
         }
      }

      return map;
   }
}
