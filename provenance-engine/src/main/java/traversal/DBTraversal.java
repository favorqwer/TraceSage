package traversal;

import gql.Expression;
import gql.Match;
import model.Edge;
import model.EntityNode;
import model.EventEdge;
import org.jgrapht.graph.DirectedPseudograph;

public interface DBTraversal {
   void initial(String var1);

   DirectedPseudograph<EntityNode, EventEdge> traverse(String var1, EntityNode var2, Edge var3, String var4, Expression var5, boolean var6, Match var7);
}
