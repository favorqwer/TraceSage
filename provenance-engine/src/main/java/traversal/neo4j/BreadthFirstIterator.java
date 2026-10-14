package traversal.neo4j;

import java.util.ArrayDeque;
import java.util.Deque;
import org.jgrapht.Graph;
import org.jgrapht.Graphs;
import org.jgrapht.traverse.CrossComponentIterator;

public class BreadthFirstIterator<V, E> extends CrossComponentIterator<V, E, BreadthFirstIterator.SearchNodeData<E>> {
   private Deque<V> queue = new ArrayDeque();

   public BreadthFirstIterator(Graph<V, E> g) {
      this(g, null);
   }

   public BreadthFirstIterator(Graph<V, E> g, V startVertex) {
      super(g, startVertex);
   }

   public BreadthFirstIterator(Graph<V, E> g, Iterable<V> startVertices) {
      super(g, startVertices);
   }

   protected boolean isConnectedComponentExhausted() {
      return this.queue.isEmpty();
   }

   protected void encounterVertex(V vertex, E edge) {
      int depth = edge == null ? 0 : ((BreadthFirstIterator.SearchNodeData)this.getSeenData(Graphs.getOppositeVertex(this.graph, edge, vertex))).depth + 1;
      this.putSeenData(vertex, new BreadthFirstIterator.SearchNodeData(edge, depth));
      this.queue.add(vertex);
   }

   protected void encounterVertexAgain(V vertex, E edge) {
   }

   public V getParent(V v) {
      assert this.getSeenData(v) != null;

      E edge = ((BreadthFirstIterator.SearchNodeData)this.getSeenData(v)).edge;
      return (V)(edge == null ? null : Graphs.getOppositeVertex(this.graph, edge, v));
   }

   public E getSpanningTreeEdge(V v) {
      assert this.getSeenData(v) != null;

      return ((BreadthFirstIterator.SearchNodeData)this.getSeenData(v)).edge;
   }

   public int getDepth(V v) {
      assert this.getSeenData(v) != null;

      return ((BreadthFirstIterator.SearchNodeData)this.getSeenData(v)).depth;
   }

   protected V provideNextVertex() {
      return this.queue.removeFirst();
   }

   protected static class SearchNodeData<E> {
      private final E edge;
      private final int depth;

      public SearchNodeData(E edge, int depth) {
         this.edge = edge;
         this.depth = depth;
      }

      public E getEdge() {
         return this.edge;
      }

      public int getDepth() {
         return this.depth;
      }
   }
}
