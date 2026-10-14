package util.llm;

import java.util.ArrayList;
import java.util.List;
import model.EntityNode;
import model.EventEdge;
import org.jgrapht.graph.DirectedPseudograph;

public final class LlmRepairHardConstraintVerifier {
   public ValidationResult validate(EventEdge edge, DirectedPseudograph<EntityNode, EventEdge> currentGraph,
      DirectedPseudograph<EntityNode, EventEdge> candidateGraph, int maxSelected) {
      List<String> reasons = new ArrayList<>();
      if (edge == null) reasons.add("null_edge");
      if (edge != null && (candidateGraph == null || !candidateGraph.containsEdge(edge))) reasons.add("edge_not_in_candidate_graph");
      if (edge != null && (edge.getSource() == null || edge.getSink() == null)) reasons.add("missing_endpoint");
      if (edge != null && currentGraph != null) {
         if (currentGraph.containsEdge(edge)) reasons.add("duplicate_edge");
         boolean sourceKnown = currentGraph.containsVertex(edge.getSource());
         boolean sinkKnown = currentGraph.containsVertex(edge.getSink());
         if (!sourceKnown && !sinkKnown) reasons.add("does_not_connect_current_graph");
      }
      return new ValidationResult(reasons.isEmpty(), reasons);
   }

   public static final class ValidationResult {
      private final boolean accepted; private final List<String> reasons;
      ValidationResult(boolean accepted, List<String> reasons) { this.accepted = accepted; this.reasons = new ArrayList<>(reasons); }
      public boolean isAccepted() { return accepted; }
      public List<String> getReasons() { return reasons; }
   }

}
