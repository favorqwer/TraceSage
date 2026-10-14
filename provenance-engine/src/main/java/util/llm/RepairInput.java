package util.llm;

import model.EntityNode;
import model.EventEdge;
import org.jgrapht.graph.DirectedPseudograph;

/** Immutable input boundary for the semantic repair agent. */
public final class RepairInput {
   private final LlmAttackStoryContext context;
   private final DirectedPseudograph<EntityNode, EventEdge> baseGraph;
   private final DirectedPseudograph<EntityNode, EventEdge> repairUniverse;
   private final DirectedPseudograph<EntityNode, EventEdge> candidatePool;
   private final DirectedPseudograph<EntityNode, EventEdge> baselineIntersectGraph;

   public RepairInput(
      LlmAttackStoryContext context,
      DirectedPseudograph<EntityNode, EventEdge> baseGraph,
      DirectedPseudograph<EntityNode, EventEdge> repairUniverse,
      DirectedPseudograph<EntityNode, EventEdge> candidatePool,
      DirectedPseudograph<EntityNode, EventEdge> baselineIntersectGraph
   ) {
      this.context = context;
      this.baseGraph = baseGraph;
      this.repairUniverse = repairUniverse;
      this.candidatePool = candidatePool;
      this.baselineIntersectGraph = baselineIntersectGraph;
   }

   public LlmAttackStoryContext getContext() { return context; }
   public DirectedPseudograph<EntityNode, EventEdge> getBaseGraph() { return baseGraph; }
   public DirectedPseudograph<EntityNode, EventEdge> getRepairUniverse() { return repairUniverse; }
   public DirectedPseudograph<EntityNode, EventEdge> getCandidatePool() { return candidatePool; }
   public DirectedPseudograph<EntityNode, EventEdge> getBaselineIntersectGraph() { return baselineIntersectGraph; }
}
