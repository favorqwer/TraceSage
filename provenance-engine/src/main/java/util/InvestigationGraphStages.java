package util;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import model.EntityNode;
import model.EventEdge;
import org.jgrapht.graph.DirectedPseudograph;
import util.llm.LlmEvidencePathResult;
import util.llm.LlmSelectionCandidate;

/** Named, immutable-by-convention checkpoints for the seven-stage LLM investigation pipeline. */
public final class InvestigationGraphStages {
   private DirectedPseudograph<EntityNode, EventEdge> bRaw = new DirectedPseudograph(EventEdge.class);
   private DirectedPseudograph<EntityNode, EventEdge> bScore = new DirectedPseudograph(EventEdge.class);
   private DirectedPseudograph<EntityNode, EventEdge> fSelectedRaw = new DirectedPseudograph(EventEdge.class);
   private DirectedPseudograph<EntityNode, EventEdge> gFilter = new DirectedPseudograph(EventEdge.class);
   private DirectedPseudograph<EntityNode, EventEdge> gRetained = new DirectedPseudograph(EventEdge.class);
   private DirectedPseudograph<EntityNode, EventEdge> gRepairPool = new DirectedPseudograph(EventEdge.class);
   private DirectedPseudograph<EntityNode, EventEdge> gFinal = new DirectedPseudograph(EventEdge.class);
   private List<EntityNode> candidateEntries = Collections.emptyList();
   private List<LlmSelectionCandidate> selectedEntries = Collections.emptyList();
   private List<LlmEvidencePathResult> evidencePaths = Collections.emptyList();

   public DirectedPseudograph<EntityNode, EventEdge> getBRaw() { return bRaw; }
   public void setBRaw(DirectedPseudograph<EntityNode, EventEdge> value) { bRaw = GraphOperations.copy(value); }
   public DirectedPseudograph<EntityNode, EventEdge> getBScore() { return bScore; }
   public void setBScore(DirectedPseudograph<EntityNode, EventEdge> value) { bScore = GraphOperations.copy(value); }
   public DirectedPseudograph<EntityNode, EventEdge> getFSelectedRaw() { return fSelectedRaw; }
   public void setFSelectedRaw(DirectedPseudograph<EntityNode, EventEdge> value) { fSelectedRaw = GraphOperations.copy(value); }
   public DirectedPseudograph<EntityNode, EventEdge> getGFilter() { return gFilter; }
   public void setGFilter(DirectedPseudograph<EntityNode, EventEdge> value) { gFilter = GraphOperations.copy(value); }
   public DirectedPseudograph<EntityNode, EventEdge> getGRetained() { return gRetained; }
   public void setGRetained(DirectedPseudograph<EntityNode, EventEdge> value) { gRetained = GraphOperations.copy(value); }
   public DirectedPseudograph<EntityNode, EventEdge> getGRepairPool() { return gRepairPool; }
   public void setGRepairPool(DirectedPseudograph<EntityNode, EventEdge> value) { gRepairPool = GraphOperations.copy(value); }
   public DirectedPseudograph<EntityNode, EventEdge> getGFinal() { return gFinal; }
   public void setGFinal(DirectedPseudograph<EntityNode, EventEdge> value) { gFinal = GraphOperations.copy(value); }
   public List<EntityNode> getCandidateEntries() { return candidateEntries; }
   public void setCandidateEntries(List<EntityNode> value) { candidateEntries = value == null ? Collections.<EntityNode>emptyList() : Collections.unmodifiableList(new ArrayList<>(value)); }
   public List<LlmSelectionCandidate> getSelectedEntries() { return selectedEntries; }
   public void setSelectedEntries(List<LlmSelectionCandidate> value) { selectedEntries = value == null ? Collections.<LlmSelectionCandidate>emptyList() : Collections.unmodifiableList(new ArrayList<>(value)); }
   public List<LlmEvidencePathResult> getEvidencePaths() { return evidencePaths; }
   public void setEvidencePaths(List<LlmEvidencePathResult> value) { evidencePaths = value == null ? Collections.<LlmEvidencePathResult>emptyList() : Collections.unmodifiableList(new ArrayList<>(value)); }
}
