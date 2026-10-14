package util.llm;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import model.EntityNode;

public final class LlmAttackStoryContext {
   private final List<LlmSelectionCandidate> selectedCandidates;
   private final EntityNode anomalyNode;

   public LlmAttackStoryContext(List<LlmSelectionCandidate> selectedCandidates, EntityNode anomalyNode) {
      this.selectedCandidates = Collections.unmodifiableList(
         new ArrayList<>(selectedCandidates == null ? Collections.<LlmSelectionCandidate>emptyList() : selectedCandidates)
      );
      this.anomalyNode = anomalyNode;
   }

   public static LlmAttackStoryContext fromSingleEntry(EntityNode entry, EntityNode anomalyNode) {
      if (entry == null) {
         return new LlmAttackStoryContext(Collections.<LlmSelectionCandidate>emptyList(), anomalyNode);
      }
      List<LlmSelectionCandidate> candidates = new ArrayList<>();
      candidates.add(
         new LlmSelectionCandidate(
            1,
            1,
            entry,
            "Single-node investigation context."
         )
      );
      return new LlmAttackStoryContext(candidates, anomalyNode);
   }

   public List<LlmSelectionCandidate> getSelectedCandidates() {
      return this.selectedCandidates;
   }

   public List<EntityNode> getSelectedEntries() {
      List<EntityNode> entries = new ArrayList<>();
      for (LlmSelectionCandidate candidate : this.selectedCandidates) {
         entries.add(candidate.getEntry());
      }
      return entries;
   }

   public EntityNode getAnomalyNode() {
      return this.anomalyNode;
   }

}
