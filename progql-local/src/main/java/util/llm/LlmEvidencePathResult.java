package util.llm;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import model.EntityNode;
import model.EventEdge;
import org.jgrapht.graph.DirectedPseudograph;
import org.json.JSONArray;
import org.json.JSONObject;

public class LlmEvidencePathResult {
   private final EntityNode entry;
   private final EventEdge poiEdge;
   private final boolean matched;
   private final String message;
   private final List<LlmEvidencePath> paths;
   private final LlmEvidencePathSearchStatus searchStatus;
   private final int expandedStates;
   private final int searchStateLimit;

   public LlmEvidencePathResult(
      EntityNode entry,
      DirectedPseudograph<EntityNode, EventEdge> graph,
      EventEdge poiEdge,
      boolean matched,
      String message,
      List<EntityNode> orderedNodes,
      List<EventEdge> orderedEdges
   ) {
      this(entry, graph, poiEdge, matched, message, orderedNodes, orderedEdges, false);
   }

   public LlmEvidencePathResult(
      EntityNode entry,
      DirectedPseudograph<EntityNode, EventEdge> graph,
      EventEdge poiEdge,
      boolean matched,
      String message,
      List<EntityNode> orderedNodes,
      List<EventEdge> orderedEdges,
      boolean searchTruncated
   ) {
      LlmEvidencePath path = new LlmEvidencePath(1, 0.0, 0.0, 0.0, graph, orderedNodes, orderedEdges);
      this.entry = entry;
      this.poiEdge = poiEdge;
      this.matched = matched;
      this.message = message == null ? "" : message;
      this.paths = Collections.unmodifiableList(matched ? Collections.singletonList(path) : Collections.<LlmEvidencePath>emptyList());
      this.searchStatus = legacyStatus(matched, this.paths.size(), searchTruncated);
      this.expandedStates = 0;
      this.searchStateLimit = 0;
   }

   public LlmEvidencePathResult(EntityNode entry, EventEdge poiEdge, boolean matched, String message, List<LlmEvidencePath> paths, boolean searchTruncated) {
      this(entry, poiEdge, matched, message, paths, legacyStatus(matched, paths == null ? 0 : paths.size(), searchTruncated), 0, 0);
   }

   public LlmEvidencePathResult(
      EntityNode entry,
      EventEdge poiEdge,
      boolean matched,
      String message,
      List<LlmEvidencePath> paths,
      LlmEvidencePathSearchStatus searchStatus,
      int expandedStates,
      int searchStateLimit
   ) {
      this.entry = entry;
      this.poiEdge = poiEdge;
      this.matched = matched;
      this.message = message == null ? "" : message;
      this.paths = Collections.unmodifiableList(new ArrayList<>(paths == null ? Collections.<LlmEvidencePath>emptyList() : paths));
      this.searchStatus = searchStatus == null ? LlmEvidencePathSearchStatus.UNAVAILABLE : searchStatus;
      this.expandedStates = expandedStates;
      this.searchStateLimit = searchStateLimit;
   }

   public EntityNode getEntry() {
      return this.entry;
   }

   public DirectedPseudograph<EntityNode, EventEdge> getGraph() {
      return getFirstPath() == null ? new DirectedPseudograph(EventEdge.class) : getFirstPath().getGraph();
   }

   public EventEdge getPoiEdge() {
      return this.poiEdge;
   }

   public boolean isMatched() {
      return this.matched;
   }

   public String getMessage() {
      return this.message;
   }

   public List<LlmEvidencePath> getPaths() {
      return this.paths;
   }

   public boolean isSearchTruncated() {
      return this.searchStatus == LlmEvidencePathSearchStatus.TRUNCATED;
   }

   public LlmEvidencePathSearchStatus getSearchStatus() {
      return this.searchStatus;
   }

   public int getExpandedStates() {
      return this.expandedStates;
   }

   public int getSearchStateLimit() {
      return this.searchStateLimit;
   }

   public List<EntityNode> getOrderedNodes() {
      return getFirstPath() == null ? Collections.<EntityNode>emptyList() : getFirstPath().getOrderedNodes();
   }

   public List<EventEdge> getOrderedEdges() {
      return getFirstPath() == null ? Collections.<EventEdge>emptyList() : getFirstPath().getOrderedEdges();
   }

   public JSONObject toJsonObject() {
      JSONArray pathJson = new JSONArray();
      for (LlmEvidencePath path : this.paths) {
         pathJson.put(path.toJsonObject());
      }
      return new JSONObject()
         .put("entry_id", this.entry == null ? JSONObject.NULL : this.entry.getId())
         .put("entry_signature", this.entry == null ? JSONObject.NULL : this.entry.getSignature())
         .put("poi_edge_id", this.poiEdge == null ? JSONObject.NULL : this.poiEdge.getID())
         .put("matched", this.matched)
         .put("message", this.message)
         .put("search_truncated", isSearchTruncated())
         .put("path_search_status", this.searchStatus.name())
         .put("expanded_states", this.expandedStates)
         .put("search_state_limit", this.searchStateLimit)
         .put("paths", pathJson);
   }

   private static LlmEvidencePathSearchStatus legacyStatus(boolean matched, int pathCount, boolean searchTruncated) {
      if (searchTruncated) {
         return LlmEvidencePathSearchStatus.TRUNCATED;
      }
      if (!matched || pathCount == 0) {
         return LlmEvidencePathSearchStatus.NO_PATH;
      }
      return pathCount == 1
         ? LlmEvidencePathSearchStatus.EXHAUSTIVE_SINGLE_PATH
         : LlmEvidencePathSearchStatus.EXHAUSTIVE_MULTIPLE_PATHS;
   }

   private LlmEvidencePath getFirstPath() {
      return this.paths.isEmpty() ? null : this.paths.get(0);
   }
}
