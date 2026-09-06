package util.llm;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import model.EntityNode;
import org.json.JSONArray;
import org.json.JSONObject;

public class LlmSelectionResult {
   private final LlmSelectionQuestionRecord questionRecord;
   private final List<EntityNode> selectedEntries;
   private final List<LlmSelectionCandidate> rankedCandidates;
   private final List<Integer> selectedCandidateRanks;
   private final String summary;
   private final String rawResponseText;
   private final int statusCode;

   public LlmSelectionResult(
      LlmSelectionQuestionRecord questionRecord,
      List<EntityNode> selectedEntries,
      List<LlmSelectionCandidate> rankedCandidates,
      List<Integer> selectedCandidateRanks,
      String summary,
      String rawResponseText,
      int statusCode
   ) {
      this.questionRecord = questionRecord;
      this.selectedEntries = Collections.unmodifiableList(new ArrayList<>(selectedEntries));
      this.rankedCandidates = Collections.unmodifiableList(new ArrayList<>(rankedCandidates));
      this.selectedCandidateRanks = Collections.unmodifiableList(new ArrayList<>(selectedCandidateRanks));
      this.summary = summary == null ? "" : summary;
      this.rawResponseText = rawResponseText == null ? "" : rawResponseText;
      this.statusCode = statusCode;
   }

   public LlmSelectionQuestionRecord getQuestionRecord() {
      return this.questionRecord;
   }

   public JSONObject getQuestionRecordJson() {
      return this.questionRecord.toJsonObject();
   }

   public List<EntityNode> getSelectedEntries() {
      return this.selectedEntries;
   }

   public List<LlmSelectionCandidate> getRankedCandidates() {
      return this.rankedCandidates;
   }

   public List<Integer> getSelectedCandidateRanks() {
      return this.selectedCandidateRanks;
   }

   public String getSummary() {
      return this.summary;
   }

   public String getRawResponseText() {
      return this.rawResponseText;
   }

   public int getStatusCode() {
      return this.statusCode;
   }

   public JSONObject toJsonObject() {
      JSONObject json = new JSONObject();
      JSONArray selectedIds = new JSONArray();
      JSONArray selectedRanks = new JSONArray();
      JSONArray rankedCandidatesJson = new JSONArray();

      for (Integer rank : this.selectedCandidateRanks) {
         selectedRanks.put(rank);
      }

      for (LlmSelectionCandidate candidate : this.rankedCandidates) {
         selectedIds.put(candidate.getEntryId());
         rankedCandidatesJson.put(candidate.toJsonObject());
      }

      json.put("selected_candidate_ranks", selectedRanks);
      json.put("selected_entry_ids", selectedIds);
      json.put("ranked_candidates", rankedCandidatesJson);
      json.put("summary", this.summary);
      json.put("raw_response_text", this.rawResponseText);
      json.put("http_status", this.statusCode);
      return json;
   }
}

class LlmPromptRecord {
   private final String provider;
   private final String endpoint;
   private final String model;
   private final String systemPrompt;
   private final String userPrompt;

   LlmPromptRecord(String provider, String endpoint, String model, String systemPrompt, String userPrompt) {
      this.provider = provider == null ? "" : provider;
      this.endpoint = endpoint == null ? "" : endpoint;
      this.model = model == null ? "" : model;
      this.systemPrompt = systemPrompt == null ? "" : systemPrompt;
      this.userPrompt = userPrompt == null ? "" : userPrompt;
   }

   String getProvider() {
      return this.provider;
   }

   String getEndpoint() {
      return this.endpoint;
   }

   String getModel() {
      return this.model;
   }

   String getSystemPrompt() {
      return this.systemPrompt;
   }

   String getUserPrompt() {
      return this.userPrompt;
   }

   JSONObject toJsonObject() {
      return new JSONObject()
         .put("provider", this.provider)
         .put("endpoint", this.endpoint)
         .put("model", this.model)
         .put("system_prompt", this.systemPrompt)
         .put("user_prompt", this.userPrompt);
   }
}

class LlmSelectionQuestionRecord extends LlmPromptRecord {
   private final int maxSelections;

   LlmSelectionQuestionRecord(String provider, String endpoint, String model, int maxSelections, String systemPrompt, String userPrompt) {
      super(provider, endpoint, model, systemPrompt, userPrompt);
      this.maxSelections = maxSelections;
   }

   @Override
   JSONObject toJsonObject() {
      return super
         .toJsonObject()
         .put("max_selections", this.maxSelections);
   }
}
