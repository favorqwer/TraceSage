package util.llm;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.json.JSONArray;
import org.json.JSONObject;

/** Versioned, offline ATT&CK tactic vocabulary used by the agent. */
public final class AttackTacticKnowledge {
   private final String version;
   private final Map<String, String> tactics;
   private final Map<String, List<String>> predecessors;

   private AttackTacticKnowledge(String version, Map<String, String> tactics, Map<String, List<String>> predecessors) {
      this.version = version;
      this.tactics = Collections.unmodifiableMap(new LinkedHashMap<>(tactics));
      this.predecessors = Collections.unmodifiableMap(new LinkedHashMap<>(predecessors));
   }

   public static AttackTacticKnowledge loadDefault() {
      InputStream input = AttackTacticKnowledge.class.getResourceAsStream("/attack/attack-tactics.json");
      if (input == null) {
         throw new IllegalStateException("ATT&CK tactic resource is missing: /attack/attack-tactics.json");
      }
      try (InputStream stream = input) {
         byte[] bytes = readAll(stream);
         return fromJson(new JSONObject(new String(bytes, StandardCharsets.UTF_8)));
      } catch (Exception ex) {
         throw new IllegalStateException("Failed to load ATT&CK tactic resource.", ex);
      }
   }

   public static AttackTacticKnowledge fromJson(JSONObject json) {
      if (json == null) {
         throw new IllegalArgumentException("ATT&CK tactic JSON is null.");
      }
      String version = json.optString("version", "unknown").trim();
      Map<String, String> tactics = new LinkedHashMap<>();
      JSONArray tacticArray = json.optJSONArray("tactics");
      if (tacticArray == null || tacticArray.length() == 0) {
         throw new IllegalStateException("ATT&CK tactic JSON has no tactics.");
      }
      for (int i = 0; i < tacticArray.length(); i++) {
         JSONObject tactic = tacticArray.getJSONObject(i);
         String id = tactic.optString("id", "").trim();
         String name = tactic.optString("name", id).trim();
         if (id.isEmpty()) {
            throw new IllegalStateException("ATT&CK tactic entry has no id.");
         }
         tactics.put(id, name);
      }
      Map<String, List<String>> predecessors = new LinkedHashMap<>();
      JSONObject relationObject = json.optJSONObject("predecessors");
      if (relationObject != null) {
         for (String key : relationObject.keySet()) {
            JSONArray values = relationObject.optJSONArray(key);
            List<String> ids = new ArrayList<>();
            if (values != null) {
               for (int i = 0; i < values.length(); i++) {
                  String id = values.optString(i, "").trim();
                  if (!id.isEmpty() && tactics.containsKey(id)) {
                     ids.add(id);
                  }
               }
            }
            predecessors.put(key, ids);
         }
      }
      return new AttackTacticKnowledge(version, tactics, predecessors);
   }

   public String getVersion() { return version; }
   public boolean isValidTactic(String id) { return id != null && tactics.containsKey(id.trim()); }
   public String getName(String id) { return tactics.get(id); }

   public String toPromptText() {
      StringBuilder builder = new StringBuilder("ATT&CK_VERSION=").append(version).append(System.lineSeparator());
      for (Map.Entry<String, String> entry : tactics.entrySet()) {
         builder.append(entry.getKey()).append(" = ").append(entry.getValue());
         List<String> before = predecessors.get(entry.getKey());
         if (before != null && !before.isEmpty()) {
            builder.append("; preferred_predecessors=").append(before);
         }
         builder.append(System.lineSeparator());
      }
      return builder.toString().trim();
   }

   private static byte[] readAll(InputStream input) throws java.io.IOException {
      java.io.ByteArrayOutputStream output = new java.io.ByteArrayOutputStream();
      byte[] buffer = new byte[4096];
      int count;
      while ((count = input.read(buffer)) >= 0) {
         if (count > 0) output.write(buffer, 0, count);
      }
      return output.toByteArray();
   }
}
