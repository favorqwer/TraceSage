package util.llm;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.nio.file.Path;
import java.util.Set;
import model.EntityNode;
import model.EventEdge;
import org.jgrapht.graph.DirectedPseudograph;

/**
 * Applies deterministic graph cleanup before LLM-based semantic analysis.
 */
public class LlmEdgePrefilter {
   private final Path configPath;

   public LlmEdgePrefilter() {
      this(null);
   }

   LlmEdgePrefilter(Path configPath) {
      this.configPath = configPath;
   }

   public GraphPrefilterResult filterGraph(DirectedPseudograph<EntityNode, EventEdge> graph) {
      DirectedPseudograph<EntityNode, EventEdge> safeGraph = graph == null ? new DirectedPseudograph(EventEdge.class) : graph;
      LlmEdgePrefilterConfig config = this.configPath == null ? LlmEdgePrefilterConfig.loadDefault() : LlmEdgePrefilterConfig.load(this.configPath);
      List<LlmNoiseGraphEdge> orderedEdges = LlmNoiseGraphSelector.serializeFullGraphEdges(safeGraph);
      StructuralDecision structuralDecision = findStructuralDecisions(safeGraph, config);
      List<LlmNoiseGraphEdge> keepEdges = new ArrayList<>();
      List<LlmNoiseGraphEdge> structuralDrops = new ArrayList<>();
      List<LlmNoiseGraphEdge> structuralNormalizationDrops = new ArrayList<>();
      List<LlmNoiseGraphEdge> ruleDrops = new ArrayList<>();
      DirectedPseudograph<EntityNode, EventEdge> keepGraph = new DirectedPseudograph(EventEdge.class);

      for (EntityNode node : safeGraph.vertexSet()) {
         keepGraph.addVertex(node);
      }

      for (LlmNoiseGraphEdge graphEdge : orderedEdges) {
         EventEdge edge = graphEdge.getEdge();
         if (structuralDecision.normalizationDrops.contains(edge)) {
            structuralDrops.add(graphEdge);
            structuralNormalizationDrops.add(graphEdge);
         } else if (shouldDropByRule(edge, config)) {
            ruleDrops.add(graphEdge);
         } else {
            keepEdges.add(graphEdge);
            addEdgeToGraph(keepGraph, edge);
         }
      }

      return new GraphPrefilterResult(
         keepGraph,
         orderedEdges.size(),
         keepEdges,
         structuralDrops,
         structuralNormalizationDrops,
         ruleDrops,
         structuralDecision.reasons,
         structuralDecision.representatives,
         structuralDecision.semanticFamilies,
         structuralDecision.duplicateDropCount,
         structuralDecision.semanticMirrorDropCount,
         config.getStatus()
      );
   }

   public static String summarize(GraphPrefilterResult result) {
      if (result == null) {
         return "input=0, structural_drop=0, rule_drop=0, keep=0";
      }
      return "input="
         + result.getInputEdgeCount()
         + ", structural_drop="
         + result.getStructuralDroppedEdges().size()
         + " (duplicate_edge="
         + result.getDuplicateDropCount()
         + ", semantic_mirror="
         + result.getSemanticMirrorDropCount()
         + ")"
         + ", rule_drop="
         + result.getRuleDroppedEdges().size()
         + ", keep="
         + result.getKeepEdges().size()
         + ", content_rules="
         + result.getContentRuleStatus();
   }

   private static StructuralDecision findStructuralDecisions(
      DirectedPseudograph<EntityNode, EventEdge> graph,
      LlmEdgePrefilterConfig config
   ) {
      Set<EventEdge> normalizationDrops = new HashSet<>();
      Map<EventEdge, String> reasons = new LinkedHashMap<>();
      Map<EventEdge, Long> representatives = new LinkedHashMap<>();
      Map<EventEdge, String> semanticFamilies = new LinkedHashMap<>();
      List<EventEdge> ordered = new ArrayList<>(graph.edgeSet());
      ordered.sort(EDGE_ORDER);

      int duplicateDropCount = findDuplicateEdgeDrops(
         ordered, normalizationDrops, reasons, representatives
      );
      int semanticMirrorDropCount = findSemanticNormalizationDrops(
         ordered,
         normalizationDrops,
         reasons,
         representatives,
         semanticFamilies
      );

      return new StructuralDecision(
         normalizationDrops,
         reasons,
         representatives,
         semanticFamilies,
         duplicateDropCount,
         semanticMirrorDropCount
      );
   }

   private static int findDuplicateEdgeDrops(
      List<EventEdge> ordered,
      Set<EventEdge> normalizationDrops,
      Map<EventEdge, String> reasons,
      Map<EventEdge, Long> representatives
   ) {
      Map<DuplicateKey, List<EventEdge>> groups = new LinkedHashMap<>();
      for (EventEdge edge : ordered) {
         DuplicateKey key = DuplicateKey.from(edge);
         if (key != null) groups.computeIfAbsent(key, ignored -> new ArrayList<>()).add(edge);
      }

      int dropped = 0;
      for (List<EventEdge> group : groups.values()) {
         group.sort(TIME_ORDER);
         List<EventEdge> cluster = new ArrayList<>();
         for (EventEdge edge : group) {
            if (!canJoinDuplicateCluster(cluster, edge)) {
               dropped += keepDuplicateCluster(cluster, normalizationDrops, reasons, representatives);
               cluster.clear();
            }
            cluster.add(edge);
         }
         dropped += keepDuplicateCluster(cluster, normalizationDrops, reasons, representatives);
      }
      return dropped;
   }

   private static int keepDuplicateCluster(
      List<EventEdge> cluster,
      Set<EventEdge> normalizationDrops,
      Map<EventEdge, String> reasons,
      Map<EventEdge, Long> representatives
   ) {
      if (cluster == null || cluster.size() <= 1) return 0;
      EventEdge representative = cluster.get(0);
      for (int i = 1; i < cluster.size(); i++) {
         EventEdge candidate = cluster.get(i);
         if (DUPLICATE_REPRESENTATIVE_ORDER.compare(candidate, representative) < 0) representative = candidate;
      }
      int dropped = 0;
      for (EventEdge edge : cluster) {
         if (edge == representative) continue;
         normalizationDrops.add(edge);
         reasons.put(edge, "duplicate_edge");
         representatives.put(edge, representative.getID());
         dropped++;
      }
      return dropped;
   }

   private static int findSemanticNormalizationDrops(
      List<EventEdge> ordered,
      Set<EventEdge> normalizationDrops,
      Map<EventEdge, String> reasons,
      Map<EventEdge, Long> representatives,
      Map<EventEdge, String> semanticFamilies
   ) {
      Map<SemanticKey, List<EventEdge>> groups = new LinkedHashMap<>();
      for (EventEdge edge : ordered) {
         if (normalizationDrops.contains(edge)) continue;
         SemanticEventFamily family = SemanticEventFamily.from(edge);
         if (family != null) {
            groups.computeIfAbsent(new SemanticKey(edge, family.name), ignored -> new ArrayList<>()).add(edge);
         }
      }

      int dropped = 0;
      for (Map.Entry<SemanticKey, List<EventEdge>> entry : groups.entrySet()) {
         List<EventEdge> group = entry.getValue();
         group.sort(TIME_ORDER);
         List<EventEdge> cluster = new ArrayList<>();
         for (EventEdge edge : group) {
            if (!canJoinDuplicateCluster(cluster, edge)) {
               dropped += keepSemanticCluster(cluster, entry.getKey().familyName, normalizationDrops, reasons, representatives, semanticFamilies);
               cluster.clear();
            }
            cluster.add(edge);
         }
         dropped += keepSemanticCluster(cluster, entry.getKey().familyName, normalizationDrops, reasons, representatives, semanticFamilies);
      }
      return dropped;
   }

   private static int keepSemanticCluster(
      List<EventEdge> cluster,
      String familyName,
      Set<EventEdge> normalizationDrops,
      Map<EventEdge, String> reasons,
      Map<EventEdge, Long> representatives,
      Map<EventEdge, String> semanticFamilies
   ) {
      if (cluster == null || cluster.size() <= 1) return 0;
      EventEdge representative = cluster.get(0);
      for (int i = 1; i < cluster.size(); i++) {
         EventEdge candidate = cluster.get(i);
         if (SEMANTIC_REPRESENTATIVE_ORDER.compare(candidate, representative) < 0) representative = candidate;
      }
      int dropped = 0;
      for (EventEdge edge : cluster) {
         if (edge == representative || normalize(edge.getEvent()).equals(normalize(representative.getEvent()))) continue;
         normalizationDrops.add(edge);
         reasons.put(edge, "semantic_mirror");
         representatives.put(edge, representative.getID());
         semanticFamilies.put(edge, familyName);
         dropped++;
      }
      return dropped;
   }

   private static boolean canJoinDuplicateCluster(List<EventEdge> cluster, EventEdge candidate) {
      for (EventEdge existing : cluster) {
         if (hostsConflict(existing, candidate)) return false;
      }
      return true;
   }

   private static boolean hostsConflict(EventEdge first, EventEdge second) {
      String firstHost = normalize(first == null ? null : first.getHost());
      String secondHost = normalize(second == null ? null : second.getHost());
      return !firstHost.isEmpty() && !secondHost.isEmpty() && !firstHost.equals(secondHost);
   }

   private static final Comparator<EventEdge> EDGE_ORDER = Comparator
      .comparingLong((EventEdge edge) -> edge.getSource() == null ? Long.MIN_VALUE : edge.getSource().getId())
      .thenComparingLong(edge -> edge.getSink() == null ? Long.MIN_VALUE : edge.getSink().getId())
      .thenComparing(edge -> normalize(edge.getHost()))
      .thenComparingLong(EventEdge::getStartns)
      .thenComparingLong(EventEdge::getEndns)
      .thenComparingLong(EventEdge::getID);

   private static final Comparator<EventEdge> TIME_ORDER = Comparator
      .comparingLong(EventEdge::getStartns)
      .thenComparingLong(EventEdge::getEndns)
      .thenComparingLong(EventEdge::getID);

   private static final Comparator<EventEdge> DUPLICATE_REPRESENTATIVE_ORDER = Comparator
      .comparingLong(LlmEdgePrefilter::durationNs)
      .reversed()
      .thenComparingLong(EventEdge::getID);

   private static final Comparator<EventEdge> SEMANTIC_REPRESENTATIVE_ORDER = Comparator
      .comparingInt(LlmEdgePrefilter::semanticEventRank)
      .thenComparingLong(EventEdge::getID);

   private static long durationNs(EventEdge edge) {
      if (edge == null) return Long.MIN_VALUE;
      return Math.max(0L, edge.getEndns() - edge.getStartns());
   }

   private static int semanticEventRank(EventEdge edge) {
      SemanticEventFamily family = SemanticEventFamily.from(edge);
      return family == null ? Integer.MAX_VALUE : family.rank(edge.getEvent());
   }

   private static boolean isNetworkNode(EntityNode node) {
      if (node == null) return false;
      if (node.getN() != null) return true;
      String signature = normalize(node.getSignature());
      return signature.contains("->") && node.getF() == null;
   }

   private static boolean isProcessNode(EntityNode node) {
      return node != null && node.getP() != null;
   }

   private static boolean isFileNode(EntityNode node) {
      return node != null && node.getF() != null;
   }

   private static final class StructuralDecision {
      private final Set<EventEdge> normalizationDrops;
      private final Map<EventEdge, String> reasons;
      private final Map<EventEdge, Long> representatives;
      private final Map<EventEdge, String> semanticFamilies;
      private final int duplicateDropCount;
      private final int semanticMirrorDropCount;

      private StructuralDecision(
         Set<EventEdge> normalizationDrops,
         Map<EventEdge, String> reasons,
         Map<EventEdge, Long> representatives,
         Map<EventEdge, String> semanticFamilies,
         int duplicateDropCount,
         int semanticMirrorDropCount
      ) {
         this.normalizationDrops = normalizationDrops;
         this.reasons = reasons;
         this.representatives = representatives;
         this.semanticFamilies = semanticFamilies;
         this.duplicateDropCount = duplicateDropCount;
         this.semanticMirrorDropCount = semanticMirrorDropCount;
      }
   }

   private static final class DuplicateKey {
      private final long sourceId;
      private final long sinkId;
      private final String event;

      private DuplicateKey(
         long sourceId,
         long sinkId,
         String event
      ) {
         this.sourceId = sourceId;
         this.sinkId = sinkId;
         this.event = event;
      }

      private static DuplicateKey from(EventEdge edge) {
         if (edge == null || edge.getSource() == null || edge.getSink() == null) return null;
         return new DuplicateKey(
            edge.getSource().getId(),
            edge.getSink().getId(),
            normalize(edge.getEvent())
         );
      }

      @Override
      public boolean equals(Object other) {
         if (this == other) return true;
         if (!(other instanceof DuplicateKey)) return false;
         DuplicateKey that = (DuplicateKey) other;
         return this.sourceId == that.sourceId
            && this.sinkId == that.sinkId
            && this.event.equals(that.event);
      }

      @Override
      public int hashCode() {
         int result = Long.hashCode(this.sourceId);
         result = 31 * result + Long.hashCode(this.sinkId);
         result = 31 * result + this.event.hashCode();
         return result;
      }
   }

   private static final class SemanticKey {
      private final long sourceId;
      private final long sinkId;
      private final String familyName;

      private SemanticKey(EventEdge edge, String familyName) {
         this.sourceId = edge.getSource().getId();
         this.sinkId = edge.getSink().getId();
         this.familyName = familyName;
      }

      @Override
      public boolean equals(Object other) {
         if (this == other) return true;
         if (!(other instanceof SemanticKey)) return false;
         SemanticKey that = (SemanticKey) other;
         return this.sourceId == that.sourceId && this.sinkId == that.sinkId && this.familyName.equals(that.familyName);
      }

      @Override
      public int hashCode() {
         int result = Long.hashCode(this.sourceId);
         result = 31 * result + Long.hashCode(this.sinkId);
         return 31 * result + this.familyName.hashCode();
      }
   }

   private static final class SemanticEventFamily {
      private static final List<SemanticEventFamily> FAMILIES = createFamilies();
      private final String name;
      private final String[] aliases;
      private final String[] priorities;
      private final NodePairMatcher nodePairMatcher;

      private SemanticEventFamily(String name, String[] aliases, String[] priorities, NodePairMatcher nodePairMatcher) {
         this.name = name;
         this.aliases = aliases;
         this.priorities = priorities;
         this.nodePairMatcher = nodePairMatcher;
      }

      private static List<SemanticEventFamily> createFamilies() {
         List<SemanticEventFamily> families = new ArrayList<>();
         families.add(new SemanticEventFamily(
            "network_receive",
            new String[]{"recvmsg", "recvfrom", "read_socket_params", "readv", "read"},
            new String[]{"recvmsg", "recvfrom", "read_socket_params", "readv", "read"},
            (source, sink) -> isNetworkNode(source) && isProcessNode(sink)
         ));
         families.add(new SemanticEventFamily(
            "network_send",
            new String[]{"sendmsg", "sendto", "connect", "write_socket_params", "writev", "write"},
            new String[]{"sendmsg", "sendto", "connect", "write_socket_params", "writev", "write"},
            (source, sink) -> isProcessNode(source) && isNetworkNode(sink)
         ));
         families.add(new SemanticEventFamily(
            "file_read",
            new String[]{"read", "pread", "pread64", "readv", "preadv", "preadv2"},
            new String[]{"pread64", "preadv2", "preadv", "pread", "readv", "read"},
            (source, sink) -> isFileNode(source) && isProcessNode(sink)
         ));
         families.add(new SemanticEventFamily(
            "file_metadata_observation",
            new String[]{"stat", "lstat", "fstat", "fstatat", "newfstatat", "statx", "statfs", "statfs64", "fstatfs", "fstatfs64"},
            new String[]{"statx", "newfstatat", "fstatat", "fstat", "lstat", "stat", "statfs64", "statfs", "fstatfs64", "fstatfs"},
            (source, sink) -> isFileNode(source) && isProcessNode(sink)
         ));
         return Collections.unmodifiableList(families);
      }

      private static SemanticEventFamily from(EventEdge edge) {
         if (edge == null || edge.getSource() == null || edge.getSink() == null) return null;
         String event = normalize(edge.getEvent());
         for (SemanticEventFamily family : FAMILIES) {
            if (family.nodePairMatcher.matches(edge.getSource(), edge.getSink()) && family.contains(event)) return family;
         }
         return null;
      }

      private boolean contains(String event) {
         for (String alias : this.aliases) if (alias.equals(event)) return true;
         return false;
      }

      private int rank(String event) {
         String normalized = normalize(event);
         for (int index = 0; index < this.priorities.length; index++) {
            if (this.priorities[index].equals(normalized)) return index;
         }
         return Integer.MAX_VALUE;
      }
   }

   private interface NodePairMatcher {
      boolean matches(EntityNode source, EntityNode sink);
   }

   private static boolean shouldDropByRule(EventEdge edge, LlmEdgePrefilterConfig config) {
      if (edge == null || edge.getSource() == null || edge.getSink() == null) {
         return true;
      }
      if (!config.isContentFilteringEnabled()) {
         return false;
      }
      String event = normalize(edge.getEvent());
      String sourceValue = normalizedFileSignatureValue(edge.getSource());
      String sinkValue = normalizedFileSignatureValue(edge.getSink());
      return config.matches(event, sourceValue, sinkValue);
   }

   private static void addEdgeToGraph(DirectedPseudograph<EntityNode, EventEdge> graph, EventEdge edge) {
      if (graph == null || edge == null) {
         return;
      }
      if (!graph.containsVertex(edge.getSource())) {
         graph.addVertex(edge.getSource());
      }
      if (!graph.containsVertex(edge.getSink())) {
         graph.addVertex(edge.getSink());
      }
      if (!graph.containsEdge(edge)) {
         graph.addEdge(edge.getSource(), edge.getSink(), edge);
      }
   }

   private static String normalizedSignatureValue(EntityNode node) {
      if (node == null || node.getSignature() == null) {
         return "";
      }
      String signature = normalize(node.getSignature());
      int colonIndex = signature.indexOf(": ");
      return colonIndex >= 0 ? signature.substring(colonIndex + 2).trim() : signature;
   }

   private static String normalizedFileSignatureValue(EntityNode node) {
      return node != null && node.getF() != null ? normalizedSignatureValue(node) : "";
   }

   private static String normalize(String value) {
      return value == null ? "" : value.trim().toLowerCase(Locale.US);
   }

   public static final class GraphPrefilterResult {
      private final DirectedPseudograph<EntityNode, EventEdge> keepGraph;
      private final int inputEdgeCount;
      private final List<LlmNoiseGraphEdge> keepEdges;
      private final List<LlmNoiseGraphEdge> structuralDroppedEdges;
      private final List<LlmNoiseGraphEdge> structuralNormalizationDroppedEdges;
      private final List<LlmNoiseGraphEdge> ruleDroppedEdges;
      private final List<LlmNoiseGraphEdge> droppedEdges;
      private final Map<Long, String> structuralDropReasons;
      private final Map<Long, Long> structuralDropRepresentatives;
      private final Map<Long, String> structuralDropSemanticFamilies;
      private final int duplicateDropCount;
      private final int semanticMirrorDropCount;
      private final String contentRuleStatus;

      private GraphPrefilterResult(
         DirectedPseudograph<EntityNode, EventEdge> keepGraph,
         int inputEdgeCount,
         List<LlmNoiseGraphEdge> keepEdges,
         List<LlmNoiseGraphEdge> structuralDroppedEdges,
         List<LlmNoiseGraphEdge> structuralNormalizationDroppedEdges,
         List<LlmNoiseGraphEdge> ruleDroppedEdges,
         Map<EventEdge, String> structuralDropReasons,
         Map<EventEdge, Long> structuralDropRepresentatives,
         Map<EventEdge, String> structuralDropSemanticFamilies,
         int duplicateDropCount,
         int semanticMirrorDropCount,
         String contentRuleStatus
      ) {
         this.keepGraph = keepGraph;
         this.inputEdgeCount = inputEdgeCount;
         this.keepEdges = Collections.unmodifiableList(new ArrayList<>(keepEdges));
         this.structuralDroppedEdges = Collections.unmodifiableList(new ArrayList<>(structuralDroppedEdges));
         this.structuralNormalizationDroppedEdges = Collections.unmodifiableList(new ArrayList<>(structuralNormalizationDroppedEdges));
         this.ruleDroppedEdges = Collections.unmodifiableList(new ArrayList<>(ruleDroppedEdges));
         List<LlmNoiseGraphEdge> allDrops = new ArrayList<>(structuralDroppedEdges);
         allDrops.addAll(ruleDroppedEdges);
         this.droppedEdges = Collections.unmodifiableList(allDrops);
         Map<Long, String> reasons = new LinkedHashMap<>();
         for (Map.Entry<EventEdge, String> entry : structuralDropReasons.entrySet()) {
            reasons.put(entry.getKey().getID(), entry.getValue());
         }
         this.structuralDropReasons = Collections.unmodifiableMap(reasons);
         Map<Long, Long> representatives = new LinkedHashMap<>();
         for (Map.Entry<EventEdge, Long> entry : structuralDropRepresentatives.entrySet()) {
            representatives.put(entry.getKey().getID(), entry.getValue());
         }
         this.structuralDropRepresentatives = Collections.unmodifiableMap(representatives);
         Map<Long, String> families = new LinkedHashMap<>();
         for (Map.Entry<EventEdge, String> entry : structuralDropSemanticFamilies.entrySet()) {
            families.put(entry.getKey().getID(), entry.getValue());
         }
         this.structuralDropSemanticFamilies = Collections.unmodifiableMap(families);
         this.duplicateDropCount = duplicateDropCount;
         this.semanticMirrorDropCount = semanticMirrorDropCount;
         this.contentRuleStatus = contentRuleStatus;
      }

      public DirectedPseudograph<EntityNode, EventEdge> getKeepGraph() {
         return this.keepGraph;
      }

      public int getInputEdgeCount() {
         return this.inputEdgeCount;
      }

      public List<LlmNoiseGraphEdge> getKeepEdges() {
         return this.keepEdges;
      }

      public List<LlmNoiseGraphEdge> getStructuralDroppedEdges() {
         return this.structuralDroppedEdges;
      }

      public List<LlmNoiseGraphEdge> getStructuralNormalizationDroppedEdges() {
         return this.structuralNormalizationDroppedEdges;
      }

      public List<LlmNoiseGraphEdge> getDuplicateDroppedEdges() {
         return structuralDropsByReason("duplicate_edge");
      }

      public List<LlmNoiseGraphEdge> getSemanticNormalizationDroppedEdges() {
         return structuralDropsByReason("semantic_mirror");
      }

      public List<LlmNoiseGraphEdge> getRuleDroppedEdges() {
         return this.ruleDroppedEdges;
      }

      public List<LlmNoiseGraphEdge> getDroppedEdges() {
         return this.droppedEdges;
      }

      public String getStructuralDropReason(EventEdge edge) {
         return edge == null ? null : this.structuralDropReasons.get(edge.getID());
      }

      public Long getStructuralDropRepresentativeId(EventEdge edge) {
         return edge == null ? null : this.structuralDropRepresentatives.get(edge.getID());
      }

      public String getStructuralDropSemanticFamily(EventEdge edge) {
         return edge == null ? null : this.structuralDropSemanticFamilies.get(edge.getID());
      }

      public int getDuplicateDropCount() {
         return this.duplicateDropCount;
      }

      public int getSemanticNormalizationDropCount() {
         return this.semanticMirrorDropCount;
      }

      public int getSemanticMirrorDropCount() {
         return this.semanticMirrorDropCount;
      }

      public String getContentRuleStatus() {
         return this.contentRuleStatus;
      }

      private List<LlmNoiseGraphEdge> structuralDropsByReason(String reason) {
         List<LlmNoiseGraphEdge> matches = new ArrayList<>();
         for (LlmNoiseGraphEdge graphEdge : this.structuralDroppedEdges) {
            if (reason.equals(getStructuralDropReason(graphEdge.getEdge()))) matches.add(graphEdge);
         }
         return Collections.unmodifiableList(matches);
      }
   }
}
