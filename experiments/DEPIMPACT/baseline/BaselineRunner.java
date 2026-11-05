package baseline;

import gql.Atom;
import gql.Collect;
import gql.Expression;
import gql.IdInColl;
import gql.Match;
import gql.MapLiteral;
import gql.Max;
import gql.Min;
import gql.NodeLabel;
import gql.NodePattern;
import gql.Pattern;
import gql.PatternElementChain;
import gql.PatternPart;
import gql.Property;
import gql.PropertyExpression;
import gql.PropertyLookup;
import gql.RelationshipDetail;
import gql.RelationshipPattern;
import gql.TraversalExpression;
import gql.Type;
import gql.Variable;
import java.io.File;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.ArrayDeque;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.BiFunction;
import main.Main;
import model.Edge;
import model.EntityNode;
import model.EventEdge;
import model.POIEdge;
import model.ProjectionFeature;
import model.PoiEventInfo;
import org.jgrapht.graph.DirectedPseudograph;
import org.json.JSONArray;
import org.json.JSONObject;
import traversal.neo4jserver.Neo4jServerTraversal;
import util.CausalityPreserve;
import util.ExpressionUtils;
import util.ForwardAnalysis;
import util.GQLBackwardPropagate;
import util.GraphOperations;

/**
 * Deterministic re-execution of the investigation flow of the ProGQL query layer,
 * against the Neo4j provenance store (parser import), producing a JSON
 * artifact for regression comparison.
 *
 * The flow replicates the pipeline logic of main.Main.processSingleProGQLQuery
 * for this query shape (no LLM clause): backward causal traversal, CPR edge
 * merging, projection-feature weighting plus reputation propagation, entry
 * candidate selection, forward expansion from the selected entries, and a final
 * intersection. The ProGQL query text is reconstructed programmatically instead
 * of being parsed.
 *
 * POI 没有默认值，必须显式给：网络 POI 用
 * `--poi-srcip/--poi-srcport/--poi-dstip/--poi-dstport/--poi-optype`；文件 POI 用
 * `--poi-file <绝对路径>`，此时 dst 标签切为 File
 * （`(p:Process)-[st:FileEvent{optype:"write"}]->(f:File{name:"..."})`，`name` 经兼容层映射到 `path`）。
 * 各场景的 POI 见 `provenance/config/scenarios.json`。属性名沿用 PG 侧写法，
 * 由 Neo4jServerTraversal 兼容层翻译到 Neo4j schema（lip/lport/rip/rport/syscall，
 * 并剥掉 /32、/128 后缀）。
 *
 * 入口数默认 5，可用 `--entry-limit N` 覆盖。
 * final_edges 内嵌 `syscall/starttime/endtime`（秒，浮点），使产物自足、
 * 评分（tools/score_graph_product.py）无需回库。
 */
public class BaselineRunner {
   private static final double CPR_MERGE_WINDOW = 10.0;
   private static int entryLimit = 5;

   // POI 匹配参数：没有默认值，必须由命令行给全（见类注释）；optype 默认 write。
   private static String poiSrcIp = "";
   private static String poiSrcPort = "";
   private static String poiDstIp = "";
   private static String poiDstPort = "";
   private static String poiEndpoints = null;
   private static String poiOptype = "write";
   private static String poiFile = null;
   private static final Map<Long, Double> entryCompositeScores = new HashMap<>();
   private static double entryImpactWeight = 1.0;
   private static double entryTimeWeight = 0.0;

   public static void main(String[] args) throws Exception {
      if (args.length == 0 || args[0].isEmpty()) {
         throw new IllegalArgumentException("usage: <scenarioName> [outDir] "
            + "[--poi-srcip v --poi-srcport v --poi-dstip v --poi-dstport v --poi-optype v] "
            + "[--poi-endpoints ep] [--poi-file path] [--entry-limit N]（POI 无默认值，必须显式给）");
      }
      String dbName = args[0];
      String outDirArg = args.length > 1 ? args[1] : "output/engine-baseline/" + dbName;

      // POI 参数（见类注释；无默认值）。
      for (int i = 2; i < args.length; i++) {
         String key = args[i];
         if (!(key.startsWith("--poi-") || key.equals("--entry-limit")) || i + 1 >= args.length) {
            throw new IllegalArgumentException("Unknown argument: " + key
               + " (usage: <dbName> <outDir> [--poi-srcip v --poi-srcport v --poi-dstip v --poi-dstport v --poi-optype v]"
               + " [--poi-endpoints ep] [--poi-file path] [--entry-limit N])");
         }
         String value = args[++i];
         switch (key) {
            case "--poi-srcip": poiSrcIp = value; break;
            case "--poi-srcport": poiSrcPort = value; break;
            case "--poi-dstip": poiDstIp = value; break;
            case "--poi-dstport": poiDstPort = value; break;
            case "--poi-endpoints": poiEndpoints = value; break;
            case "--poi-optype": poiOptype = value; break;
            case "--poi-file": poiFile = value; break;
            case "--entry-limit": entryLimit = Integer.parseInt(value); break;
            default:
               throw new IllegalArgumentException("Unknown POI option: " + key);
         }
      }

      if (poiFile == null && poiEndpoints == null
            && (poiSrcIp.isEmpty() || poiSrcPort.isEmpty() || poiDstIp.isEmpty() || poiDstPort.isEmpty())) {
         throw new IllegalArgumentException("需要 --poi-file <路径>，或 --poi-endpoints <endpoints>，或四个网络 POI 参数 "
            + "--poi-srcip/--poi-srcport/--poi-dstip/--poi-dstport");
      }

      Path outDir = Paths.get(outDirArg);
      Files.createDirectories(outDir);

      Neo4jServerTraversal traversal = new Neo4jServerTraversal();
      try {
         traversal.initial(dbName);

         // Step 1: POI match + backward causal traversal (g_raw)
      Main.poiEdge = new POIEdge("st");
      Match poiMatch = buildPoiMatch();
      String poiPattern = poiMatch.getPattern().toString();
      System.out.println("POI pattern: " + poiPattern);

      Edge backwardEdge = new Edge("r");
      Expression backwardWhere = buildCausalityExpression(
         "r.starttime<max(collect(vout IN out(v) | vout.endtime))", "vout", "v", "out", "endtime", true
      );
      long t0 = System.currentTimeMillis();
      DirectedPseudograph<EntityNode, EventEdge> bRaw =
         traversal.traverse(poiPattern, null, backwardEdge, "backward", backwardWhere, false, poiMatch);
      System.out.println("b_raw: " + bRaw.vertexSet().size() + "v/" + bRaw.edgeSet().size() + "e in " + (System.currentTimeMillis() - t0) + "ms");
      if (bRaw.vertexSet().isEmpty()) {
         throw new IllegalStateException("backward traversal returned an empty graph; nothing to baseline");
      }

      // Step 2: causality-preserving edge merge
      DirectedPseudograph<EntityNode, EventEdge> bCpr = applyCpr(bRaw);
      System.out.println("b_cpr: " + bCpr.vertexSet().size() + "v/" + bCpr.edgeSet().size() + "e");

      // Step 3: projection-feature weights + reputation propagation (SET clauses)
      GQLBackwardPropagate propagate = new GQLBackwardPropagate(bCpr);
      propagate.setMyEdge(backwardEdge);
      propagate.setPoiEdge(Main.poiEdge);
      propagate.setSeedSources(new HashSet<>(Arrays.asList(Main.highRP)));
      propagate.setProjectionFeatureLst(buildProjectionFeatures());
      propagate.calculateWeights_ML_ClusterAll(true);
      propagate.initialReputation(Main.highRP, new String[0], new String[0]);
      propagate.PageRankIteration(Main.detection);

      // Step 4: entry candidates WHERE count(in(n))=0 ORDER BY n.rel DESC LIMIT 5
      Expression countExpression = new Expression("count(in(n))=0");
      CandidateLsts candidates = getEntryLstByCountExpr(bCpr, countExpression);
      Map<EntityNode, BigDecimal> entryTimes = findEarliestCausalEntryTimes(bCpr);
      entryCompositeScores.clear();
      sortEntryCandidates(candidates.networkLst, entryTimes, "desc");
      sortEntryCandidates(candidates.fileLst, entryTimes, "desc");
      sortEntryCandidates(candidates.processLst, entryTimes, "desc");
      List<EntityNode> topEntries = selectEntryCandidatesByQuota(candidates.networkLst, candidates.fileLst, candidates.processLst, entryLimit);
      System.out.println("entry candidates: network=" + candidates.networkLst.size() + " file=" + candidates.fileLst.size() + " process=" + candidates.processLst.size() + ", selected top " + topEntries.size());

      // Step 5: forward expansion from the selected entries (in-memory subgraph, aligned with DepImpact)
      BigDecimal poiTime = null;
      if (Main.poiEventInfo != null && Main.poiEventInfo.getEndTime() != null) {
         poiTime = Main.poiEventInfo.getEndTime();
      } else {
         for (EventEdge e : bCpr.edgeSet()) {
            if (e.getEndTime() != null && (poiTime == null || e.getEndTime().compareTo(poiTime) > 0)) {
               poiTime = e.getEndTime();
            }
         }
      }

      ForwardAnalysis forwardAnalysis = new ForwardAnalysis(bCpr);
      DirectedPseudograph<EntityNode, EventEdge> forwardUnion = new DirectedPseudograph(EventEdge.class);
      JSONArray perEntry = new JSONArray();
      int entryRank = 1;
      for (EntityNode entry : topEntries) {
         DirectedPseudograph<EntityNode, EventEdge> internal = forwardAnalysis.forwardLimitedByTime(entry, poiTime);
         JSONObject item = new JSONObject()
            .put("rank", entryRank)
            .put("id", entry.getId())
            .put("signature", entry.getSignature())
            .put("vertices", internal.vertexSet().size())
            .put("edges", internal.edgeSet().size());
         perEntry.put(item);
         System.out.println("forward from entry #" + entryRank + " id=" + entry.getId() + ": " + internal.vertexSet().size() + "v/" + internal.edgeSet().size() + "e");
         if (forwardUnion.vertexSet().isEmpty() && forwardUnion.edgeSet().isEmpty()) {
            forwardUnion = internal;
         } else {
            forwardUnion = GraphOperations.union(forwardUnion, internal);
         }
         entryRank++;
      }
      System.out.println("forward_union: " + forwardUnion.vertexSet().size() + "v/" + forwardUnion.edgeSet().size() + "e");

      // Step 6: final result = INTERSECT(bCpr, forwardUnion) (with DepImpact fallback if forwardUnion is empty)
      DirectedPseudograph<EntityNode, EventEdge> finalGraph;
      if (forwardUnion.edgeSet().isEmpty()) {
         System.out.println("forward_union is empty; fallback to b_cpr (aligned with DepImpact fallback)");
         finalGraph = bCpr;
      } else {
         finalGraph = GraphOperations.intersection(bCpr, forwardUnion);
      }
      System.out.println("final: " + finalGraph.vertexSet().size() + "v/" + finalGraph.edgeSet().size() + "e");

      // --- baseline artifact ---
      JSONObject root = new JSONObject();
      root.put("meta", new JSONObject()
         .put("scenario", dbName)
         .put("database", traversal.connectionDescription())
         .put("query_file", "input/sysdig/" + dbName + ".query")
         .put("poi_pattern", poiPattern)
         .put("entry_limit", entryLimit)
         .put("entry_order", "desc")
         .put("cpr_merge_window", CPR_MERGE_WINDOW)
         .put("unsupervised_mode", true)
         .put("prior_knowledge", "none")
         .put("entry_ranking_policy", "pure_reputation")
         .put("forward_analysis_scope", "in_memory_subgraph")
         .put("entry_ranking_weights", new JSONArray(Arrays.asList(entryImpactWeight, entryTimeWeight))));

      PoiEventInfo poi = Main.poiEventInfo;
      root.put("poi", new JSONObject()
         .put("source_signature", poi == null ? JSONObject.NULL : poi.getSourceSignature())
         .put("sink_signature", poi == null ? JSONObject.NULL : poi.getSinkSignature())
         .put("event_type", poi == null ? JSONObject.NULL : poi.getEventType())
         .put("start_time", poi == null ? JSONObject.NULL : poi.getStartTime())
         .put("end_time", poi == null ? JSONObject.NULL : poi.getEndTime()));

      root.put("stages", new JSONObject()
         .put("b_raw", stageCounts(bRaw))
         .put("b_cpr", stageCounts(bCpr))
         .put("b_score", stageCounts(bCpr))
         .put("forward_union", stageCounts(forwardUnion))
         .put("final", stageCounts(finalGraph)));

      root.put("entry_candidates", new JSONObject()
         .put("network", candidates.networkLst.size())
         .put("file", candidates.fileLst.size())
         .put("process", candidates.processLst.size()));

      JSONArray ranking = new JSONArray();
      int rank = 1;
      for (EntityNode entry : topEntries) {
         ranking.put(new JSONObject()
            .put("rank", rank)
            .put("id", entry.getId())
            .put("entity_type", entityType(entry))
            .put("signature", entry.getSignature())
            .put("composite_score", round(getEntryCompositeScore(entry), 9))
            .put("reputation", round(entry.getReputation(), 9))
            .put("earliest_entry_time", entryTimes.get(entry) == null ? JSONObject.NULL : entryTimes.get(entry)));
         rank++;
      }
      root.put("entry_ranking", ranking);
      root.put("forward_per_entry", perEntry);

      JSONObject candidateLists = new JSONObject()
         .put("network", candidateArray(candidates.networkLst, entryTimes))
         .put("file", candidateArray(candidates.fileLst, entryTimes))
         .put("process", candidateArray(candidates.processLst, entryTimes));
      root.put("entry_candidate_lists", candidateLists);

      root.put("final_vertex_mix", vertexMix(finalGraph));
      root.put("final_event_distribution", eventDistribution(finalGraph));

      List<String> bRawKeys = new ArrayList<>(GraphOperations.edgeKeys(bRaw));
      bRawKeys.sort(Comparator.naturalOrder());
      root.put("b_raw_edge_keys", new JSONArray(bRawKeys));

      List<String> forwardUnionKeys = new ArrayList<>(GraphOperations.edgeKeys(forwardUnion));
      forwardUnionKeys.sort(Comparator.naturalOrder());
      root.put("forward_union_edge_keys", new JSONArray(forwardUnionKeys));

      JSONArray vertices = new JSONArray();
      List<EntityNode> sortedVertices = new ArrayList<>(finalGraph.vertexSet());
      sortedVertices.sort(Comparator.comparingLong(EntityNode::getId));
      for (EntityNode v : sortedVertices) {
         vertices.put(new JSONObject()
            .put("id", v.getId())
            .put("entity_type", entityType(v))
            .put("signature", v.getSignature())
            .put("reputation", round(v.getReputation(), 9)));
      }
      root.put("final_vertices", vertices);

      JSONArray edges = new JSONArray();
      List<EventEdge> sortedEdges = new ArrayList<>(finalGraph.edgeSet());
      sortedEdges.sort(Comparator.comparing(CanonicalKey::of));
      for (EventEdge e : sortedEdges) {
         // syscall/starttime/endtime 内嵌（时间=秒，浮点），使产物自足、评分无需回库。
         edges.put(edgeFact(e).put("weight", round(e.weight, 6)));
      }
      root.put("final_edges", edges);

      List<EventEdge> bScoreEdgeList = new ArrayList<>(bCpr.edgeSet());
      bScoreEdgeList.sort(Comparator.comparing(CanonicalKey::of));
      JSONArray bScoreEdges = new JSONArray();
      for (EventEdge e : bScoreEdgeList) {
         bScoreEdges.put(new JSONObject()
            .put("key", CanonicalKey.of(e))
            .put("weight", round(e.weight, 6)));
      }
      root.put("b_score_edges", bScoreEdges);

         Path jsonPath = outDir.resolve("baseline.json");
         Files.write(jsonPath, root.toString(2).getBytes(StandardCharsets.UTF_8));
         System.out.println("baseline written: " + jsonPath.toAbsolutePath());
      } finally {
         traversal.close();
      }
   }

   // --- query reconstruction (programmatic equivalent of the parsed query file) ---

   private static Match buildPoiMatch() {
      NodePattern src = new NodePattern(new Variable("p"), new NodeLabel("Process"));
      NodePattern dst;
      String relationshipType;
      if (poiFile != null) {
         dst = new NodePattern(
            new Variable("f"),
            new NodeLabel("File"),
            Arrays.asList(new Property("name", JSONObject.quote(poiFile)))
         );
         relationshipType = ":FileEvent";
      } else {
         List<Property> netProps = new ArrayList<>();
         if (poiEndpoints != null && !poiEndpoints.isEmpty()) {
            netProps.add(new Property("endpoints", "\"" + poiEndpoints + "\""));
         } else if (!poiSrcIp.isEmpty() && !poiSrcPort.isEmpty() && !poiDstIp.isEmpty() && !poiDstPort.isEmpty()) {
            String ep = poiSrcIp + ":" + poiSrcPort + "->" + poiDstIp + ":" + poiDstPort;
            netProps.add(new Property("endpoints", "\"" + ep + "\""));
            netProps.add(new Property("srcip", "\"" + poiSrcIp + "\""));
            netProps.add(new Property("srcport", "\"" + poiSrcPort + "\""));
            netProps.add(new Property("dstip", "\"" + poiDstIp + "\""));
            netProps.add(new Property("dstport", "\"" + poiDstPort + "\""));
         }
         dst = new NodePattern(
            new Variable("net"),
            new NodeLabel("Network"),
            netProps
         );
         relationshipType = ":NetworkEvent";
      }
      RelationshipDetail detail = new RelationshipDetail(new Variable("st"), new Type(relationshipType), new MapLiteral("optype", "\"" + poiOptype + "\""));
      PatternElementChain chain = new PatternElementChain(new RelationshipPattern(detail, ">"), dst);
      return new Match(new Pattern(new PatternPart(src, chain)));
   }

   private static Expression buildCausalityExpression(String exprStr, String outerVar, String inVar, String direction, String property, boolean max) {
      Expression expression = new Expression(exprStr);
      IdInColl idInColl = new IdInColl(new Variable(outerVar), new Expression(direction + "(" + inVar + ")"));
      PropertyExpression propertyExpression = new PropertyExpression(new Atom(new Variable(outerVar)), new PropertyLookup(property));
      Collect collect = new Collect(idInColl, propertyExpression);
      TraversalExpression traversalExpression = new TraversalExpression();
      if (max) {
         traversalExpression.setMax(new Max(collect));
      } else {
         traversalExpression.setMin(new Min(collect));
      }
      expression.setTraversalExpression(traversalExpression);
      return expression;
   }

   private static List<ProjectionFeature> buildProjectionFeatures() {
      ProjectionFeature amount = new ProjectionFeature("1/(abs(r.amount-st.amount)+0.0001)");
      amount.setFeatureType("amount");
      amount.setVariableTermLst(Arrays.asList("r.amount", "st.amount"));

      ProjectionFeature time = new ProjectionFeature("ln(1+1/abs(r.endtime-st.endtime))");
      time.setFeatureType("time");
      time.setVariableTermLst(Arrays.asList("r.endtime", "st.endtime"));

      ProjectionFeature structure = new ProjectionFeature("count(out(v))/count(in(v))");
      structure.setFeatureType("structure");
      structure.setVariableTermLst(new ArrayList<>());

      return Arrays.asList(amount, time, structure);
   }

   // --- pipeline helpers replicated from main.Main (deterministic parts) ---

   private static DirectedPseudograph<EntityNode, EventEdge> applyCpr(DirectedPseudograph<EntityNode, EventEdge> graph) {
      if (graph == null || graph.edgeSet().isEmpty()) {
         return GraphOperations.copy(graph);
      }
      return new CausalityPreserve(GraphOperations.copy(graph)).mergeEdgeFallInTheRange2(CPR_MERGE_WINDOW);
   }

   private static final class CandidateLsts {
      List<EntityNode> fileLst = new ArrayList<>();
      List<EntityNode> processLst = new ArrayList<>();
      List<EntityNode> networkLst = new ArrayList<>();
   }

   private static CandidateLsts getEntryLstByCountExpr(DirectedPseudograph<EntityNode, EventEdge> jg, Expression countExpr) {
      CandidateLsts result = new CandidateLsts();
      String excludedSignature = Main.detection;
      StringBuilder operator = new StringBuilder();
      StringBuilder value = new StringBuilder();
      ExpressionUtils.extractOperatorAndValue(countExpr.toString(), operator, value);
      BiFunction<Integer, Integer, Boolean> func = compare(operator.toString());
      boolean usesIn = countExpr.toString().contains("in(");
      boolean usesOut = countExpr.toString().contains("out(");

      for (EntityNode n : jg.vertexSet()) {
         if (excludedSignature != null && excludedSignature.equals(n.getSignature())) {
            continue;
         }
         if (n.getN() != null) {
            result.networkLst.add(n);
            continue;
         }

         // 入口候选排除系统安装位置（/proc、/sys、库目录、系统二进制目录）
         // 与匿名管道哨兵——它们是环境，不是"来历不明的数据出现"。
         // 注意不按"是否有出边 execve"排除：/tmp 等外来空间下被执行的
         // 文件正是经典攻击入口信号，必须保留。
         String patternExcludeLib = "^(?!(?:/proc|/sys|/lib|/lib64|/usr/lib|/usr/lib64|/usr/bin|/bin|/sbin|/usr/sbin|/usr/libexec)/|pipe:\\[).*";
         if (usesIn && n.getF() != null
            && java.util.regex.Pattern.matches(patternExcludeLib, n.getF().getPath())
            && func.apply(jg.incomingEdgesOf(n).size(), Integer.parseInt(value.toString()))) {
            result.fileLst.add(n);
         }
         if (usesOut && n.getF() != null
            && java.util.regex.Pattern.matches(patternExcludeLib, n.getF().getPath())
            && func.apply(jg.outgoingEdgesOf(n).size(), Integer.parseInt(value.toString()))) {
            result.fileLst.add(n);
         }

         String isSystemLib = "^/(?:lib|lib64|usr/lib|usr/lib64)/.*";
         if (usesIn && n.getP() != null
            && jg.incomingEdgesOf(n).stream().allMatch(e -> e.getSource().getF() != null && java.util.regex.Pattern.matches(isSystemLib, e.getSource().getF().getPath()))
            && jg.incomingEdgesOf(n).size() != 0) {
            result.processLst.add(n);
         }
         if (usesOut && n.getP() != null
            && jg.outgoingEdgesOf(n).stream().allMatch(e -> e.getSource().getF() != null && java.util.regex.Pattern.matches(isSystemLib, e.getSource().getF().getPath()))
            && jg.incomingEdgesOf(n).size() != 0) {
            result.processLst.add(n);
         }
      }

      return result;
   }

   private static BiFunction<Integer, Integer, Boolean> compare(String operator) {
      switch (operator) {
         case "<":
            return (x1, x2) -> x1 < x2;
         case "=":
            return (x1, x2) -> x1.intValue() == x2.intValue();
         case ">":
            return (x1, x2) -> x1 > x2;
         case "<=":
            return (x1, x2) -> x1 <= x2;
         case ">=":
            return (x1, x2) -> x1 >= x2;
         default:
            return (x1, x2) -> false;
      }
   }

   private static Map<EntityNode, BigDecimal> findEarliestCausalEntryTimes(DirectedPseudograph<EntityNode, EventEdge> backJg) {
      Map<EntityNode, BigDecimal> entryTimes = new HashMap<>();
      EventEdge poiEvent = findPoiEvent(backJg);
      if (poiEvent == null || poiEvent.getSource() == null) {
         return entryTimes;
      }

      Set<EntityNode> nodesReachingPoi = new HashSet<>();
      Queue<EntityNode> queue = new ArrayDeque<>();
      nodesReachingPoi.add(poiEvent.getSource());
      queue.add(poiEvent.getSource());
      while (!queue.isEmpty()) {
         EntityNode current = queue.remove();
         for (EventEdge incoming : backJg.incomingEdgesOf(current)) {
            EntityNode predecessor = incoming.getSource();
            if (nodesReachingPoi.add(predecessor)) {
               queue.add(predecessor);
            }
         }
      }

      for (EntityNode candidate : backJg.vertexSet()) {
         BigDecimal earliest = null;
         for (EventEdge outgoing : backJg.outgoingEdgesOf(candidate)) {
            if ((outgoing.equals(poiEvent) || nodesReachingPoi.contains(outgoing.getSink())) && outgoing.getStartTime() != null) {
               if (earliest == null || outgoing.getStartTime().compareTo(earliest) < 0) {
                  earliest = outgoing.getStartTime();
               }
            }
         }
         if (earliest != null) {
            entryTimes.put(candidate, earliest);
         }
      }
      return entryTimes;
   }

   private static EventEdge findPoiEvent(DirectedPseudograph<EntityNode, EventEdge> backJg) {
      PoiEventInfo poiEventInfo = Main.poiEventInfo;
      if (backJg == null || poiEventInfo == null) {
         return null;
      }
      for (EventEdge edge : backJg.edgeSet()) {
         if (poiEventInfo.matches(edge)) {
            return edge;
         }
      }
      for (EventEdge edge : backJg.edgeSet()) {
         if (poiEventInfo.matchesRelaxed(edge)) {
            return edge;
         }
      }
      return null;
   }

   private static void sortEntryCandidates(List<EntityNode> candidates, Map<EntityNode, BigDecimal> entryTimes, String orderBy) {
      if (candidates == null || candidates.isEmpty()) {
         return;
      }

      for (EntityNode candidate : candidates) {
         // Pure reputation ranking aligned with DepImpact (sortedSignatureBasedOnRP)
         entryCompositeScores.put(candidate.getId(), candidate.getReputation());
      }
      Comparator<EntityNode> comparator = (left, right) -> {
         double leftRep = left.getReputation();
         double rightRep = right.getReputation();
         int comparison = Double.compare(rightRep, leftRep); // descending by reputation
         if (orderBy != null && orderBy.equalsIgnoreCase("asc")) {
            comparison = -comparison;
         }
         if (comparison != 0) {
            return comparison;
         }
         // Deterministic tie-breakers: earliest entry time, then node ID
         BigDecimal leftTime = entryTimes.get(left);
         BigDecimal rightTime = entryTimes.get(right);
         if (leftTime != null && rightTime != null) {
            int timeComp = leftTime.compareTo(rightTime);
            if (timeComp != 0) {
               return timeComp;
            }
         }
         return Long.compare(left.getId(), right.getId());
      };
      candidates.sort(comparator);
   }

   private static double getEntryCompositeScore(EntityNode entry) {
      if (entry == null) {
         return 0.0;
      }
      Double compositeScore = entryCompositeScores.get(entry.getId());
      return compositeScore == null ? entry.getReputation() : compositeScore;
   }

   private static double calculateEntryCompositeScore(
      EntityNode candidate, BigDecimal entryTime, double minimumReputation, double maximumReputation,
      BigDecimal earliestEntryTime, BigDecimal latestEntryTime
   ) {
      double reputationScore = normalize(candidate.getReputation(), minimumReputation, maximumReputation);
      if (entryTime == null || earliestEntryTime == null || latestEntryTime == null) {
         return reputationScore;
      }
      double timeScore = normalize(
         latestEntryTime.subtract(entryTime).doubleValue(),
         0.0,
         latestEntryTime.subtract(earliestEntryTime).doubleValue()
      );
      return entryImpactWeight * reputationScore + entryTimeWeight * timeScore;
   }

   private static double normalize(double value, double minimum, double maximum) {
      if (Double.compare(minimum, maximum) == 0) {
         return 1.0;
      }
      return (value - minimum) / (maximum - minimum);
   }

   private static List<EntityNode> selectEntryCandidatesByQuota(
      List<EntityNode> networkLst, List<EntityNode> fileLst, List<EntityNode> processLst, int limitNum
   ) {
      List<List<EntityNode>> candidateLists = new ArrayList<>();
      candidateLists.add(networkLst);
      candidateLists.add(fileLst);
      candidateLists.add(processLst);

      int limit = Math.max(0, limitNum);
      int quotaPerType = limit / candidateLists.size();
      int[] selectedCounts = new int[candidateLists.size()];
      int selectedTotal = 0;

      for (int i = 0; i < candidateLists.size(); i++) {
         selectedCounts[i] = Math.min(quotaPerType, candidateLists.get(i).size());
         selectedTotal += selectedCounts[i];
      }

      int remaining = limit - selectedTotal;
      for (int i = 0; i < candidateLists.size() && remaining > 0; i++) {
         int available = candidateLists.get(i).size() - selectedCounts[i];
         int additional = Math.min(available, remaining);
         selectedCounts[i] += additional;
         remaining -= additional;
      }

      List<EntityNode> result = new ArrayList<>();
      for (int i = 0; i < candidateLists.size(); i++) {
         result.addAll(candidateLists.get(i).subList(0, selectedCounts[i]));
      }
      return result;
   }

   // --- artifact helpers ---

   private static final class CanonicalKey {
      private static String of(EventEdge edge) {
         return util.CanonicalEdgeIdentity.key(edge);
      }
   }

   /** 边的规范键 + 内容事实（syscall 与起止时间秒），供产物内嵌与外部评分使用。 */
   private static JSONObject edgeFact(EventEdge edge) {
      JSONObject fact = new JSONObject().put("key", CanonicalKey.of(edge));
      fact.put("syscall", edge.getEvent() == null ? JSONObject.NULL : edge.getEvent());
      fact.put("starttime", edge.getStartTime() == null ? JSONObject.NULL : edge.getStartTime().doubleValue());
      fact.put("endtime", edge.getEndTime() == null ? JSONObject.NULL : edge.getEndTime().doubleValue());
      // 成败证据：result 为系统调用返回值原值（null = 该边不记录返回值）；effect 为归一化成败。
      Long result = edge.getResult();
      fact.put("result", result == null ? JSONObject.NULL : result);
      fact.put("effect", result == null ? JSONObject.NULL : (result < 0 ? "failure" : "success"));
      return fact;
   }

   private static JSONObject stageCounts(DirectedPseudograph<EntityNode, EventEdge> graph) {
      return new JSONObject().put("vertices", graph.vertexSet().size()).put("edges", graph.edgeSet().size());
   }

   private static JSONArray candidateArray(List<EntityNode> candidates, Map<EntityNode, BigDecimal> entryTimes) {
      JSONArray array = new JSONArray();
      for (EntityNode candidate : candidates) {
         BigDecimal entryTime = entryTimes.get(candidate);
         array.put(new JSONObject()
            .put("id", candidate.getId())
            .put("entity_type", entityType(candidate))
            .put("signature", candidate.getSignature())
            .put("reputation", round(candidate.getReputation(), 9))
            .put("composite_score", round(getEntryCompositeScore(candidate), 9))
            .put("earliest_entry_time", entryTime == null ? JSONObject.NULL : entryTime));
      }
      return array;
   }

   private static JSONObject vertexMix(DirectedPseudograph<EntityNode, EventEdge> graph) {
      int file = 0;
      int process = 0;
      int network = 0;
      for (EntityNode v : graph.vertexSet()) {
         if (v.getF() != null) {
            file++;
         } else if (v.getP() != null) {
            process++;
         } else if (v.getN() != null) {
            network++;
         }
      }
      return new JSONObject().put("file", file).put("process", process).put("network", network);
   }

   private static JSONObject eventDistribution(DirectedPseudograph<EntityNode, EventEdge> graph) {
      Map<String, Integer> counts = new HashMap<>();
      for (EventEdge e : graph.edgeSet()) {
         String event = e.getEvent() == null ? "null" : e.getEvent();
         counts.merge(event, 1, Integer::sum);
      }
      JSONObject distribution = new JSONObject();
      new TreeSet<>(counts.keySet()).forEach(key -> distribution.put(key, counts.get(key)));
      return distribution;
   }

   private static String entityType(EntityNode node) {
      if (node == null) {
         return "Unknown";
      }
      if (node.getF() != null) {
         return "File";
      }
      if (node.getP() != null) {
         return "Process";
      }
      if (node.getN() != null) {
         return "Network";
      }
      return "Unknown";
   }

   private static double round(double value, int scale) {
      if (Double.isNaN(value) || Double.isInfinite(value)) {
         return 0.0;
      }
      return BigDecimal.valueOf(value).setScale(scale, RoundingMode.HALF_UP).doubleValue();
   }
}
