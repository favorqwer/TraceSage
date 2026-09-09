package main;

import antlr.ProGQLLexer;
import antlr.ProGQLParser;
import gql.AntlrToClause;
import gql.BFS;
import gql.Expression;
import gql.Limit;
import gql.Match;
import gql.MyErrorListener;
import gql.Pattern;
import gql.ProGQL;
import gql.ProGQLQuery;
import gql.Projection;
import gql.PropertyExpression;
import gql.PropertyLookup;
import gql.SingleQuery;
import gql.SortItem;
import gql.TraversalExpression;
import gql.Variable;
import gql.WithQuery;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.ArrayDeque;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.function.BiFunction;
import gql.Atom;
import gql.Collect;
import gql.IdInColl;
import model.Edge;
import model.EntityAttributeProvider;
import model.EntityIdProvider;
import model.EntityNameProvider;
import model.EntityNode;
import model.EventEdge;
import model.EventEdgeProvider;
import model.FileEntity;
import model.NetworkEntity;
import model.POIEdge;
import model.PoiEventInfo;
import model.ProcessEntity;
import model.ProjectionFeature;
import gql.Min;
import org.antlr.v4.runtime.CharStream;
import org.antlr.v4.runtime.CharStreams;
import org.antlr.v4.runtime.CommonTokenStream;
import org.antlr.v4.runtime.tree.ParseTree;
import org.jgrapht.ext.DOTExporter;
import org.jgrapht.graph.DirectedPseudograph;
import org.neo4j.graphdb.Node;
import traversal.DBTraversal;
import traversal.DBTraversalFactory;
import traversal.neo4j.Neo4jTraversal;
import traversal.postgres.PostgresTraversal;
import util.CausalityPreserve;
import util.GraphOperations;
import util.InvestigationGraphStages;
import util.LlmEntryGraphAssembler;
import util.DotSvgConverter;
import util.ExpressionUtils;
import util.GQLBackwardPropagate;
import util.ProcessSubgraphBuildResult;
import util.ProcessSubgraphBuilder;
import util.ProcessSubgraphDotExporter;
import util.SubgraphConfig;
import util.llm.LlmConfig;
import util.llm.LlmEdgePrefilter;
import util.llm.LlmEvidencePathExtractor;
import util.llm.LlmEvidencePath;
import util.llm.LlmEvidencePathResult;
import util.llm.LlmEvidencePathSearchStatus;
import util.llm.LlmAttackStoryContext;
import util.llm.LlmEntrySelector;
import util.llm.LlmNoiseGraphEdge;
import util.llm.LlmSelectionCandidate;
import util.llm.LlmSelectionResult;
import util.llm.LlmNoiseGraphResult;
import util.llm.LlmRepairCandidateEdge;
import util.llm.LlmRepairNode;
import util.llm.LlmRepairResult;
import util.llm.LlmRepairSelectedEdge;
import util.llm.RepairInput;
import util.llm.LlmSemanticRepairAgent;
import util.llm.LlmCoreNoiseFilter;
import util.llm.SubgraphLlmEdgeFilter;
import util.llm.SubgraphLlmEdgeFilterResult;

public class Main {
   private static final String OUTPUT_ROOT = "output";
   private static final String QUERY_OUTPUT_DIR = "query";
   private static final String DOT_DIR = "dot";
   private static final String RUN_LOG_FILE = "pipeline.log";
   private static final String FINAL_STAGE = "g_final";
   private static final String FINAL_SVG_FILE = "g_final.svg";
   private static final String DEFAULT_FORWARD_EDGE_VARIABLE = "re";
   private static final String DEFAULT_LLM_FORWARD_WHERE_EXPR = "re.endtime>min(collect(uin IN in(u) | uin.starttime))";
   private static final DateTimeFormatter OUTPUT_TIMESTAMP_FORMATTER = DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss");
   private static String gqlFile = "";
   private static String output = "";
   public static POIEdge poiEdge;
   public static String[] highRP = new String[0];
   static String[] midRP = new String[0];
   static String[] lowRP = new String[0];
   public static String detection = "";
   static List<ProjectionFeature> projectionFeatureLst = new ArrayList<>();
   public static String timeDenominator = null;
   static Edge edgeInTraverse;
   private static String db;
   public static String depth = "";
   public static PoiEventInfo poiEventInfo;
   private static final Map<String, Integer> STAGE_EXPORT_ORDER = new LinkedHashMap<>();
   private static final Map<Long, Double> entryCompositeScores = new HashMap<>();
   private static double entryImpactWeight = 0.7;
   private static double entryTimeWeight = 0.3;
   private static int nextStageExportIndex = 1;

   public static void main(String[] args) throws Exception {
      Date startDate = new Date();
      DBTraversalFactory factory = new DBTraversalFactory();
      BackendSelection backendSelection = null;
      if (args.length == 0) {
         printUsage();
         return;
      }

      for (int index = 0; index < args.length; index++) {
         String option = args[index].trim();
          if (option.equalsIgnoreCase("-file")) {
            if (!hasNextArg(args, index)) {
               System.err.println("Missing value for -file");
               printUsage();
               return;
            }

            gqlFile = args[++index];
         } else if (option.equalsIgnoreCase("-db")) {
            if (!hasNextArg(args, index)) {
               System.err.println("Missing value for -db");
               printUsage();
               return;
            }

            try {
               backendSelection = resolveBackendSelection(args[++index]);
            } catch (IllegalArgumentException ex) {
               System.err.println(ex.getMessage());
               printUsage();
               return;
            }
         } else if (option.equalsIgnoreCase("-output")) {
            if (!hasNextArg(args, index)) {
               System.err.println("Missing value for -output");
               printUsage();
               return;
            }

            output = args[++index];
         } else if (option.equalsIgnoreCase("-depth")) {
            if (!hasNextArg(args, index)) {
               System.err.println("Missing value for -depth");
               printUsage();
               return;
            }

            depth = args[++index];
         }
      }

      if (gqlFile.isEmpty() || backendSelection == null) {
         System.err.println("Both -file and -db are required.");
         printUsage();
         return;
      }

      DBTraversal traversalInstance = factory.getInstance(backendSelection.getBackendId());
      if (traversalInstance == null) {
         System.err.println("Unable to initialize database backend: " + backendSelection.getBackendId());
         printUsage();
         return;
      }

      db = backendSelection.getBackendId();
      traversalInstance.initial(backendSelection.getInitArg());

      if (output.isEmpty()) {
         output = "result";
      }

      output = resolveOutputName(output);
      try (RunLogCapture ignored = RunLogCapture.start(getRunLogPath())) {
         runQuery(traversalInstance, startDate);
      }
   }

   private static void runQuery(DBTraversal traversalInstance, Date startDate) throws Exception {
      File gqlInput = new File(gqlFile);
      if (!gqlInput.isFile()) {
         System.err.println("Query file not found: " + gqlFile);
         return;
      }

      ProGQLParser parser = getParser(gqlFile);
      if (parser == null) {
         System.err.println("Failed to initialize parser for query file: " + gqlFile);
         return;
      }

      ParseTree antlrAST = parser.oC_ProGQL();
      if (!MyErrorListener.hasError) {
         AntlrToClause gqlVisitor = new AntlrToClause();
         ProGQL progql = (ProGQL)gqlVisitor.visit(antlrAST);
         if (gqlVisitor.semanticErrors.isEmpty()) {
            new DirectedPseudograph(EventEdge.class);
            Queue<Object> progqlqueue = progql.getProGQLQueue();
            ProGQLQuery progqlquery = (ProGQLQuery)progqlqueue.poll();
            DirectedPseudograph<EntityNode, EventEdge> progqlqueryjg = processSingleProGQLQuery(progqlquery, traversalInstance);
            DirectedPseudograph<EntityNode, EventEdge> err = progqlqueryjg;
            boolean unionFlag = false;
            Date stForUnionMultiGQL = new Date();

            while (!progqlqueue.isEmpty()) {
               Object next = progqlqueue.poll();
               if (next instanceof String) {
                  String operation = (String)next;
                  if ("union".equalsIgnoreCase(operation)) {
                     unionFlag = true;
                  } else {
                     if (!"intersect".equalsIgnoreCase(operation)) {
                        throw new IllegalArgumentException("Unknown operation: " + operation);
                     }

                     unionFlag = false;
                  }
               } else {
                  if (!(next instanceof ProGQLQuery)) {
                     throw new IllegalArgumentException("Invalid element in query queue.");
                  }

                  ProGQLQuery nextProGQLQuery = (ProGQLQuery)next;
                  Date st = new Date();
                  DirectedPseudograph<EntityNode, EventEdge> nextProGQLQueryjg = processSingleProGQLQuery(nextProGQLQuery, traversalInstance);
                  Date et = new Date();
                  long diff = et.getTime() - st.getTime();
                  long secs = TimeUnit.MILLISECONDS.toSeconds(diff);
                  if (unionFlag) {
                     err = createUnionJg(err, nextProGQLQueryjg);
                  } else {
                     err = createIntersectJg(err, nextProGQLQueryjg);
                  }
               }
            }

            Date etForUnionMultiGQL = new Date();
            long diff = etForUnionMultiGQL.getTime() - stForUnionMultiGQL.getTime();
            long seconds = TimeUnit.MILLISECONDS.toSeconds(diff);
            System.out.println("finaljg has: " + err.vertexSet().size() + " vertices and " + err.edgeSet().size() + " edges.");
            DOTExporter<EntityNode, EventEdge> exporter = new DOTExporter(
               new EntityIdProvider(), new EntityNameProvider(), new EventEdgeProvider(), new EntityAttributeProvider(), null
            );
             exportGraph(exporter, err, FINAL_STAGE);
         } else {
            for (String err : gqlVisitor.semanticErrors) {
               System.out.println(err);
            }
         }
      }

      Date endDate = new Date();
      long diff = endDate.getTime() - startDate.getTime();
      long minutes = TimeUnit.MILLISECONDS.toSeconds(diff);
      System.out.println("Executed in " + minutes + " seconds.");
   }

   private static ProGQLParser getParser(String gqlFile) {
      ProGQLParser parser = null;

      try {
         CharStream input = CharStreams.fromFileName(gqlFile);
         ProGQLLexer lexer = new ProGQLLexer(input);
         CommonTokenStream tokens = new CommonTokenStream(lexer);
         parser = new ProGQLParser(tokens);
         parser.removeErrorListeners();
         parser.addErrorListener(new MyErrorListener());
      } catch (IOException var5) {
         var5.printStackTrace();
      }

      return parser;
   }

   private static DirectedPseudograph<EntityNode, EventEdge> processSingleProGQLQuery(ProGQLQuery progqlquery, DBTraversal traversalInstance) {
      projectionFeatureLst.clear();
      new DirectedPseudograph(EventEdge.class);
      new DirectedPseudograph(EventEdge.class);
      DirectedPseudograph<EntityNode, EventEdge> returnJg = new DirectedPseudograph(EventEdge.class);
      SingleQuery singleQuery = progqlquery.getSinglequery();
      DirectedPseudograph<EntityNode, EventEdge> bRaw = GraphOperations.copy(processSingleQuery(singleQuery, traversalInstance));
      if (bRaw.vertexSet().isEmpty()) {
         System.out.println("No graph data matched the query.");
         return bRaw;
      }

      InvestigationGraphStages stages = new InvestigationGraphStages();
      stages.setBRaw(bRaw);
      DOTExporter<EntityNode, EventEdge> exporter = createDotExporter();
      exportGraph(exporter, stages.getBRaw(), "b_raw", false);
      DirectedPseudograph<EntityNode, EventEdge> bCpr = applyCpr(bRaw);
      returnJg = bCpr;

      if (singleQuery.getMatchLst() != null
         && singleQuery.getSetLst() != null
         && singleQuery.getMatchLst().size() >= 1
         && singleQuery.getMatchLst().size() == singleQuery.getSetLst().size()
         && singleQuery.getBfs() != null
         && singleQuery.getYield() != null
         && singleQuery.getUnwind() != null) {
         Projection projection = singleQuery.getSetLst().get(0).getProjection();

         for (Expression e : projection.getExpressionLst()) {
            ProjectionFeature feature = new ProjectionFeature(e.toString());
            if (e.toString().contains(".amount")) {
               feature.setFeatureType("amount");
            } else if (e.toString().contains("time")) {
               feature.setFeatureType("time");
               feature.setDenominator(timeDenominator);
            } else if (e.toString().contains("count")) {
               feature.setFeatureType("structure");
            }

            List<String> variableTermLst = new ArrayList<>();

            for (PropertyExpression pe : e.getPropertyExpressionLst()) {
               variableTermLst.add(pe.toString());
            }

            feature.setVariableTermLst(variableTermLst);
            projectionFeatureLst.add(feature);
         }
      }

      if (projectionFeatureLst.size() > 0) {
         DirectedPseudograph<EntityNode, EventEdge> backJg;
         if (singleQuery.getMatchLst().size() == 1 && singleQuery.getWithquery() != null) {
            backJg = backPropagateWithFilter(bCpr, singleQuery.getWithquery().getWhere().getExpression().getExprStr());
         } else {
            backJg = backPropagate(bCpr);
         }

         stages.setBScore(backJg);
         returnJg = stages.getBScore();
         exportGraph(exporter, stages.getBScore(), "b_score", false);
         if (progqlquery.getIntersectOrUnion() != null && progqlquery.getIntersectOrUnion().equalsIgnoreCase("intersect")) {
            new DirectedPseudograph(EventEdge.class);
            WithQuery withQuery = progqlquery.getWithquery();
            Match matchInWith = withQuery.getMatch();
            Expression countExpr = matchInWith.getWhere().getExpression();
            CandidateLstsBasedOnCount candidateLst = getEntryLstByCountExpr(stages.getBScore(), countExpr);
            String orderBy = ((SortItem)matchInWith.getWhere().getOrder().getSortitem()).getAscordesc().toLowerCase();
            Limit limitClause = matchInWith.getWhere().getLimit();
            int limitNum = Integer.parseInt(limitClause.getExpression().toString());
            List<EntityNode> topEntryLst = getTopEntryLst(candidateLst, orderBy, limitNum, stages.getBScore());
            List<LlmEvidencePathResult> evidencePaths = exportLlmEvidencePathsIfNeeded(stages.getBScore(), topEntryLst, withQuery);
            stages.setCandidateEntries(topEntryLst);
            stages.setEvidencePaths(evidencePaths);
            writeCandidateEntryArtifact(topEntryLst, evidencePaths);
            LlmEntrySelectionContext llmContext = applyLlmEntrySelectionIfNeeded(topEntryLst, evidencePaths, withQuery);
            topEntryLst = llmContext.getSelectedEntries();
            if (withQuery.getLlmClause() != null) {
               stages.setSelectedEntries(llmContext.getSelectedCandidates());
               writeSelectedEntryArtifact(llmContext.getSelectedCandidates(), llmContext.selectionResult);
               returnJg = processSevenStageLlmInvestigation(stages, withQuery, traversalInstance);
            } else {
               DirectedPseudograph<EntityNode, EventEdge> var28 = processWithClause(topEntryLst, withQuery, "union", traversalInstance);
               returnJg = createIntersectJg(stages.getBScore(), var28);
               System.out.println("jgIntersect has: " + returnJg.vertexSet().size() + " vertices and " + returnJg.edgeSet().size() + " edges.");
            }

         }

         if (progqlquery.getIntersectOrUnion() != null && progqlquery.getIntersectOrUnion().equalsIgnoreCase("union")) {
            new DirectedPseudograph(EventEdge.class);
            WithQuery withQuery = progqlquery.getWithquery();
            Match matchInWith = withQuery.getMatch();
            Expression countClause = matchInWith.getWhere().getExpression();
            CandidateLstsBasedOnCount candidateLst = getEntryLstByCountExpr(stages.getBScore(), countClause);
            String orderBy = ((SortItem)matchInWith.getWhere().getOrder().getSortitem()).getAscordesc().toLowerCase();
            Limit limitClause = matchInWith.getWhere().getLimit();
            int limitNum = Integer.parseInt(limitClause.getExpression().toString());
            List<EntityNode> topEntryLst = getTopEntryLst(candidateLst, orderBy, limitNum, stages.getBScore());
            List<LlmEvidencePathResult> evidencePaths = exportLlmEvidencePathsIfNeeded(stages.getBScore(), topEntryLst, withQuery);
            stages.setCandidateEntries(topEntryLst);
            stages.setEvidencePaths(evidencePaths);
            writeCandidateEntryArtifact(topEntryLst, evidencePaths);
            LlmEntrySelectionContext llmContext = applyLlmEntrySelectionIfNeeded(topEntryLst, evidencePaths, withQuery);
            topEntryLst = llmContext.getSelectedEntries();
            if (withQuery.getLlmClause() != null) {
               stages.setSelectedEntries(llmContext.getSelectedCandidates());
               writeSelectedEntryArtifact(llmContext.getSelectedCandidates(), llmContext.selectionResult);
               returnJg = processSevenStageLlmInvestigation(stages, withQuery, traversalInstance);
            } else {
               DirectedPseudograph<EntityNode, EventEdge> var29 = processWithClause(topEntryLst, withQuery, "union", traversalInstance);
               returnJg = createUnionJg(stages.getBScore(), var29);
               System.out.println("jgUnion has: " + returnJg.vertexSet().size() + " vertices and " + returnJg.edgeSet().size() + " edges.");
            }

         }
      }

      return returnJg;
   }

   public static DirectedPseudograph<EntityNode, EventEdge> processSingleQuery(SingleQuery sq, DBTraversal traversalInstance) {
      new DirectedPseudograph(EventEdge.class);
      Match match = null;
      if (sq.getMatch() != null && sq.getBfs() != null && sq.getSetLst() == null && sq.getYield() != null && sq.getUnwind() == null) {
         match = sq.getMatch();
      }

      if (sq.getMatchLst() != null
         && sq.getSetLst() != null
         && sq.getMatchLst().size() >= 1
         && sq.getMatchLst().size() == sq.getSetLst().size()
         && sq.getBfs() != null
         && sq.getYield() != null
         && sq.getUnwind() != null) {
         match = sq.getMatchLst().get(0);
      }

      Pattern pattern = match.getPattern();
      String poiEdgeName = pattern.getPatternPart().getPatternElementChain().getRelationshipPattern().getDetail().getVariable().toString();
      poiEdge = new POIEdge(poiEdgeName);
      BFS bfs = sq.getBfs();
      String direction = "";
      if (bfs.getBackward() != null) {
         direction = "backward";
      }

      if (bfs.getForward() != null) {
         direction = "forward";
      }

      edgeInTraverse = new Edge(bfs.getVariable().toString());
      Expression ExprInWhere = bfs.getMatch().getWhere().getExpression();
      return traversalInstance.traverse(pattern.toString(), null, edgeInTraverse, direction, ExprInWhere, false, match);
   }

   private static Set<String> getInitial() {
      Set<String> res = new HashSet<>();

      for (String s : highRP) {
         res.add(s);
      }

      return res;
   }

   private static DirectedPseudograph<EntityNode, EventEdge> backPropagate(DirectedPseudograph<EntityNode, EventEdge> jg) {
      GQLBackwardPropagate backPropagate = new GQLBackwardPropagate(jg);
      backPropagate.setMyEdge(edgeInTraverse);
      backPropagate.setPoiEdge(poiEdge);
      backPropagate.setSeedSources(getInitial());
      backPropagate.setProjectionFeatureLst(projectionFeatureLst);
      backPropagate.calculateWeights_ML_ClusterAll(true);
      backPropagate.initialReputation(highRP, midRP, lowRP);
      backPropagate.PageRankIteration(detection);
      return jg;
   }

   private static DirectedPseudograph<EntityNode, EventEdge> backPropagateWithFilter(DirectedPseudograph<EntityNode, EventEdge> jg, String expressionStr) {
      GQLBackwardPropagate backPropagate = new GQLBackwardPropagate(jg);
      backPropagate.setMyEdge(edgeInTraverse);
      backPropagate.setPoiEdge(poiEdge);
      backPropagate.setSeedSources(getInitial());
      backPropagate.setProjectionFeatureLst(projectionFeatureLst);
      backPropagate.calculateWeights_ML_ClusterAll(true);
      return filterJg(jg, expressionStr);
   }

   public static DirectedPseudograph<EntityNode, EventEdge> filterJg(DirectedPseudograph<EntityNode, EventEdge> jg, String expressionStr) {
      DirectedPseudograph<EntityNode, EventEdge> filteredJg = new DirectedPseudograph(EventEdge.class);
      model.Expression expression = ExpressionUtils.parseExpression(expressionStr);
      String left = expression.getLeft();
      String operator = expression.getOperator();
      String right = expression.getRight();

      for (EventEdge edge : jg.edgeSet()) {
         double weight = edge.weight;
         String weightStr = String.valueOf(weight);
         String replacedLeft = isNumeric(left) ? left : weightStr;
         String replacedRight = isNumeric(right) ? right : weightStr;
         if (compareReturnBoolean(replacedLeft, operator, replacedRight)) {
            EntityNode src = edge.getSource();
            EntityNode dst = edge.getSink();
            if (!filteredJg.containsVertex(src)) {
               filteredJg.addVertex(src);
            }

            if (!filteredJg.containsVertex(dst)) {
               filteredJg.addVertex(dst);
            }

            filteredJg.addEdge(src, dst, edge);
         }
      }

      System.out.println("Filtered graph: " + filteredJg.vertexSet().size() + " vertices and " + filteredJg.edgeSet().size() + " edges.");
      DOTExporter<EntityNode, EventEdge> exporter0 = new DOTExporter(
         new EntityIdProvider(), new EntityNameProvider(), new EventEdgeProvider(), new EntityAttributeProvider(), null
      );
      exportGraph(exporter0, filteredJg, "filter");

      return filteredJg;
   }

   static BackendSelection resolveBackendSelection(String dbArg) {
      if (dbArg == null || dbArg.trim().isEmpty()) {
         throw new IllegalArgumentException("Missing database target. Use postgres/<dbName>, neo4j path, or neo4jpostgres/<dbName>.");
      }

      String trimmed = dbArg.trim();
      String normalized = trimmed.toLowerCase(Locale.ROOT);

      if (normalized.startsWith("neo4jpostgres/")) {
         return new BackendSelection("neo4jpostgres", extractDbName(trimmed, "neo4jpostgres"));
      }

      if (normalized.contains("neo4j-community-3.5.11")) {
         return new BackendSelection("neo4j", trimmed);
      }

      if (normalized.startsWith("postgres/")) {
         return new BackendSelection("postgres", extractDbName(trimmed, "postgres"));
      }

      if (normalized.startsWith("mariadb/") || normalized.equals("mariadb")) {
         throw new IllegalArgumentException(buildUnsupportedBackendMessage("MariaDB", dbArg));
      }

      if (normalized.startsWith("nebula/") || normalized.equals("nebula")) {
         throw new IllegalArgumentException(buildUnsupportedBackendMessage("NebulaGraph", dbArg));
      }

      if (normalized.startsWith("myrocks/") || normalized.equals("myrocks")) {
         throw new IllegalArgumentException(buildUnsupportedBackendMessage("MyRocks", dbArg));
      }

      throw new IllegalArgumentException(
         "Unsupported database backend '" + dbArg + "'. Supported values: postgres/<dbName>, <neo4j path containing neo4j-community-3.5.11>, neo4jpostgres/<dbName>."
      );
   }

   private static String buildUnsupportedBackendMessage(String backendName, String dbArg) {
      return backendName
         + " support has been removed from this project. Unsupported value: '"
         + dbArg
         + "'. Supported values: postgres/<dbName>, <neo4j path containing neo4j-community-3.5.11>, neo4jpostgres/<dbName>.";
   }

   private static String extractDbName(String dbArg, String backendName) {
      int slashIndex = dbArg.indexOf(47);
      if (slashIndex < 0 || slashIndex == dbArg.length() - 1) {
         throw new IllegalArgumentException("Invalid " + backendName + " target '" + dbArg + "'. Expected format: " + backendName + "/<dbName>.");
      }

      return dbArg.substring(slashIndex + 1).trim();
   }

   private static boolean hasNextArg(String[] args, int index) {
      return index + 1 < args.length;
   }

   private static void printUsage() {
      System.err.println(
         "Usage: java -jar progql-local.jar -file <queryFile> -db <postgres/<dbName>|neo4j path|neo4jpostgres/<dbName>> [-output <name>] [-depth <n>]"
      );
   }

   static String resolveOutputName(String requestedOutput) throws IOException {
      Path requestedDir = Paths.get(OUTPUT_ROOT, QUERY_OUTPUT_DIR, requestedOutput);
      if (!Files.exists(requestedDir)) {
         return requestedOutput;
      }

      String timestampSuffix = LocalDateTime.now().format(OUTPUT_TIMESTAMP_FORMATTER);
      String candidate = requestedOutput + "_" + timestampSuffix;
      Path candidateDir = Paths.get(OUTPUT_ROOT, QUERY_OUTPUT_DIR, candidate);
      int duplicateIndex = 1;

      while (Files.exists(candidateDir)) {
         candidate = requestedOutput + "_" + timestampSuffix + "_" + duplicateIndex++;
         candidateDir = Paths.get(OUTPUT_ROOT, QUERY_OUTPUT_DIR, candidate);
      }

      System.out.println("Output directory '" + requestedDir + "' already exists. Writing results to '" + candidateDir + "'.");
      return candidate;
   }

   private static File buildOutputFile(String stage) throws IOException {
      Path dir = getQueryOutputDir().resolve(DOT_DIR);
      Files.createDirectories(dir);
      return dir.resolve(stage + ".dot").toFile();
   }

   private static Path buildSvgOutputPath(String stage) throws IOException {
      Path dir = getQueryOutputDir().resolve(DOT_DIR);
      Files.createDirectories(dir);
      return dir.resolve(stage + ".svg");
   }

   private static Path getQueryOutputDir() {
      return Paths.get(OUTPUT_ROOT, QUERY_OUTPUT_DIR, output);
   }

   private static Path getRunLogPath() {
      return getQueryOutputDir().resolve(RUN_LOG_FILE);
   }

   private static synchronized String buildOrderedStageFileName(String stage, String extension) {
      Integer stageIndex = STAGE_EXPORT_ORDER.get(stage);
      if (stageIndex == null) {
         stageIndex = nextStageExportIndex++;
         STAGE_EXPORT_ORDER.put(stage, stageIndex);
      }

      return stageIndex + "." + stage + extension;
   }

   private static void exportGraph(DOTExporter<EntityNode, EventEdge> exporter, DirectedPseudograph<EntityNode, EventEdge> graph, String stage) {
      exportGraph(exporter, graph, stage, FINAL_STAGE.equals(stage));
   }

   private static void exportGraph(
      DOTExporter<EntityNode, EventEdge> exporter, DirectedPseudograph<EntityNode, EventEdge> graph, String stage, boolean generateSvg
   ) {
      File dotFile;
      try {
         dotFile = buildOutputFile(stage);
      } catch (IOException e) {
         e.printStackTrace();
         return;
      }

      try (FileWriter writer = new FileWriter(dotFile)) {
         exporter.exportGraph(graph, writer);
      } catch (IOException e) {
         e.printStackTrace();
         return;
      }

      if (generateSvg) {
         try {
            Path svgPath = FINAL_STAGE.equals(stage) ? getQueryOutputDir().resolve(FINAL_SVG_FILE) : buildSvgOutputPath(stage);
            DotSvgConverter.convert(dotFile.toPath(), svgPath);
         } catch (IOException e) {
            System.err.println("Failed to generate SVG for stage '" + stage + "': " + e.getMessage());
            e.printStackTrace();
         }
      }
   }

   private static boolean isNumeric(String str) {
      if (str == null) {
         return false;
      } else {
         try {
            Double.parseDouble(str);
            return true;
         } catch (NumberFormatException var2) {
            return false;
         }
      }
   }

   private static Boolean compareReturnBoolean(String leftVal, String operator, String rightVal) {
      switch (operator.hashCode()) {
         case 60:
            if (operator.equals("<")) {
               return ExpressionUtils.compare(leftVal, rightVal, (a1, a2) -> a1 < a2);
            }
            break;
         case 61:
            if (operator.equals("=")) {
               return ExpressionUtils.compare(leftVal, rightVal, (a1, a2) -> a1 == a2);
            }
            break;
         case 62:
            if (operator.equals(">")) {
               return ExpressionUtils.compare(leftVal, rightVal, (a1, a2) -> a1 > a2);
            }
            break;
         case 1921:
            if (operator.equals("<=")) {
               return ExpressionUtils.compare(leftVal, rightVal, (a1, a2) -> a1 <= a2);
            }
            break;
         case 1983:
            if (operator.equals(">=")) {
               return ExpressionUtils.compare(leftVal, rightVal, (a1, a2) -> a1 >= a2);
            }
      }

      return false;
   }

   private static BiFunction<Integer, Integer, Boolean> compare(String operator) {
      BiFunction<Integer, Integer, Boolean> func = null;
      switch (operator.hashCode()) {
         case 60:
            if (operator.equals("<")) {
               func = (x1, x2) -> x1 < x2;
            }
            break;
         case 61:
            if (operator.equals("=")) {
               func = (x1, x2) -> x1 == x2;
            }
            break;
         case 62:
            if (operator.equals(">")) {
               func = (x1, x2) -> x1 > x2;
            }
            break;
         case 1921:
            if (operator.equals("<=")) {
               func = (x1, x2) -> x1 <= x2;
            }
            break;
         case 1983:
            if (operator.equals(">=")) {
               func = (x1, x2) -> x1 >= x2;
            }
      }

      return func;
   }

   private static CandidateLstsBasedOnCount getEntryLstByCountExpr(DirectedPseudograph<EntityNode, EventEdge> jg, Expression countExpr) {
      Set<EntityNode> vertexSet = jg.vertexSet();
      List<EntityNode> fileLst = new ArrayList<>();
      List<EntityNode> processLst = new ArrayList<>();
      List<EntityNode> networkLst = new ArrayList<>();
      String excludedSignature = detection;
      StringBuilder operator = new StringBuilder();
      StringBuilder value = new StringBuilder();
      ExpressionUtils.extractOperatorAndValue(countExpr.toString(), operator, value);
      BiFunction<Integer, Integer, Boolean> func = compare(operator.toString());
      if (countExpr.toString().contains("in(")) {
         for (EntityNode n : vertexSet) {
            if (excludedSignature != null && excludedSignature.equals(n.getSignature())) {
               continue;
            }

            if (n.getN() != null) {
               networkLst.add(n);
            } else {
               // 入口候选排除系统安装位置（/proc、/sys、库目录、系统二进制
               // 目录）与匿名管道哨兵——它们是环境，不是"来历不明的数据
               // 出现"。不按"是否有出边 execve"排除：/tmp 等外来空间下被
               // 执行的文件正是经典攻击入口信号，必须保留（与 BaselineRunner 一致）。
               String patternExcludeLib = "^(?!(?:/proc|/sys|/lib|/lib64|/usr/lib|/usr/lib64|/usr/bin|/bin|/sbin|/usr/sbin|/usr/libexec)/|pipe:\\[).*";
               if (n.getF() != null
                  && java.util.regex.Pattern.matches(patternExcludeLib, n.getF().getPath())
                  && func.apply(jg.incomingEdgesOf(n).size(), Integer.parseInt(value.toString()))) {
                  fileLst.add(n);
               }

               String isSystemLib = "^/(?:lib|lib64|usr/lib|usr/lib64)/.*";
               if (n.getP() != null
                  && jg.incomingEdgesOf(n)
                     .stream()
                     .allMatch(e -> e.getSource().getF() != null && java.util.regex.Pattern.matches(isSystemLib, e.getSource().getF().getPath()))
                  && jg.incomingEdgesOf(n).size() != 0) {
                  processLst.add(n);
               }
            }
         }
      } else if (countExpr.toString().contains("out(")) {
         for (EntityNode nx : vertexSet) {
            if (excludedSignature != null && excludedSignature.equals(nx.getSignature())) {
               continue;
            }

            if (nx.getN() != null) {
               networkLst.add(nx);
            } else {
               String pattern = "^(?!(?:/proc|/sys|/lib|/lib64|/usr/lib|/usr/lib64)/).*";
               if (nx.getF() != null
                  && java.util.regex.Pattern.matches(pattern, nx.getF().getPath())
                  && func.apply(jg.outgoingEdgesOf(nx).size(), Integer.parseInt(value.toString()))) {
                  fileLst.add(nx);
               }

               String patternIncludeLib = "^/(?:lib|lib64|usr/lib|usr/lib64)/.*";
               if (nx.getP() != null
                  && jg.outgoingEdgesOf(nx)
                     .stream()
                     .allMatch(e -> e.getSource().getF() != null && java.util.regex.Pattern.matches(patternIncludeLib, e.getSource().getF().getPath()))
                  && jg.incomingEdgesOf(nx).size() != 0) {
                  processLst.add(nx);
               }
            }
         }
      }

      return new CandidateLstsBasedOnCount(fileLst, networkLst, processLst);
   }

   static List<EntityNode> getTopEntryLst(CandidateLstsBasedOnCount candidateLst, String orderBy, int limitNum) {
      return getTopEntryLst(candidateLst, orderBy, limitNum, null);
   }

   static List<EntityNode> getTopEntryLst(
      CandidateLstsBasedOnCount candidateLst, String orderBy, int limitNum, DirectedPseudograph<EntityNode, EventEdge> backJg
   ) {
      List<EntityNode> topEntryLst = new ArrayList<>();
      List<EntityNode> result = getAllEntryLst(candidateLst, orderBy, limitNum, backJg);
      int i = 0;

      for (EntityNode n : result) {
         if (i < limitNum) {
            topEntryLst.add(n);
            String nodeType = "";
            if (n.getF() != null) {
               nodeType = "File";
            }

            if (n.getN() != null) {
               nodeType = "Network";
            }

            if (n.getP() != null) {
               nodeType = "Process";
            }

            System.out
               .println(
                  " @@@@@ Top "
                     + (i + 1)
                     + ": id: "
                     + n.getId()
                     + "("
                     + nodeType
                     + ")"
                     + " signature: "
                     + n.getSignature()
                     + " composite_score: "
                     + getEntryCompositeScore(n)
               );
            i++;
         }
      }

      return topEntryLst;
   }

   private static List<EntityNode> getAllEntryLst(
      CandidateLstsBasedOnCount candidateLst, String orderBy, int limitNum, DirectedPseudograph<EntityNode, EventEdge> backJg
   ) {
      Map<EntityNode, BigDecimal> entryTimes = findEarliestCausalEntryTimes(backJg);
      double[] rankingWeights = LlmConfig.loadEntryRankingWeightsOrDefault();
      entryImpactWeight = rankingWeights[0];
      entryTimeWeight = rankingWeights[1];
      entryCompositeScores.clear();
      sortEntryCandidates(candidateLst.fileLst, entryTimes, orderBy);
      sortEntryCandidates(candidateLst.networkLst, entryTimes, orderBy);
      sortEntryCandidates(candidateLst.processLst, entryTimes, orderBy);
      return selectEntryCandidatesByQuota(candidateLst.networkLst, candidateLst.fileLst, candidateLst.processLst, limitNum);
   }

   /**
    * Ranks candidates within one entity type by a normalized blend of reputation
    * and the earliest first-hop event on a path that reaches the current POI.
    */
   static void sortEntryCandidates(List<EntityNode> candidates, Map<EntityNode, BigDecimal> entryTimes, String orderBy) {
      if (candidates == null || candidates.isEmpty()) {
         return;
      }

      double minimumReputation = Double.POSITIVE_INFINITY;
      double maximumReputation = Double.NEGATIVE_INFINITY;
      BigDecimal earliestEntryTime = null;
      BigDecimal latestEntryTime = null;
      for (EntityNode candidate : candidates) {
         minimumReputation = Math.min(minimumReputation, candidate.getReputation());
         maximumReputation = Math.max(maximumReputation, candidate.getReputation());
         BigDecimal entryTime = entryTimes.get(candidate);
         if (entryTime != null) {
            earliestEntryTime = earliestEntryTime == null || entryTime.compareTo(earliestEntryTime) < 0 ? entryTime : earliestEntryTime;
            latestEntryTime = latestEntryTime == null || entryTime.compareTo(latestEntryTime) > 0 ? entryTime : latestEntryTime;
         }
      }

      final double minReputation = minimumReputation;
      final double maxReputation = maximumReputation;
      final BigDecimal earliest = earliestEntryTime;
      final BigDecimal latest = latestEntryTime;
      for (EntityNode candidate : candidates) {
         entryCompositeScores.put(
            candidate.getId(),
            calculateEntryCompositeScore(candidate, entryTimes.get(candidate), minReputation, maxReputation, earliest, latest)
         );
      }
      Comparator<EntityNode> comparator = (left, right) -> {
         double leftScore = getEntryCompositeScore(left);
         double rightScore = getEntryCompositeScore(right);
         int comparison = Double.compare(rightScore, leftScore);
         if (orderBy != null && orderBy.equalsIgnoreCase("asc")) {
            comparison = -comparison;
         }
         if (comparison != 0) {
            return comparison;
         }
         return Long.compare(left.getId(), right.getId());
      };
      Collections.sort(candidates, comparator);
   }

   public static double getEntryCompositeScore(EntityNode entry) {
      if (entry == null) {
         return 0.0;
      }
      Double compositeScore = entryCompositeScores.get(entry.getId());
      return compositeScore == null ? entry.getReputation() : compositeScore;
   }

   private static double calculateEntryCompositeScore(
      EntityNode candidate,
      BigDecimal entryTime,
      double minimumReputation,
      double maximumReputation,
      BigDecimal earliestEntryTime,
      BigDecimal latestEntryTime
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

   static Map<EntityNode, BigDecimal> findEarliestCausalEntryTimes(DirectedPseudograph<EntityNode, EventEdge> backJg) {
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

   /**
    * Selects candidates with an even per-type quota. Remainders and any quota
    * left unused by a sparse type are assigned in network, file, process order.
    */
   static List<EntityNode> selectEntryCandidatesByQuota(
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

   private static Comparator<EntityNode> buildEntryRankComparator(String orderBy) {
      if (orderBy != null && orderBy.toLowerCase().equals("desc")) {
         return (n1, n2) -> Double.valueOf(n2.getReputation()).compareTo(n1.getReputation());
      } else {
         return (n1, n2) -> Double.valueOf(n1.getReputation()).compareTo(n2.getReputation());
      }
   }

   private static LlmEntrySelectionContext applyLlmEntrySelectionIfNeeded(List<EntityNode> topEntryLst, List<LlmEvidencePathResult> evidencePaths, WithQuery withQuery) {
      if (withQuery == null || withQuery.getLlmClause() == null) {
         System.out.println("LLM entry selection not requested; using ranked entries as-is.");
         return new LlmEntrySelectionContext(null, topEntryLst, evidencePaths);
      }

      try {
         LlmEntrySelector selector = new LlmEntrySelector();
         LlmSelectionResult selectionResult = selector.selectEntries(topEntryLst, evidencePaths, withQuery);
          return new LlmEntrySelectionContext(selectionResult, topEntryLst, evidencePaths);
      } catch (Exception ex) {
         String failure = describeFailure(ex);
         List<LlmSelectionCandidate> fallbackCandidates = buildDeterministicLlmFallbackCandidates(topEntryLst, withQuery);
         String message = "LLM entry selection failed; using ranked candidates up to LLM TOP N. " + failure;
         writeTextArtifact("llm_select_entry_degraded", message);
         System.out.println(message);
         return new LlmEntrySelectionContext(null, topEntryLst, evidencePaths, fallbackCandidates);
      }
   }

   private static List<LlmSelectionCandidate> buildDeterministicLlmFallbackCandidates(
      List<EntityNode> topEntryLst, WithQuery withQuery
   ) {
      if (topEntryLst == null || topEntryLst.isEmpty() || withQuery == null || withQuery.getLlmClause() == null) {
         return Collections.emptyList();
      }

      int selectionCount = Math.min(withQuery.getLlmClause().getTopK(), topEntryLst.size());
      List<LlmSelectionCandidate> candidates = new ArrayList<>();
      for (int i = 0; i < selectionCount; i++) {
         candidates.add(
            new LlmSelectionCandidate(
               i + 1,
               i + 1,
               topEntryLst.get(i),
               "Deterministic fallback because LLM entry selection failed."
            )
         );
      }
      return candidates;
   }

   private static List<LlmEvidencePathResult> exportLlmEvidencePathsIfNeeded(
      DirectedPseudograph<EntityNode, EventEdge> backJg, List<EntityNode> topEntryLst, WithQuery withQuery
   ) {
      if (withQuery == null || withQuery.getLlmClause() == null) {
         return Collections.emptyList();
      }

      LlmConfig config = null;
      String configFailure = null;
      try {
         config = LlmConfig.load();
      } catch (Exception ex) {
         configFailure = "LLM configuration is unavailable: " + describeFailure(ex);
         System.out.println(configFailure);
      }
      LlmEvidencePathExtractor extractor = new LlmEvidencePathExtractor();
      List<LlmEvidencePathResult> results = new ArrayList<>();

      for (int i = 0; i < topEntryLst.size(); i++) {
         EntityNode entry = topEntryLst.get(i);
         LlmEvidencePathResult result;
         if (poiEventInfo == null) {
            result = createUnavailableEvidencePathResult(entry, "POI event information is unavailable.");
         } else if (configFailure != null) {
            result = createUnavailableEvidencePathResult(entry, configFailure);
         } else {
            try {
               result = extractor.extractPaths(
                  backJg,
                  entry,
                  poiEventInfo,
                  config.getEntrySelectionMaxEvidencePathsPerCandidate(),
                  config.getEntrySelectionMaxEvidenceSearchStatesPerPath()
               );
            } catch (Exception ex) {
               String failure = "Evidence path extraction failed: " + describeFailure(ex);
               System.out.println("LLM evidence extraction unavailable for candidate " + (i + 1) + ": " + failure);
               result = createUnavailableEvidencePathResult(entry, failure);
            }
         }
         results.add(result);
      }

      return results;
   }

   private static LlmEvidencePathResult createUnavailableEvidencePathResult(EntityNode entry, String message) {
      return new LlmEvidencePathResult(
         entry,
         null,
         false,
         message,
         Collections.<LlmEvidencePath>emptyList(),
         LlmEvidencePathSearchStatus.UNAVAILABLE,
         0,
         0
      );
   }

   private static void writeLlmSelectionArtifacts(
      LlmSelectionResult selectionResult, List<LlmEvidencePathResult> evidencePaths
   ) {
      try {
         Path queryOutputDir = getQueryOutputDir();
         Files.createDirectories(queryOutputDir);
         Files.write(
            queryOutputDir.resolve("llm_select_entry_question.json"),
            selectionResult.getQuestionRecordJson().toString(2).getBytes(StandardCharsets.UTF_8)
         );
         Files.write(
            queryOutputDir.resolve("llm_select_entry_answer.json"),
            selectionResult.toJsonObject().toString(2).getBytes(StandardCharsets.UTF_8)
         );
         org.json.JSONArray evidenceJson = new org.json.JSONArray();
         for (LlmEvidencePathResult evidencePath : evidencePaths) {
            evidenceJson.put(evidencePath.toJsonObject());
         }
         Files.write(
            queryOutputDir.resolve("llm_select_entry_evidence.json"),
            evidenceJson.toString(2).getBytes(StandardCharsets.UTF_8)
         );
      } catch (Exception ex) {
         System.err.println("Failed to write LLM selection artifacts; continuing without them. " + describeFailure(ex));
      }
   }

   private static void writeCandidateEntryArtifact(List<EntityNode> candidates, List<LlmEvidencePathResult> evidencePaths) {
      org.json.JSONArray entries = new org.json.JSONArray();
      Map<Long, LlmEvidencePathResult> evidenceByEntryId = new HashMap<>();
      if (evidencePaths != null) {
         for (LlmEvidencePathResult evidencePath : evidencePaths) {
            if (evidencePath != null && evidencePath.getEntry() != null) {
               evidenceByEntryId.put(evidencePath.getEntry().getId(), evidencePath);
            }
         }
      }
      if (candidates != null) {
         for (int index = 0; index < candidates.size(); index++) {
            EntityNode entry = candidates.get(index);
            if (entry == null) {
               continue;
            }
            org.json.JSONObject json = new org.json.JSONObject()
               .put("candidate_rank", index + 1)
               .put("entry_id", entry.getId())
               .put("entity_type", entityType(entry))
               .put("signature", entry.getSignature())
               .put("composite_score", getEntryCompositeScore(entry))
               .put("reputation", entry.getReputation());
            LlmEvidencePathResult evidencePath = evidenceByEntryId.get(entry.getId());
            if (evidencePath != null) {
               json.put("evidence", evidencePath.toJsonObject());
            }
            entries.put(json);
         }
      }
      writeJsonArtifact("candidate_entry", new org.json.JSONObject().put("entries", entries));
   }

   private static void writeSelectedEntryArtifact(List<LlmSelectionCandidate> selected, LlmSelectionResult selectionResult) {
      org.json.JSONArray entries = new org.json.JSONArray();
      if (selected != null) {
         for (LlmSelectionCandidate candidate : selected) {
            if (candidate == null || candidate.getEntry() == null) {
               continue;
            }
            entries.put(candidate.toJsonObject().put("entity_type", entityType(candidate.getEntry())));
         }
      }
      org.json.JSONObject payload = new org.json.JSONObject().put("entries", entries);
      if (selectionResult != null) {
         payload.put("summary", selectionResult.getSummary())
            .put("selected_candidate_ranks", selectionResult.getSelectedCandidateRanks());
      } else {
         payload.put("summary", "Deterministic fallback after LLM entry selection failure.");
      }
      writeJsonArtifact("selected_entry", payload);
   }

   private static String entityType(EntityNode node) {
      if (node == null) return "Unknown";
      if (node.getF() != null) return "File";
      if (node.getP() != null) return "Process";
      if (node.getN() != null) return "Network";
      return "Unknown";
   }

   private static void writeStageSummary(
      InvestigationGraphStages stages,
      LlmEdgePrefilter.GraphPrefilterResult filterResult,
      LlmCoreNoiseFilter.LlmCoreNoiseFilterResult noiseResult,
      String degradedReason
   ) {
      org.json.JSONObject payload = new org.json.JSONObject()
         .put("b_raw", stageCounts(stages.getBRaw()))
         .put("b_score", stageCounts(stages.getBScore()))
         .put("f_selected_raw", stageCounts(stages.getFSelectedRaw()))
         .put("g_filter", stageCounts(stages.getGFilter()))
         .put("g_retained", stageCounts(stages.getGRetained()))
         .put("g_repair_pool", stageCounts(stages.getGRepairPool()))
         .put("g_final", stageCounts(stages.getGFinal()))
         .put("candidate_entry_count", stages.getCandidateEntries().size())
         .put("selected_entry_count", stages.getSelectedEntries().size())
         .put("repair_added_edge_count", Math.max(0, stages.getGFinal().edgeSet().size() - stages.getGRetained().edgeSet().size()))
         .put("degraded_reason", degradedReason == null ? "" : degradedReason);
      if (filterResult != null) {
         payload.put("g_filter_structural_drop_count", filterResult.getStructuralDroppedEdges().size())
            .put("g_filter_structural_normalization_drop_count", filterResult.getStructuralNormalizationDroppedEdges().size())
            .put("g_filter_duplicate_drop_count", filterResult.getDuplicateDropCount())
            .put("g_filter_semantic_normalization_drop_count", filterResult.getSemanticNormalizationDropCount())
            .put("g_filter_semantic_mirror_drop_count", filterResult.getSemanticMirrorDropCount())
            .put("g_filter_rule_drop_count", filterResult.getRuleDroppedEdges().size());
      }
      if (noiseResult != null) {
         payload.put("g_retained_llm_dropped_edge_count", noiseResult.getCoreResult().getDroppedEdgeCount())
            .put("g_retained_llm_fallback_used", noiseResult.getCoreResult().isFallbackUsed());
      }
      writeJsonArtifact("stage_summary", payload);
   }

   private static org.json.JSONObject stageCounts(DirectedPseudograph<EntityNode, EventEdge> graph) {
      return new org.json.JSONObject().put("node_count", graphNodeCount(graph)).put("edge_count", graphEdgeCount(graph));
   }

   private static void writeRepairArtifacts(LlmRepairResult repairResult) {
      if (repairResult == null) {
         return;
      }
      org.json.JSONArray rounds = new org.json.JSONArray();
      for (LlmRepairResult.LlmRepairRoundResult round : repairResult.getRounds()) {
         rounds.put(
            new org.json.JSONObject()
               .put("round", round.getRound())
               .put("added_edge_count", round.getAddedEdges().size())
               .put("candidate_count", round.getCandidates().size())
               .put("selected_edge_count", round.getSelectedEdges().size())
         );
      }
      writeJsonArtifact(
         "g_final_repair_summary",
         new org.json.JSONObject()
            .put("added_edge_count", repairResult.getAddedEdgeCount())
            .put("stop_reason", repairResult.getStopReason())
            .put("rounds", rounds)
      );
   }


   private static DirectedPseudograph<EntityNode, EventEdge> applyCpr(DirectedPseudograph<EntityNode, EventEdge> graph) {
      if (graph == null || graph.edgeSet().isEmpty()) {
         return GraphOperations.copy(graph);
      }

      CausalityPreserve cpr = new CausalityPreserve(GraphOperations.copy(graph));
      cpr.mergeEdgeFallInTheRange2(10.0);
      return cpr.afterMerge;
   }

   public static DirectedPseudograph<EntityNode, EventEdge> createUnionJg(
      DirectedPseudograph<EntityNode, EventEdge> jg1, DirectedPseudograph<EntityNode, EventEdge> jg2
   ) {
      return GraphOperations.union(jg1, jg2);
   }

   public static DirectedPseudograph<EntityNode, EventEdge> createIntersectJg(
      DirectedPseudograph<EntityNode, EventEdge> jg1, DirectedPseudograph<EntityNode, EventEdge> jg2
   ) {
      return GraphOperations.intersection(jg1, jg2);
   }

   public static DirectedPseudograph<EntityNode, EventEdge> processWithClause(
      List<EntityNode> entryLst, WithQuery wq, String method, DBTraversal traversalInstance
   ) {
      DirectedPseudograph<EntityNode, EventEdge> jg = new DirectedPseudograph(EventEdge.class);
      int traversedEntries = 0;
      int nonEmptyEntries = 0;
      int totalInternalVertices = 0;
      int totalInternalEdges = 0;
      BFS bfs = wq.getBfs();
      Edge edge = new Edge(bfs.getVariable().toString());
      String direction = "";
      if (bfs.getBackward() != null) {
         direction = "backward";
      }

      if (bfs.getForward() != null) {
         direction = "forward";
      }

      Expression ExprInWhere = bfs.getMatch().getWhere().getExpression();

      for (EntityNode entry : entryLst) {
         new DirectedPseudograph(EventEdge.class);
         String pattern = "(n{id:" + entry.getId() + "})-[]->()";
         DirectedPseudograph<EntityNode, EventEdge> internalJg =
            applyCpr(traversalInstance.traverse(pattern, entry, edge, direction, ExprInWhere, true, null));
         traversedEntries++;
         totalInternalVertices += internalJg.vertexSet().size();
         totalInternalEdges += internalJg.edgeSet().size();
         if (!internalJg.vertexSet().isEmpty() || !internalJg.edgeSet().isEmpty()) {
            nonEmptyEntries++;
         }
         if (jg.vertexSet().size() == 0) {
            jg = internalJg;
         } else {
            if (method.equals("union")) {
               jg = createUnionJg(jg, internalJg);
            }

            if (method.equals("intersect")) {
               jg = createUnionJg(jg, internalJg);
            }
         }
      }

      System.out.println(
         "Forward expansion summary: "
            + traversedEntries
            + " entries, "
            + nonEmptyEntries
            + " non-empty, merged graph has "
            + jg.vertexSet().size()
            + " vertices and "
            + jg.edgeSet().size()
            + " edges (sum of per-entry graphs: "
            + totalInternalVertices
            + " vertices, "
            + totalInternalEdges
            + " edges)."
      );
      return jg;
   }

   private static DirectedPseudograph<EntityNode, EventEdge> processSingleEntryWithClause(
      EntityNode entry, WithQuery wq, DBTraversal traversalInstance
   ) {
      BFS bfs = wq.getBfs();
      Edge edge = new Edge(bfs.getVariable().toString());
      String direction = "";
      if (bfs.getBackward() != null) {
         direction = "backward";
      }

      if (bfs.getForward() != null) {
         direction = "forward";
      }

      Expression exprInWhere = bfs.getMatch().getWhere().getExpression();
      String pattern = "(n{id:" + entry.getId() + "})-[]->()";
      return applyCpr(traversalInstance.traverse(pattern, entry, edge, direction, exprInWhere, true, null));
   }

   private static Expression createDefaultLlmForwardExpression() {
      Expression exprInWhere = new Expression(DEFAULT_LLM_FORWARD_WHERE_EXPR);
      Variable uinVar = new Variable("uin");
      Variable inUVar = new Variable("u");
      IdInColl idInColl = new IdInColl(uinVar, new Expression("in(" + inUVar + ")"));
      PropertyExpression propertyExpression = new PropertyExpression(new Atom(uinVar), new PropertyLookup("starttime"));
      exprInWhere.setTraversalExpression(new TraversalExpression(new Min(new Collect(idInColl, propertyExpression))));
      return exprInWhere;
   }

   private static DirectedPseudograph<EntityNode, EventEdge> processSingleEntryLlmForward(
      EntityNode entry, WithQuery withQuery, DBTraversal traversalInstance
   ) {
      BFS bfs = withQuery == null ? null : withQuery.getBfs();
      Edge edge;
      Expression exprInWhere;
      String direction = "forward";
      if (bfs != null) {
         edge = new Edge(bfs.getVariable().toString());
         exprInWhere = bfs.getMatch().getWhere().getExpression();
         if (bfs.getBackward() != null) {
            direction = "backward";
         } else if (bfs.getForward() != null) {
            direction = "forward";
         }
      } else {
         edge = new Edge(DEFAULT_FORWARD_EDGE_VARIABLE);
         exprInWhere = createDefaultLlmForwardExpression();
      }

      String pattern = "(n{id:" + entry.getId() + "})-[]->()";
      return GraphOperations.copy(traversalInstance.traverse(pattern, entry, edge, direction, exprInWhere, true, null));
   }

   private static DirectedPseudograph<EntityNode, EventEdge> processSevenStageLlmInvestigation(
      InvestigationGraphStages stages, WithQuery withQuery, DBTraversal traversalInstance
   ) {
      DOTExporter<EntityNode, EventEdge> exporter = createDotExporter();
      List<LlmSelectionCandidate> selectedCandidates = stages.getSelectedEntries();
      List<LlmSelectionCandidate> successfulCandidates = new ArrayList<>();
      DirectedPseudograph<EntityNode, EventEdge> forwardUnion = new DirectedPseudograph(EventEdge.class);
      String degradedReason = "";

      LlmConfig llmConfig = null;
      try {
         llmConfig = LlmConfig.load();
      } catch (Exception ex) {
         degradedReason = "LLM configuration is unavailable: " + describeFailure(ex);
         System.out.println(degradedReason);
      }
      boolean prefilterEnabled = llmConfig == null || llmConfig.isPrefilterEnabled();

      for (LlmSelectionCandidate candidate : selectedCandidates) {
         EntityNode entry = candidate.getEntry();
         if (entry == null) {
            continue;
         }
         try {
            DirectedPseudograph<EntityNode, EventEdge> forwardGraph = processSingleEntryLlmForward(entry, withQuery, traversalInstance);
            forwardUnion = GraphOperations.union(forwardUnion, forwardGraph);
            successfulCandidates.add(candidate);
         } catch (Exception ex) {
            String failure = "Forward BFS failed for selected entry " + entry.getId() + ": " + describeFailure(ex);
            degradedReason = appendLlmEntryDegradedReason(degradedReason, failure);
            System.out.println(failure);
         }
      }

      stages.setFSelectedRaw(forwardUnion);
      exportGraph(exporter, stages.getFSelectedRaw(), "f_selected_raw", false);

      DirectedPseudograph<EntityNode, EventEdge> rawIntersection = GraphOperations.intersection(stages.getBRaw(), stages.getFSelectedRaw());
      DirectedPseudograph<EntityNode, EventEdge> intersectionCpr = applyCpr(rawIntersection);
      LlmEdgePrefilter.GraphPrefilterResult filterResult = null;
      DirectedPseudograph<EntityNode, EventEdge> intersectionPrefiltered = intersectionCpr;
      if (prefilterEnabled) {
         try {
            filterResult = new LlmEdgePrefilter().filterGraph(intersectionCpr);
            intersectionPrefiltered = filterResult.getKeepGraph();
         } catch (Exception ex) {
            String failure = "G_filter deterministic prefilter failed; retaining CPR intersection: " + describeFailure(ex);
            degradedReason = appendLlmEntryDegradedReason(degradedReason, failure);
            System.out.println(failure);
         }
      }

      Set<Long> selectedEntryIds = selectedEntryIds(selectedCandidates);
      Set<Long> poiNodeIds = poiNodeIds(stages.getBRaw());
      stages.setGFilter(GraphOperations.attackComponents(intersectionPrefiltered, selectedEntryIds, poiNodeIds));
      exportGraph(exporter, stages.getGFilter(), "g_filter", false);

      DirectedPseudograph<EntityNode, EventEdge> retained = stages.getGFilter();
      LlmCoreNoiseFilter.LlmCoreNoiseFilterResult noiseResult = null;
      LlmAttackStoryContext context = new LlmAttackStoryContext(selectedCandidates, resolveLlmAnomalyNode(stages.getBRaw()));
      if (!stages.getGFilter().edgeSet().isEmpty() && llmConfig != null && llmConfig.isNoiseEnabled()) {
         try {
            if (llmConfig.getNoiseMode() == LlmConfig.NoiseMode.SUBGRAPH) {
               SubgraphConfig subgraphConfig = SubgraphConfig.fromLlmConfig(llmConfig);
               ProcessSubgraphBuildResult subgraphBuild = new ProcessSubgraphBuilder(subgraphConfig).build(
                  stages.getGFilter(), selectedEntryNodes(selectedCandidates), resolvePoiNodes(stages.getBRaw())
               );
               exportProcessSubgraphs(subgraphBuild, "g_filter_process_subgraphs", "g_filter_process_subgraphs.dot");
               SubgraphLlmEdgeFilterResult subgraphResult = new SubgraphLlmEdgeFilter().filter(
                  stages.getGFilter(), subgraphBuild, context, resolveLlmAnomalyNode(stages.getBRaw()), subgraphConfig
               );
               retained = subgraphResult.getRetainedGraph();
               writeTextArtifact("g_retained_subgraph_filter_summary", subgraphResult.toSummaryText());
               writeJsonArtifact("g_retained_subgraph_filter_question", subgraphResult.getQuestionJson());
               writeTextArtifact("g_retained_subgraph_filter_answer", subgraphResult.getAnswersText());
               writeJsonArtifact("g_retained_subgraph_filter_decisions", subgraphResult.getDecisionsJson());
               if (!subgraphResult.getDegradedReason().isEmpty()) {
                  degradedReason = appendLlmEntryDegradedReason(degradedReason, subgraphResult.getDegradedReason());
               }
            } else {
               noiseResult = new LlmCoreNoiseFilter().filter(context, stages.getGFilter(), false);
               retained = noiseResult.getFinalGraph();
               writeJsonArtifact("g_retained_llm_question", noiseResult.getCoreResult().getQuestionRecordJson());
               writeJsonArtifact("g_retained_llm_answer", noiseResult.getCoreResult().toJsonObject());
               if (noiseResult.getCoreResult().isFallbackUsed()) {
                  degradedReason = appendLlmEntryDegradedReason(degradedReason, "LLM filtering used fallback retention for one or more requests.");
               }
            }
         } catch (Exception ex) {
            String failure = "LLM filtering failed; retaining G_filter: " + describeFailure(ex);
            degradedReason = appendLlmEntryDegradedReason(degradedReason, failure);
            System.out.println(failure);
         }
      }
      stages.setGRetained(retained);
      exportGraph(exporter, stages.getGRetained(), "g_retained", false);

      DirectedPseudograph<EntityNode, EventEdge> rawUnion = GraphOperations.union(stages.getBRaw(), stages.getFSelectedRaw());
      DirectedPseudograph<EntityNode, EventEdge> rawDifference = GraphOperations.difference(rawUnion, rawIntersection);
      DirectedPseudograph<EntityNode, EventEdge> repairPool = applyCpr(rawDifference);
      if (prefilterEnabled) {
         try {
            repairPool = new LlmEdgePrefilter().filterGraph(repairPool).getKeepGraph();
         } catch (Exception ex) {
            String failure = "G_repair_pool deterministic prefilter failed; retaining CPR difference: " + describeFailure(ex);
            degradedReason = appendLlmEntryDegradedReason(degradedReason, failure);
            System.out.println(failure);
         }
      }
      stages.setGRepairPool(repairPool);
      exportGraph(exporter, stages.getGRepairPool(), "g_repair_pool", false);

      DirectedPseudograph<EntityNode, EventEdge> finalGraph = stages.getGRetained();
      if (llmConfig != null && llmConfig.isRepairAgentEnabled() && !stages.getGRetained().edgeSet().isEmpty() && !stages.getGRepairPool().edgeSet().isEmpty()) {
         try {
            RepairInput repairInput = new RepairInput(context, stages.getGRetained(), rawUnion, stages.getGRepairPool(), rawIntersection);
            LlmRepairResult repairResult = new LlmSemanticRepairAgent().repair(repairInput);
            finalGraph = repairResult.getFinalGraph();
            writeRepairArtifacts(repairResult);
         } catch (Exception ex) {
            String failure = "LLM semantic repair failed; retaining G_retained: " + describeFailure(ex);
            degradedReason = appendLlmEntryDegradedReason(degradedReason, failure);
            System.out.println(failure);
         }
      }
      stages.setGFinal(finalGraph);
      writeStageSummary(stages, filterResult, noiseResult, degradedReason);
      return stages.getGFinal();
   }

   private static Set<Long> selectedEntryIds(List<LlmSelectionCandidate> candidates) {
      Set<Long> ids = new LinkedHashSet<>();
      if (candidates != null) {
         for (LlmSelectionCandidate candidate : candidates) {
            if (candidate != null && candidate.getEntry() != null) {
               ids.add(candidate.getEntry().getId());
            }
         }
      }
      return ids;
   }

   private static Set<EntityNode> selectedEntryNodes(List<LlmSelectionCandidate> candidates) {
      Set<EntityNode> entries = new LinkedHashSet<>();
      if (candidates != null) {
         for (LlmSelectionCandidate candidate : candidates) {
            if (candidate != null && candidate.getEntry() != null) {
               entries.add(candidate.getEntry());
            }
         }
      }
      return entries;
   }

   private static Set<Long> poiNodeIds(DirectedPseudograph<EntityNode, EventEdge> graph) {
      Set<Long> ids = new LinkedHashSet<>();
      for (EntityNode node : resolvePoiNodes(graph)) {
         ids.add(node.getId());
      }
      return ids;
   }


   private static Set<EntityNode> resolvePoiNodes(DirectedPseudograph<EntityNode, EventEdge> graph) {
      Set<EntityNode> nodes = new LinkedHashSet<>();
      EventEdge poi = findPoiEvent(graph);
      if (poi != null) {
         nodes.add(poi.getSource());
         nodes.add(poi.getSink());
      }
      return nodes;
   }

   private static void exportProcessSubgraphs(ProcessSubgraphBuildResult result, String orderedStage, String fixedFileName) {
      try {
         File orderedFile = buildOutputFile(orderedStage);
         try (FileWriter writer = new FileWriter(orderedFile)) {
            new ProcessSubgraphDotExporter().export(result, writer);
         }
         Path fixedPath = getQueryOutputDir().resolve(DOT_DIR).resolve(fixedFileName);
         Files.createDirectories(fixedPath.getParent());
         try (FileWriter writer = new FileWriter(fixedPath.toFile())) {
            new ProcessSubgraphDotExporter().export(result, writer);
         }
      } catch (IOException ex) {
         System.err.println("Failed to export process-subgraph DOT '" + fixedFileName + "'; continuing. " + describeFailure(ex));
      }
   }

   private static void exportPerEntryIntersectArtifactsIfNeeded(
      DirectedPseudograph<EntityNode, EventEdge> backJg, List<EntityNode> selectedEntryLst, WithQuery withQuery, DBTraversal traversalInstance
   ) {
      if (withQuery == null || withQuery.getBfs() == null || withQuery.getLlmClause() != null) {
         return;
      }

      DOTExporter<EntityNode, EventEdge> exporter = createDotExporter();
      forEachSelectedEntry(
         selectedEntryLst,
         "No per-entry extra artifacts generated because no selected entries were found.",
         "Generating non-LLM per-entry forward/intersect artifacts for ",
         "Generating per-entry artifacts for rank ",
         new PerEntryArtifactProcessor() {
            @Override
            public void process(EntityNode entry, int rank) {
               DirectedPseudograph<EntityNode, EventEdge> singleForwardJg = processSingleEntryWithClause(entry, withQuery, traversalInstance);
               exportGraph(exporter, singleForwardJg, buildPerEntryStageName("forward", rank, entry), false);
               DirectedPseudograph<EntityNode, EventEdge> singleIntersectJg = createIntersectJg(backJg, singleForwardJg);
               System.out.println(
                  "Per-entry intersect graph for rank "
                     + rank
                     + " has "
                     + singleIntersectJg.vertexSet().size()
                     + " vertices and "
                     + singleIntersectJg.edgeSet().size()
                     + " edges."
               );
               exportGraph(exporter, singleIntersectJg, buildPerEntryStageName("intersect", rank, entry), false);
            }
         }
      );
   }

   private static DirectedPseudograph<EntityNode, EventEdge> processMergedLlmAttackStory(
      DirectedPseudograph<EntityNode, EventEdge> backJg,
      List<LlmSelectionCandidate> selectedCandidates,
      WithQuery withQuery,
      DBTraversal traversalInstance
   ) {
      DOTExporter<EntityNode, EventEdge> exporter = createDotExporter();
      DirectedPseudograph<EntityNode, EventEdge> emptyGraph = new DirectedPseudograph(EventEdge.class);
      if (selectedCandidates == null || selectedCandidates.isEmpty()) {
         System.out.println("No LLM attack-path nodes were selected; returning an empty merged graph.");
         exportGraph(exporter, emptyGraph, "llm_merged_filtered", false);
         writeLlmGlobalSummary(Collections.<LlmEntryInvestigationResult>emptyList(), emptyGraph, emptyGraph, emptyGraph, emptyGraph, null, emptyGraph, "No selected entries.");
         return emptyGraph;
      }

      LlmConfig llmConfig = null;
      String llmConfigFailure = null;
      try {
         llmConfig = LlmConfig.load();
      } catch (Exception ex) {
         llmConfigFailure = "LLM configuration is unavailable; retaining the global rule-filtered graph and skipping LLM-only stages. "
            + describeFailure(ex);
         System.out.println(llmConfigFailure);
         writeTextArtifact("llm_configuration_degraded", llmConfigFailure);
      }
      boolean rulePrefilterEnabled = llmConfig == null || llmConfig.isPrefilterEnabled();
      boolean noiseEnabled = llmConfig != null && llmConfig.isNoiseEnabled();
      boolean repairAgentEnabled = llmConfig != null && llmConfig.isRepairAgentEnabled();
      EntityNode anomalyNode = resolveLlmAnomalyNode(backJg);
      LlmEntryGraphAssembler assembler = new LlmEntryGraphAssembler();
      LlmCoreNoiseFilter coreNoiseFilter = new LlmCoreNoiseFilter();
      LlmEdgePrefilter ruleNoiseFilter = new LlmEdgePrefilter();
      List<LlmEntryInvestigationResult> entryResults = new ArrayList<>();
      List<LlmSelectionCandidate> successfulCandidates = new ArrayList<>();
      List<EntityNode> successfulEntryNodes = new ArrayList<>();
      DirectedPseudograph<EntityNode, EventEdge> mergedForwardGraph = new DirectedPseudograph(EventEdge.class);

      System.out.println("========== LLM Global Attack Story ==========");
      for (LlmSelectionCandidate candidate : selectedCandidates) {
         EntityNode entry = candidate.getEntry();
         LlmEntryInvestigationResult entryResult = new LlmEntryInvestigationResult(candidate);
         entryResults.add(entryResult);
         if (entry == null) {
            entryResult.fail("Selected LLM entry is null.");
            writeLlmEntryFailureArtifact(entryResult);
            continue;
         }

         try {
            System.out.println(
               "Processing LLM entry rank="
                  + candidate.getRank()
                  + ", candidate_rank="
                  + candidate.getCandidateRank()
                  + ", entry_id="
                  + entry.getId()
                  + ", signature="
                  + entry.getSignature()
            );
            entryResult.forwardGraph = processSingleEntryLlmForward(entry, withQuery, traversalInstance);
            if (entryResult.forwardGraph == null || entryResult.forwardGraph.edgeSet().isEmpty()) {
               entryResult.markEmpty();
               continue;
            }
            entryResult.markSuccess();
            successfulCandidates.add(candidate);
            successfulEntryNodes.add(entry);
            mergedForwardGraph = createUnionJg(mergedForwardGraph, entryResult.forwardGraph);
         } catch (Exception ex) {
            entryResult.fail(describeFailure(ex));
            System.out.println("Skipping LLM entry " + candidate.getRank() + " after failure: " + entryResult.failureReason);
         }
      }

      exportGraph(exporter, mergedForwardGraph, "llm_merged_forward", false);
      if (successfulCandidates.isEmpty() || mergedForwardGraph.edgeSet().isEmpty()) {
         writeLlmGlobalSummary(entryResults, mergedForwardGraph, emptyGraph, emptyGraph, emptyGraph, null, emptyGraph, "No successful forward graph.");
         exportGraph(exporter, emptyGraph, "llm_merged_intersect_raw", false);
         exportGraph(exporter, emptyGraph, "llm_merged_intersect_connected", false);
         exportGraph(exporter, emptyGraph, "llm_merged_rule_filtered", false);
         exportGraph(exporter, emptyGraph, "llm_merged_filtered", false);
         System.out.println("No successful global forward graph completed; skipping merged semantic repair.");
         return emptyGraph;
      }

      LlmEntryGraphAssembler.LlmEntryGraphAssemblyResult assemblyResult =
         assembler.assemble(mergedForwardGraph, backJg, successfulEntryNodes, anomalyNode);
      DirectedPseudograph<EntityNode, EventEdge> rawIntersectGraph = assemblyResult.getRawIntersect();
      DirectedPseudograph<EntityNode, EventEdge> connectedIntersectGraph = applyCpr(assemblyResult.getFilteredIntersect());
      exportGraph(exporter, rawIntersectGraph, "llm_merged_intersect_raw", false);
      exportGraph(exporter, connectedIntersectGraph, "llm_merged_intersect_connected", false);

      if (connectedIntersectGraph == null || connectedIntersectGraph.edgeSet().isEmpty()) {
         writeJsonArtifact("llm_merged_noise_skipped", new org.json.JSONObject().put("reason", "empty_connected_intersection"));
         exportGraph(exporter, emptyGraph, "llm_merged_rule_filtered", false);
         exportGraph(exporter, emptyGraph, "llm_merged_filtered", false);
         writeLlmGlobalSummary(entryResults, mergedForwardGraph, rawIntersectGraph, connectedIntersectGraph, emptyGraph, null, emptyGraph, "Empty connected global intersection.");
         return emptyGraph;
      }

      LlmEdgePrefilter.GraphPrefilterResult globalRuleResult = null;
      DirectedPseudograph<EntityNode, EventEdge> globalRuleFilteredGraph = connectedIntersectGraph;
      String globalDegradedReason = llmConfigFailure == null ? "" : llmConfigFailure;
      if (rulePrefilterEnabled) {
         try {
            globalRuleResult = ruleNoiseFilter.filterGraph(connectedIntersectGraph);
            globalRuleFilteredGraph = globalRuleResult.getKeepGraph();
            writeGlobalRuleFilterArtifact(globalRuleResult, true);
            System.out.println("Global rule filter: " + LlmEdgePrefilter.summarize(globalRuleResult));
         } catch (Exception ruleEx) {
            globalRuleFilteredGraph = createUnionJg(new DirectedPseudograph(EventEdge.class), connectedIntersectGraph);
            globalDegradedReason = appendLlmEntryDegradedReason(globalDegradedReason, "Global rule filtering failed; retaining the connected intersection: " + describeFailure(ruleEx));
            writeGlobalRuleFilterArtifact(null, true);
            writeTextArtifact("llm_merged_rule_filter_degraded", globalDegradedReason);
         }
      } else {
         globalRuleFilteredGraph = createUnionJg(new DirectedPseudograph(EventEdge.class), connectedIntersectGraph);
         writeGlobalRuleFilterArtifact(null, false);
      }
      exportGraph(exporter, globalRuleFilteredGraph, "llm_merged_rule_filtered", false);

      DirectedPseudograph<EntityNode, EventEdge> mergedFilteredGraph = globalRuleFilteredGraph;
      LlmCoreNoiseFilter.LlmCoreNoiseFilterResult globalNoiseResult = null;
      LlmAttackStoryContext mergedContext = new LlmAttackStoryContext(successfulCandidates, anomalyNode);
      if (globalRuleFilteredGraph.edgeSet().isEmpty()) {
         writeJsonArtifact("llm_merged_noise_skipped", new org.json.JSONObject().put("reason", "empty_rule_filtered_intersection"));
       } else if (llmConfigFailure == null && noiseEnabled && llmConfig.getNoiseMode() == LlmConfig.NoiseMode.SUBGRAPH) {
          try {
             SubgraphConfig subgraphConfig = SubgraphConfig.fromLlmConfig(llmConfig);
             EntityNode poiSink = anomalyNode;
             ProcessSubgraphBuildResult subgraphBuild = new ProcessSubgraphBuilder(subgraphConfig).build(
                globalRuleFilteredGraph,
                new LinkedHashSet<>(successfulEntryNodes),
                resolvePoiNodes(globalRuleFilteredGraph)
             );
             exportProcessSubgraphs(subgraphBuild, "llm_merged_subgraph_process_subgraphs", "llm_merged_subgraph_process_subgraphs.dot");
             SubgraphLlmEdgeFilterResult subgraphResult = new SubgraphLlmEdgeFilter().filter(
                globalRuleFilteredGraph,
                subgraphBuild,
                mergedContext,
                poiSink,
                subgraphConfig
             );
             mergedFilteredGraph = subgraphResult.getRetainedGraph();
             writeTextArtifact("llm_merged_subgraph_filter_summary", subgraphResult.toSummaryText());
             writeJsonArtifact("llm_merged_subgraph_filter_question", subgraphResult.getQuestionJson());
             writeTextArtifact("llm_merged_subgraph_filter_answer", subgraphResult.getAnswersText());
             writeJsonArtifact("llm_merged_subgraph_filter_decisions", subgraphResult.getDecisionsJson());
             if (!subgraphResult.getDegradedReason().isEmpty()) {
                writeTextArtifact("llm_merged_subgraph_filter_degraded", subgraphResult.getDegradedReason());
             }
             exportGraph(exporter, mergedFilteredGraph, "llm_merged_subgraph_filtered", false);
             System.out.println(
                "LLM subgraph noise result: input_edges=" + globalRuleFilteredGraph.edgeSet().size()
                   + ", dropped_edges=" + subgraphResult.getAcceptedDropCount()
                   + ", retained_edges=" + mergedFilteredGraph.edgeSet().size()
                   + ", process_subgraphs=" + subgraphBuild.getSubgraphs().size()
             );
          } catch (Exception subgraphEx) {
             globalDegradedReason = appendLlmEntryDegradedReason(
                globalDegradedReason,
                "Global subgraph filtering failed; retaining the rule-filtered graph: " + describeFailure(subgraphEx)
             );
             writeTextArtifact("llm_merged_subgraph_filter_degraded", globalDegradedReason);
             mergedFilteredGraph = globalRuleFilteredGraph;
             exportGraph(exporter, mergedFilteredGraph, "llm_merged_subgraph_filtered", false);
          }
       } else if (llmConfigFailure == null && noiseEnabled) {
         try {
            globalNoiseResult = coreNoiseFilter.filter(mergedContext, globalRuleFilteredGraph, false);
            writeJsonArtifact("llm_merged_noise_question", globalNoiseResult.getCoreResult().getQuestionRecordJson());
            writeJsonArtifact("llm_merged_noise_answer", globalNoiseResult.getCoreResult().toJsonObject());
            logLlmNoiseRunSummary(globalNoiseResult.getCoreResult());
            if (globalNoiseResult.getCoreResult().isFallbackUsed()) {
               globalDegradedReason = appendLlmEntryDegradedReason(globalDegradedReason, "One or more global LLM noise requests failed; edges from failed requests were retained.");
            }
            mergedFilteredGraph = globalNoiseResult.getFinalGraph();
         } catch (Exception noiseEx) {
            globalDegradedReason = appendLlmEntryDegradedReason(globalDegradedReason, "Global LLM noise filtering failed; retaining the rule-filtered graph: " + describeFailure(noiseEx));
            writeTextArtifact("llm_merged_noise_degraded", globalDegradedReason);
         }
      }
      exportGraph(exporter, mergedFilteredGraph, "llm_merged_filtered", false);

      if (successfulCandidates.isEmpty() || mergedFilteredGraph.edgeSet().isEmpty()) {
         writeLlmGlobalSummary(entryResults, mergedForwardGraph, rawIntersectGraph, connectedIntersectGraph, globalRuleFilteredGraph, globalNoiseResult, mergedFilteredGraph, globalDegradedReason);
         System.out.println("No non-empty global graph completed; skipping merged semantic repair.");
         exportGraph(exporter, new DirectedPseudograph(EventEdge.class), "llm_repair_candidates", false);
         System.out.println("========== End LLM Global Attack Story ==========");
         return mergedFilteredGraph;
      }

      DirectedPseudograph<EntityNode, EventEdge> repairUniverse = createUnionJg(backJg, mergedForwardGraph);
      DirectedPseudograph<EntityNode, EventEdge> repairCandidateGraph = createGraphDifferenceByRepairEdgeKey(repairUniverse, mergedFilteredGraph);
      exportGraph(exporter, repairCandidateGraph, "llm_repair_candidates", false);

      DirectedPseudograph<EntityNode, EventEdge> finalGraph = mergedFilteredGraph;
      if (repairAgentEnabled && !repairCandidateGraph.edgeSet().isEmpty()) {
         try {
            RepairInput repairInput = new RepairInput(
               mergedContext,
               mergedFilteredGraph,
               repairUniverse,
               repairCandidateGraph,
               rawIntersectGraph
            );
            LlmSemanticRepairAgent semanticRepairAgent = new LlmSemanticRepairAgent();
            LlmRepairResult repairResult = semanticRepairAgent.repair(repairInput);
            writeLlmMergedRepairArtifacts(repairResult);
            for (LlmRepairResult.LlmRepairRoundResult roundResult : repairResult.getRounds()) {
               exportGraph(exporter, roundResult.getGraphAfterRound(), "llm_repair_round_" + roundResult.getRound(), false);
            }
            finalGraph = repairResult.getFinalGraph();
            exportGraph(exporter, finalGraph, "llm_repaired", false);
         } catch (Exception ex) {
            writeTextArtifact("llm_final_repair_error", describeFailure(ex));
            System.out.println("LLM semantic repair failed; exporting the merged filtered graph. " + describeFailure(ex));
         }
      } else if (repairAgentEnabled) {
         System.out.println("No repair candidate edges remain after excluding all entry intersection graphs.");
      } else {
         System.out.println("LLM semantic repair is disabled; exporting the merged filtered graph.");
      }

      System.out.println(
         "LLM global merge summary: successful_entries="
            + successfulCandidates.size()
            + ", final_nodes="
            + finalGraph.vertexSet().size()
            + ", final_edges="
            + finalGraph.edgeSet().size()
      );
      writeLlmGlobalSummary(entryResults, mergedForwardGraph, rawIntersectGraph, connectedIntersectGraph, globalRuleFilteredGraph, globalNoiseResult, finalGraph, globalDegradedReason);
      System.out.println("========== End LLM Global Attack Story ==========");
      return finalGraph;
   }

   private static DirectedPseudograph<EntityNode, EventEdge> createGraphDifferenceByRepairEdgeKey(
      DirectedPseudograph<EntityNode, EventEdge> sourceGraph,
      DirectedPseudograph<EntityNode, EventEdge> excludedGraph
   ) {
      DirectedPseudograph<EntityNode, EventEdge> difference = new DirectedPseudograph(EventEdge.class);
      if (sourceGraph == null) {
         return difference;
      }

      Set<String> excludedKeys = new HashSet<>();
      if (excludedGraph != null) {
         for (EventEdge edge : excludedGraph.edgeSet()) {
            excludedKeys.add(LlmRepairCandidateEdge.edgeKey(edge));
         }
      }

      for (EntityNode node : sourceGraph.vertexSet()) {
         difference.addVertex(node);
      }
      for (EventEdge edge : sourceGraph.edgeSet()) {
         if (excludedKeys.contains(LlmRepairCandidateEdge.edgeKey(edge))) {
            continue;
         }
         if (!difference.containsVertex(edge.getSource())) {
            difference.addVertex(edge.getSource());
         }
         if (!difference.containsVertex(edge.getSink())) {
            difference.addVertex(edge.getSink());
         }
         if (!difference.containsEdge(edge)) {
            difference.addEdge(edge.getSource(), edge.getSink(), edge);
         }
      }
      return difference;
   }

   private static void writeRuleFilterArtifact(
      LlmSelectionCandidate candidate,
      LlmEdgePrefilter.GraphPrefilterResult result,
      boolean enabled
   ) {
      org.json.JSONObject payload = new org.json.JSONObject().put("enabled", enabled);
      if (result != null) {
         payload.put("input_edge_count", result.getInputEdgeCount());
         payload.put("kept_edge_count", result.getKeepEdges().size());
         payload.put("content_rule_status", result.getContentRuleStatus());
          payload.put("structural_drops", serializeStructuralDrops(result));
          payload.put("rule_drops", serializeRuleDrops(result.getRuleDroppedEdges(), "configured_content_rule"));
      }
      writeJsonArtifact(buildLlmEntryArtifactName(candidate, "rule_filter"), payload);
   }

   private static void writeGlobalRuleFilterArtifact(
      LlmEdgePrefilter.GraphPrefilterResult result,
      boolean enabled
   ) {
      org.json.JSONObject payload = new org.json.JSONObject().put("enabled", enabled);
      if (result != null) {
         payload.put("input_edge_count", result.getInputEdgeCount());
         payload.put("kept_edge_count", result.getKeepEdges().size());
         payload.put("content_rule_status", result.getContentRuleStatus());
          payload.put("structural_drops", serializeStructuralDrops(result));
          payload.put("rule_drops", serializeRuleDrops(result.getRuleDroppedEdges(), "configured_content_rule"));
      }
      writeJsonArtifact("llm_merged_rule_filter", payload);
   }

   private static org.json.JSONArray serializeRuleDrops(List<LlmNoiseGraphEdge> edges, String reason) {
      org.json.JSONArray serialized = new org.json.JSONArray();
      if (edges == null) {
         return serialized;
      }
      for (LlmNoiseGraphEdge graphEdge : edges) {
         serialized.put(graphEdge.toJsonObject().put("drop_reason", reason));
      }
      return serialized;
   }

   private static org.json.JSONArray serializeStructuralDrops(LlmEdgePrefilter.GraphPrefilterResult result) {
      org.json.JSONArray serialized = new org.json.JSONArray();
      if (result == null) {
         return serialized;
      }
      for (LlmNoiseGraphEdge graphEdge : result.getStructuralDroppedEdges()) {
         org.json.JSONObject item = graphEdge.toJsonObject();
         String reason = result.getStructuralDropReason(graphEdge.getEdge());
         Long representativeId = result.getStructuralDropRepresentativeId(graphEdge.getEdge());
         String semanticFamily = result.getStructuralDropSemanticFamily(graphEdge.getEdge());
         item.put("drop_reason", reason == null ? "structural" : reason);
         if (semanticFamily != null) {
            item.put("semantic_family", semanticFamily);
         }
         if (representativeId != null) {
            item.put("representative_edge_id", representativeId.longValue());
         }
         serialized.put(item);
      }
      return serialized;
   }

   private static void writeLlmEntryFailureArtifact(LlmEntryInvestigationResult result) {
      if (result == null || result.candidate == null) {
         return;
      }
      writeTextArtifact(buildLlmEntryArtifactName(result.candidate, "failure"), result.failureReason);
   }

   private static void writeLlmEntrySummary(List<LlmEntryInvestigationResult> entryResults) {
      org.json.JSONArray entries = new org.json.JSONArray();
      int successCount = 0;
      int emptyCount = 0;
      int failedCount = 0;
      if (entryResults != null) {
         for (LlmEntryInvestigationResult result : entryResults) {
            entries.put(result.toJsonObject());
            if (result.status == LlmEntryInvestigationStatus.SUCCESS) {
               successCount++;
            } else if (result.status == LlmEntryInvestigationStatus.EMPTY) {
               emptyCount++;
            } else if (result.status == LlmEntryInvestigationStatus.FAILED) {
               failedCount++;
            }
         }
      }
      writeJsonArtifact(
         "llm_entry_summary",
         new org.json.JSONObject()
            .put("success_count", successCount)
            .put("empty_count", emptyCount)
            .put("failed_count", failedCount)
            .put("entries", entries)
      );
   }

   private static void writeLlmGlobalSummary(
      List<LlmEntryInvestigationResult> entryResults,
      DirectedPseudograph<EntityNode, EventEdge> mergedForwardGraph,
      DirectedPseudograph<EntityNode, EventEdge> rawIntersectGraph,
      DirectedPseudograph<EntityNode, EventEdge> connectedIntersectGraph,
      DirectedPseudograph<EntityNode, EventEdge> ruleFilteredGraph,
      LlmCoreNoiseFilter.LlmCoreNoiseFilterResult noiseResult,
      DirectedPseudograph<EntityNode, EventEdge> finalGraph,
      String degradedReason
   ) {
      org.json.JSONArray entries = new org.json.JSONArray();
      int successCount = 0;
      int emptyCount = 0;
      int failedCount = 0;
      if (entryResults != null) {
         for (LlmEntryInvestigationResult result : entryResults) {
            entries.put(result.toJsonObject());
            if (result.status == LlmEntryInvestigationStatus.SUCCESS) successCount++;
            else if (result.status == LlmEntryInvestigationStatus.EMPTY) emptyCount++;
            else if (result.status == LlmEntryInvestigationStatus.FAILED) failedCount++;
         }
      }
      org.json.JSONObject payload = new org.json.JSONObject()
         .put("mode", "global_union_intersection")
         .put("success_count", successCount)
         .put("empty_count", emptyCount)
         .put("failed_count", failedCount)
         .put("entries", entries)
         .put("merged_forward_nodes", graphNodeCount(mergedForwardGraph))
         .put("merged_forward_edges", graphEdgeCount(mergedForwardGraph))
         .put("raw_intersect_nodes", graphNodeCount(rawIntersectGraph))
         .put("raw_intersect_edges", graphEdgeCount(rawIntersectGraph))
         .put("connected_intersect_nodes", graphNodeCount(connectedIntersectGraph))
         .put("connected_intersect_edges", graphEdgeCount(connectedIntersectGraph))
         .put("rule_filtered_nodes", graphNodeCount(ruleFilteredGraph))
         .put("rule_filtered_edges", graphEdgeCount(ruleFilteredGraph))
         .put("final_nodes", graphNodeCount(finalGraph))
         .put("final_edges", graphEdgeCount(finalGraph))
         .put("degraded_reason", degradedReason == null ? "" : degradedReason);
      if (noiseResult != null) {
         LlmNoiseGraphResult result = noiseResult.getCoreResult();
         payload.put("noise_mode", result.getNoiseMode())
            .put("noise_input_edges", result.getInputEdgeCount())
            .put("noise_dropped_edges", result.getDroppedEdgeCount())
            .put("noise_retained_edges", result.getRetainedEdgeCount())
            .put("noise_llm_request_count", result.getLlmRequestCount())
            .put("noise_successful_request_count", result.getSuccessfulRequestCount())
            .put("noise_fallback_partition_count", result.getFallbackPartitionCount())
            .put("noise_fallback_used", result.isFallbackUsed());
      }
      writeJsonArtifact("llm_merged_summary", payload);
   }

   private static String buildLlmEntryStageName(LlmSelectionCandidate candidate, String stage) {
      return "llm_entry_" + candidate.getRank() + "_id_" + candidate.getEntryId() + "_" + stage;
   }

   private static String buildLlmEntryArtifactName(LlmSelectionCandidate candidate, String artifact) {
      return "llm_entry_" + candidate.getRank() + "_id_" + candidate.getEntryId() + "_" + artifact;
   }

   private static void logLlmNoiseRunSummary(LlmNoiseGraphResult result) {
      System.out.println(
         "LLM global noise result: mode="
            + result.getNoiseMode()
            + ", input_edges="
            + result.getInputEdgeCount()
             + ", llm_requests="
             + result.getLlmRequestCount()
            + ", partition_edge_limit="
            + (result.getEffectivePartitionSize() == null ? "n/a" : result.getEffectivePartitionSize())
            + ", partition_count="
            + result.getPartitionCount()
            + ", successful_requests="
            + result.getSuccessfulRequestCount()
            + ", fallback_partitions="
            + result.getFallbackPartitionCount()
            + ", dropped_edges="
            + result.getDroppedEdgeCount()
            + ", retained_edges="
            + result.getRetainedEdgeCount()
            + ", fallback="
            + result.isFallbackUsed()
      );
   }

   private static String appendLlmEntryDegradedReason(String currentReason, String additionalReason) {
      if (additionalReason == null || additionalReason.trim().isEmpty()) {
         return currentReason == null ? "" : currentReason;
      }
      if (currentReason == null || currentReason.trim().isEmpty()) {
         return additionalReason;
      }
      return currentReason + " " + additionalReason;
   }

   private static String describeFailure(Exception ex) {
      String detail = ex == null || ex.getMessage() == null ? "" : ex.getMessage().trim();
      detail = detail.replaceAll("(?i)(api[_-]?key|authorization|bearer)\\s*[:=]?\\s*\\S+", "$1=[redacted]");
      return (ex == null ? "Unknown failure" : ex.getClass().getSimpleName()) + (detail.isEmpty() ? "" : ": " + detail);
   }

   private static void logLlmEntryProcessingBoundary(
      EntityNode entry,
      int rank,
      DirectedPseudograph<EntityNode, EventEdge> filteredIntersectGraph,
      DirectedPseudograph<EntityNode, EventEdge> repairSearchGraph
   ) {
      String nodeType = getEntityTypeName(entry);
      int intersectNodeCount = filteredIntersectGraph == null ? 0 : filteredIntersectGraph.vertexSet().size();
      int intersectEdgeCount = filteredIntersectGraph == null ? 0 : filteredIntersectGraph.edgeSet().size();
      int repairSearchNodeCount = repairSearchGraph == null ? 0 : repairSearchGraph.vertexSet().size();
      int repairSearchEdgeCount = repairSearchGraph == null ? 0 : repairSearchGraph.edgeSet().size();

      System.out.println();
      System.out.println("========== LLM Entry " + rank + " ==========");
      System.out.println(
         "entry_id="
            + entry.getId()
            + ", type="
            + nodeType
            + ", signature="
            + entry.getSignature()
            + ", composite_score="
            + getEntryCompositeScore(entry)
      );
      System.out.println(
         "intersect_graph="
            + intersectNodeCount
            + " vertices / "
            + intersectEdgeCount
            + " edges, repair_search_graph="
            + repairSearchNodeCount
            + " vertices / "
            + repairSearchEdgeCount
            + " edges"
      );
   }

   private static void logMergedLlmProcessingBoundary(
      LlmAttackStoryContext context,
      DirectedPseudograph<EntityNode, EventEdge> filteredIntersectGraph,
      DirectedPseudograph<EntityNode, EventEdge> repairSearchGraph
   ) {
      int intersectNodeCount = filteredIntersectGraph == null ? 0 : filteredIntersectGraph.vertexSet().size();
      int intersectEdgeCount = filteredIntersectGraph == null ? 0 : filteredIntersectGraph.edgeSet().size();
      int repairSearchNodeCount = repairSearchGraph == null ? 0 : repairSearchGraph.vertexSet().size();
      int repairSearchEdgeCount = repairSearchGraph == null ? 0 : repairSearchGraph.edgeSet().size();
      System.out.println(
         "merged_intersect_graph="
            + intersectNodeCount
            + " vertices / "
            + intersectEdgeCount
            + " edges, repair_search_graph="
            + repairSearchNodeCount
            + " vertices / "
            + repairSearchEdgeCount
            + " edges, selected_nodes="
            + (context == null ? 0 : context.getSelectedCandidates().size())
      );
   }

   private static void logMergedLlmResult(
      DirectedPseudograph<EntityNode, EventEdge> filteredIntersectGraph,
      DirectedPseudograph<EntityNode, EventEdge> finalGraph,
      LlmCoreNoiseFilter.LlmCoreNoiseFilterResult coreResult,
      LlmRepairResult repairResult,
      LlmConfig llmConfig
   ) {
      int rawNodeCount = filteredIntersectGraph == null ? 0 : filteredIntersectGraph.vertexSet().size();
      int rawEdgeCount = filteredIntersectGraph == null ? 0 : filteredIntersectGraph.edgeSet().size();
      int finalNodeCount = finalGraph == null ? 0 : finalGraph.vertexSet().size();
      int finalEdgeCount = finalGraph == null ? 0 : finalGraph.edgeSet().size();
      StringBuilder summary = new StringBuilder();
      summary.append("merged_raw_nodes=")
         .append(rawNodeCount)
         .append(", merged_raw_edges=")
         .append(rawEdgeCount)
         .append(", noise_filter=")
         .append(llmConfig.isNoiseEnabled() ? "enabled" : "disabled");

      if (coreResult != null) {
         summary.append(", core_dropped_edges=")
            .append(coreResult.getCoreResult().getDroppedEdgeCount())
            .append(", core_retained_edges=")
            .append(coreResult.getCoreResult().getRetainedEdgeCount());
      }

      summary.append(", semantic_repair=")
         .append(llmConfig.isRepairAgentEnabled() ? "enabled" : "disabled");
      if (repairResult != null) {
         summary.append(", repair_rounds=")
            .append(repairResult.getRounds().size())
            .append(", repair_added_edges=")
            .append(repairResult.getAddedEdgeCount());
      }

      summary.append(", final_nodes=")
         .append(finalNodeCount)
         .append(", final_edges=")
         .append(finalEdgeCount);
      System.out.println(summary.toString());
   }

   private static String getEntityTypeName(EntityNode entry) {
      if (entry == null) {
         return "Unknown";
      }
      if (entry.getN() != null) {
         return "Network";
      }
      if (entry.getF() != null) {
         return "File";
      }
      if (entry.getP() != null) {
         return "Process";
      }
      return "Unknown";
   }

   private static void writeLlmRepairArtifacts(int rank, EntityNode entry, LlmRepairResult repairResult) {
      if (repairResult == null || repairResult.getRounds().isEmpty()) {
         return;
      }

      for (LlmRepairResult.LlmRepairRoundResult round : repairResult.getRounds()) {
         writeTextArtifact(buildRepairRoundArtifactName(round.getRound(), "gap_question", rank, entry), round.getAnchorQuestion());
         writeTextArtifact(buildRepairRoundArtifactName(round.getRound(), "gap_answer", rank, entry), round.getAnchorAnswer());
         writeTextArtifact(buildRepairRoundArtifactName(round.getRound(), "anchors", rank, entry), formatRepairAnchors(round.getAnchors()));
         writeTextArtifact(buildRepairRoundArtifactName(round.getRound(), "candidates", rank, entry), formatRepairCandidates(round.getCandidates()));
         if (round.getEdgeQuestion() != null && !round.getEdgeQuestion().trim().isEmpty()) {
            writeTextArtifact(buildRepairRoundArtifactName(round.getRound(), "select_question", rank, entry), round.getEdgeQuestion());
         }
         if (round.getEdgeAnswer() != null && !round.getEdgeAnswer().trim().isEmpty()) {
            writeTextArtifact(buildRepairRoundArtifactName(round.getRound(), "select_answer", rank, entry), round.getEdgeAnswer());
         }
         writeTextArtifact(buildRepairRoundArtifactName(round.getRound(), "selected_edges", rank, entry), formatRepairSelectedEdges(round.getSelectedEdges()));
      }
   }

   private static void writeLlmMergedRepairArtifacts(LlmRepairResult repairResult) {
      if (repairResult == null || (repairResult.getRounds().isEmpty() && repairResult.getAgentCycles().isEmpty())) {
         return;
      }
      org.json.JSONArray cycleParseStatus = new org.json.JSONArray();
      for (LlmRepairResult.AgentCycle cycle : repairResult.getAgentCycles()) {
         cycleParseStatus.put(
            new org.json.JSONObject()
               .put("cycle", cycle.getCycle())
               .put("candidate_count", cycle.getCandidateCount())
               .put("penalized_candidate_count", cycle.getPenalizedCandidateCount())
               .put("unselected_candidate_count", cycle.getUnselectedCandidateCount())
               .put("hard_rejected_candidate_count", cycle.getHardRejectedCandidateCount())
               .put("gap_candidate_counts", new org.json.JSONObject(cycle.getCandidateCountsByGap()))
               .put("gap_diagnostics", new org.json.JSONObject(cycle.getGapDiagnostics()))
               .put("base_edge_count", cycle.getBaseEdgeCount())
               .put("candidate_pool_count", cycle.getCandidatePoolCount())
               .put("proposed_candidate_ranks", toJsonArray(cycle.getProposedCandidateRanks()))
               .put("added_edge_count", cycle.getAddedEdgeCount())
               .put("cycle_stop_reason", cycle.getStopReason())
               .put("assessment", toLlmRepairAgentPhaseJson(cycle.getAssessment()))
               .put("selection", toLlmRepairAgentPhaseJson(cycle.getSelection()))
         );
      }
      writeJsonArtifact(
         "llm_repair_agent_state",
         new org.json.JSONObject()
            .put("attack_knowledge_version", repairResult.getAttackKnowledgeVersion())
            .put("cycles", repairResult.getAgentCycles().size())
            .put("added_edges", repairResult.getAddedEdgeCount())
            .put("rejected_edges", repairResult.getRejectedEdges().size())
            .put("stop_reason", repairResult.getStopReason())
            .put("cycle_parse_status", cycleParseStatus)
      );
       for (LlmRepairResult.AgentCycle cycle : repairResult.getAgentCycles()) {
          writeLlmRepairAgentPhaseArtifacts(cycle.getCycle(), "assessment", cycle.getAssessment());
          writeLlmRepairAgentPhaseArtifacts(cycle.getCycle(), "selection", cycle.getSelection());
       }
      org.json.JSONArray rejected = new org.json.JSONArray();
      for (String reason : repairResult.getRejectedEdges()) rejected.put(reason);
      writeJsonArtifact("llm_repair_agent_rejected_edges", new org.json.JSONObject().put("rejected", rejected));
      for (LlmRepairResult.LlmRepairRoundResult round : repairResult.getRounds()) {
         String prefix = "llm_merged_repair_round_" + round.getRound() + "_";
         writeTextArtifact(prefix + "gap_question", round.getAnchorQuestion());
         writeTextArtifact(prefix + "gap_answer", round.getAnchorAnswer());
         writeTextArtifact(prefix + "anchors", formatRepairAnchors(round.getAnchors()));
         writeTextArtifact(prefix + "candidates", formatRepairCandidates(round.getCandidates()));
         if (round.getEdgeQuestion() != null && !round.getEdgeQuestion().trim().isEmpty()) {
            writeTextArtifact(prefix + "select_question", round.getEdgeQuestion());
         }
         if (round.getEdgeAnswer() != null && !round.getEdgeAnswer().trim().isEmpty()) {
            writeTextArtifact(prefix + "select_answer", round.getEdgeAnswer());
         }
         writeTextArtifact(prefix + "selected_edges", formatRepairSelectedEdges(round.getSelectedEdges()));
      }
   }

   private static String buildRepairRoundArtifactName(int round, String stage, int rank, EntityNode entry) {
      return buildPerEntryArtifactName("llm_repair_round_" + round + "_" + stage, rank, entry);
   }

   private static String formatRepairAnchors(List<LlmRepairNode> anchors) {
      StringBuilder builder = new StringBuilder();
      if (anchors != null) {
         for (LlmRepairNode anchor : anchors) {
            builder.append(anchor.toLine()).append(System.lineSeparator());
         }
      }
      return builder.toString();
   }

   private static String formatRepairCandidates(List<LlmRepairCandidateEdge> candidates) {
      StringBuilder builder = new StringBuilder();
      if (candidates != null) {
         for (LlmRepairCandidateEdge candidate : candidates) {
            builder.append(candidate.toLine()).append(System.lineSeparator());
         }
      }
      return builder.toString();
   }

   private static String formatRepairSelectedEdges(List<LlmRepairSelectedEdge> selectedEdges) {
      StringBuilder builder = new StringBuilder();
      if (selectedEdges != null) {
         for (LlmRepairSelectedEdge selectedEdge : selectedEdges) {
            builder.append(selectedEdge.toLine()).append(System.lineSeparator());
         }
      }
      return builder.toString();
   }

   private static void writeTextArtifact(String fileStem, String content) {
      try {
         Path queryOutputDir = getQueryOutputDir();
         Files.createDirectories(queryOutputDir);
         Path targetPath = queryOutputDir.resolve(fileStem + ".txt");
         Files.write(targetPath, (content == null ? "" : content).getBytes(StandardCharsets.UTF_8));
      } catch (Exception ex) {
         System.err.println("Failed to write text artifact '" + fileStem + "'; continuing. " + describeFailure(ex));
      }
   }

   private static String buildPerEntryArtifactName(String prefix, int rank, EntityNode entry) {
      return prefix + "_entry_" + rank + "_id_" + entry.getId();
   }

   private static void writeJsonArtifact(String fileStem, Object jsonPayload) {
      try {
         Path queryOutputDir = getQueryOutputDir();
         Files.createDirectories(queryOutputDir);
         Path targetPath = queryOutputDir.resolve(fileStem + ".json");
         String serialized = jsonPayload instanceof org.json.JSONArray
            ? ((org.json.JSONArray)jsonPayload).toString(2)
            : ((org.json.JSONObject)jsonPayload).toString(2);
         Files.write(targetPath, serialized.getBytes(StandardCharsets.UTF_8));
      } catch (Exception ex) {
         System.err.println("Failed to write JSON artifact '" + fileStem + "'; continuing. " + describeFailure(ex));
      }
   }

   private static EntityNode resolveLlmAnomalyNode(DirectedPseudograph<EntityNode, EventEdge> backJg) {
      if (backJg == null || poiEventInfo == null || poiEventInfo.getSinkSignature() == null) {
         return null;
      }

      for (EntityNode node : backJg.vertexSet()) {
         if (poiEventInfo.getSinkSignature().equals(node.getSignature())) {
            return node;
         }
      }

      return null;
   }

   private static String buildPerEntryStageName(String prefix, int rank, EntityNode entry) {
      return prefix + "_entry_" + rank + "_id_" + entry.getId();
   }

   private static String buildLlmSeedStageName(String prefix, LlmSelectionCandidate candidate) {
      return prefix
         + "_seed_"
         + candidate.getRank()
         + "_id_"
         + candidate.getEntryId();
   }

   private static DOTExporter<EntityNode, EventEdge> createDotExporter() {
      return new DOTExporter(new EntityIdProvider(), new EntityNameProvider(), new EventEdgeProvider(), new EntityAttributeProvider(), null);
   }

   private static void forEachSelectedEntry(
      List<EntityNode> selectedEntryLst,
      String emptyMessage,
      String startMessagePrefix,
      String perEntryMessagePrefix,
      PerEntryArtifactProcessor processor
   ) {
      if (selectedEntryLst == null || selectedEntryLst.isEmpty()) {
         System.out.println(emptyMessage);
         return;
      }

      if (startMessagePrefix != null && !startMessagePrefix.trim().isEmpty()) {
         System.out.println(startMessagePrefix + selectedEntryLst.size() + " selected entries.");
      }
      int rank = 1;
      for (EntityNode entry : selectedEntryLst) {
         if (entry == null) {
            rank++;
            continue;
         }

         if (perEntryMessagePrefix != null && !perEntryMessagePrefix.trim().isEmpty()) {
            System.out.println(perEntryMessagePrefix + rank + ", id=" + entry.getId() + ", signature=" + entry.getSignature());
         }
         processor.process(entry, rank);
         rank++;
      }
   }

   public static EntityNode getEntityNode(Node n) {
      EntityNode node = null;
      if (n.hasLabel(Neo4jTraversal.MyLabel.File)) {
         FileEntity f = new FileEntity("", "", n.getProperty("name").toString(), (Long)n.getProperty("id"), n.getProperty("hostname").toString(), "");
         node = new EntityNode(f);
      } else if (n.hasLabel(Neo4jTraversal.MyLabel.Process)) {
         String exePath = n.getProperty("exename").toString();
         String reducedExepath = !exePath.isEmpty() && exePath.contains(" ") ? exePath.substring(0, exePath.indexOf(" ")) : exePath;
         ProcessEntity p = new ProcessEntity(
            n.getProperty("pid").toString(), "", "", "", "", (Long)n.getProperty("id"), reducedExepath, n.getProperty("hostname").toString(), "", 0L, "", ""
         );
         node = new EntityNode(p);
      } else if (n.hasLabel(Neo4jTraversal.MyLabel.Network)) {
         NetworkEntity network = new NetworkEntity(
            n.hasProperty("srcip") ? n.getProperty("srcip").toString() : "",
            n.hasProperty("dstip") ? n.getProperty("dstip").toString() : "",
            n.hasProperty("srcport") ? n.getProperty("srcport").toString() : "",
            n.hasProperty("dstport") ? n.getProperty("dstport").toString() : "",
            (Long)n.getProperty("id"),
            n.getProperty("hostname").toString(),
            ""
         );
         node = new EntityNode(network);
      }

      return node;
   }

   public static EntityNode getNodeById(int id, Connection conn) {
      EntityNode node = null;
      if (id <= 0 || conn == null) {
         return null;
      }

      String sql = "";
      String nodeType = "";
      sql = "Select id, 'f' as nodetype From file Where id=? Union Select id, 'n' as nodetype From network Where id=? Union Select id, 'p' as nodetype From process Where id=?";
      try (PreparedStatement stmt = conn.prepareStatement(sql)) {
         stmt.setInt(1, id);
         stmt.setInt(2, id);
         stmt.setInt(3, id);
         try (ResultSet rs = stmt.executeQuery()) {
            if (rs.next()) {
               nodeType = rs.getString("nodetype");
            }
         }
      } catch (SQLException var104) {
         var104.printStackTrace();
      }

      if (nodeType.equals("p")) {
         sql = "Select * From process Where id=?";
      } else if (nodeType.equals("f")) {
         sql = "Select * From file Where id=?";
      } else if (nodeType.equals("n")) {
         if ("postgres".equals(db) || "neo4jpostgres".equals(db)) {
            sql = "Select id, dstip::cidr as dstip, dstport, hostname, srcip::cidr as srcip, srcport From network Where id=?";
         } else {
            sql = "Select id, dstip as dstip, dstport, hostname, srcip as srcip, srcport From network Where id=?";
         }
      } else {
         return null;
      }

      try (PreparedStatement stmt = conn.prepareStatement(sql)) {
         stmt.setInt(1, id);
         try (ResultSet rs = stmt.executeQuery()) {
            if (rs.next()) {
               switch (nodeType.hashCode()) {
                  case 102:
                     if (nodeType.equals("f")) {
                        FileEntity f = new FileEntity("", "", rs.getString("name"), (long)rs.getInt("id"), rs.getString("hostname"), "");
                        node = new EntityNode(f);
                     }
                     break;
                  case 110:
                     if (nodeType.equals("n")) {
                        NetworkEntity n = new NetworkEntity(
                           rs.getString("srcip"),
                           rs.getString("dstip"),
                           String.valueOf(rs.getInt("srcport")),
                           String.valueOf(rs.getInt("dstport")),
                           (long)rs.getInt("id"),
                           rs.getString("hostname"),
                           ""
                        );
                        node = new EntityNode(n);
                     }
                     break;
                  case 112:
                     if (nodeType.equals("p")) {
                        ProcessEntity p = new ProcessEntity(
                           String.valueOf(rs.getInt("pid")),
                           "",
                           "",
                           "",
                           "",
                           (long)rs.getInt("id"),
                           rs.getString("exename"),
                           rs.getString("hostname"),
                           "",
                           0L,
                           "",
                           ""
                        );
                        node = new EntityNode(p);
                     }
               }
            }
         }
      } catch (SQLException var99) {
         var99.printStackTrace();
      }

      return node;
   }

   static final class BackendSelection {
      private final String backendId;
      private final String initArg;

      BackendSelection(String backendId, String initArg) {
         this.backendId = backendId;
         this.initArg = initArg;
      }

      String getBackendId() {
         return this.backendId;
      }

      String getInitArg() {
         return this.initArg;
      }
   }

   private static org.json.JSONObject toLlmRepairAgentPhaseJson(LlmRepairResult.AgentPhase phase) {
      LlmRepairResult.AgentPhase safePhase = phase == null ? LlmRepairResult.AgentPhase.empty() : phase;
      return new org.json.JSONObject()
         .put("valid_lines", safePhase.getValidLineCount())
         .put("ignored_lines", safePhase.getIgnoredLineCount())
         .put("finish_reason", safePhase.getFinishReason())
         .put("correction_attempted", safePhase.isCorrectionAttempted())
         .put(
            "correction",
            new org.json.JSONObject()
               .put("valid_lines", safePhase.getCorrectionValidLineCount())
               .put("ignored_lines", safePhase.getCorrectionIgnoredLineCount())
               .put("finish_reason", safePhase.getCorrectionFinishReason())
         );
   }

   private static org.json.JSONArray toJsonArray(Iterable<?> values) {
      org.json.JSONArray array = new org.json.JSONArray();
      if (values != null) {
         for (Object value : values) array.put(value);
      }
      return array;
   }

   private static void writeLlmRepairAgentPhaseArtifacts(int cycle, String phaseName, LlmRepairResult.AgentPhase phase) {
      LlmRepairResult.AgentPhase safePhase = phase == null ? LlmRepairResult.AgentPhase.empty() : phase;
      String prefix = "llm_repair_agent_cycle_" + cycle + "_" + phaseName + "_";
      writeTextArtifact(prefix + "question", safePhase.getPrompt());
      writeTextArtifact(prefix + "answer", safePhase.getResponse());
      if (safePhase.isCorrectionAttempted()) {
         writeTextArtifact(prefix + "correction_question", safePhase.getCorrectionPrompt());
         writeTextArtifact(prefix + "correction_answer", safePhase.getCorrectionResponse());
      }
   }

   private static org.json.JSONObject parseLlmAgentArtifact(String text) {
      if (text == null || text.trim().isEmpty()) {
         return new org.json.JSONObject().put("status", "empty");
      }
      try {
         return new org.json.JSONObject(util.llm.LlmConnectivityProbe.extractJsonObjectText(text));
      } catch (Exception ex) {
         return new org.json.JSONObject().put("status", "invalid_json").put("raw", text).put("error", describeFailure(ex));
      }
   }

   private enum LlmEntryInvestigationStatus {
      PENDING,
      SUCCESS,
      EMPTY,
      FAILED
   }

   private static final class LlmEntryInvestigationResult {
      private final LlmSelectionCandidate candidate;
      private DirectedPseudograph<EntityNode, EventEdge> forwardGraph;
      private DirectedPseudograph<EntityNode, EventEdge> rawIntersectGraph;
      private DirectedPseudograph<EntityNode, EventEdge> connectedIntersectGraph;
      private LlmEdgePrefilter.GraphPrefilterResult ruleFilterResult;
      private DirectedPseudograph<EntityNode, EventEdge> ruleFilteredGraph;
      private LlmCoreNoiseFilter.LlmCoreNoiseFilterResult coreNoiseResult;
      private DirectedPseudograph<EntityNode, EventEdge> llmFilteredGraph;
      private LlmEntryInvestigationStatus status = LlmEntryInvestigationStatus.PENDING;
      private String failureReason = "";
      private String degradedReason = "";

      private LlmEntryInvestigationResult(LlmSelectionCandidate candidate) {
         this.candidate = candidate;
      }

      private void markSuccess() {
         this.status = LlmEntryInvestigationStatus.SUCCESS;
      }

      private void markEmpty() {
         this.status = LlmEntryInvestigationStatus.EMPTY;
      }

      private void fail(String reason) {
         this.status = LlmEntryInvestigationStatus.FAILED;
         this.failureReason = reason == null ? "Unknown failure" : reason;
      }

      private org.json.JSONObject toJsonObject() {
         EntityNode entry = this.candidate == null ? null : this.candidate.getEntry();
         org.json.JSONObject json = new org.json.JSONObject()
            .put("status", this.status.name().toLowerCase(Locale.US))
            .put("candidate_rank", this.candidate == null ? 0 : this.candidate.getCandidateRank())
            .put("selected_rank", this.candidate == null ? 0 : this.candidate.getRank())
            .put("entry_id", entry == null ? -1 : entry.getId())
            .put("entry_signature", entry == null ? "" : entry.getSignature())
            .put("forward_nodes", graphNodeCount(this.forwardGraph))
            .put("forward_edges", graphEdgeCount(this.forwardGraph))
            .put("raw_intersect_nodes", graphNodeCount(this.rawIntersectGraph))
            .put("raw_intersect_edges", graphEdgeCount(this.rawIntersectGraph))
            .put("connected_intersect_nodes", graphNodeCount(this.connectedIntersectGraph))
            .put("connected_intersect_edges", graphEdgeCount(this.connectedIntersectGraph))
            .put("rule_filtered_nodes", graphNodeCount(this.ruleFilteredGraph))
            .put("rule_filtered_edges", graphEdgeCount(this.ruleFilteredGraph))
            .put("llm_filtered_nodes", graphNodeCount(this.llmFilteredGraph))
            .put("llm_filtered_edges", graphEdgeCount(this.llmFilteredGraph))
            .put("failure_reason", this.failureReason)
            .put("degraded_reason", this.degradedReason);
          if (this.ruleFilterResult != null) {
            json.put("rule_structural_drop_count", this.ruleFilterResult.getStructuralDroppedEdges().size());
            json.put("rule_structural_normalization_drop_count", this.ruleFilterResult.getStructuralNormalizationDroppedEdges().size());
            json.put("rule_duplicate_drop_count", this.ruleFilterResult.getDuplicateDropCount());
            json.put("rule_semantic_normalization_drop_count", this.ruleFilterResult.getSemanticNormalizationDropCount());
            json.put("rule_semantic_mirror_drop_count", this.ruleFilterResult.getSemanticMirrorDropCount());
            json.put("rule_content_drop_count", this.ruleFilterResult.getRuleDroppedEdges().size());
         }
         if (this.coreNoiseResult != null) {
            json.put("llm_noise_fallback", this.coreNoiseResult.getCoreResult().isFallbackUsed());
            json.put("llm_noise_retained_count", this.coreNoiseResult.getCoreResult().getRetainedEdgeCount());
            json.put("llm_noise_dropped_count", this.coreNoiseResult.getCoreResult().getDroppedEdgeCount());
         }
         return json;
      }
   }

   private static int graphNodeCount(DirectedPseudograph<EntityNode, EventEdge> graph) {
      return graph == null ? 0 : graph.vertexSet().size();
   }

   private static int graphEdgeCount(DirectedPseudograph<EntityNode, EventEdge> graph) {
      return graph == null ? 0 : graph.edgeSet().size();
   }

   private static final class LlmEntrySelectionContext {
      private final LlmSelectionResult selectionResult;
      private final List<EntityNode> originalEntries;
      private final List<LlmEvidencePathResult> evidencePaths;
      private final List<LlmSelectionCandidate> fallbackCandidates;

      private LlmEntrySelectionContext(
         LlmSelectionResult selectionResult, List<EntityNode> originalEntries, List<LlmEvidencePathResult> evidencePaths
      ) {
         this(selectionResult, originalEntries, evidencePaths, null);
      }

      private LlmEntrySelectionContext(
         LlmSelectionResult selectionResult,
         List<EntityNode> originalEntries,
         List<LlmEvidencePathResult> evidencePaths,
         List<LlmSelectionCandidate> fallbackCandidates
      ) {
         this.selectionResult = selectionResult;
         this.originalEntries = originalEntries == null ? Collections.emptyList() : originalEntries;
         this.evidencePaths = evidencePaths == null ? Collections.emptyList() : evidencePaths;
         this.fallbackCandidates = fallbackCandidates == null ? Collections.<LlmSelectionCandidate>emptyList() : fallbackCandidates;
      }

      private List<EntityNode> getSelectedEntries() {
         if (this.selectionResult != null) {
            return this.selectionResult.getSelectedEntries();
         }
         if (!this.fallbackCandidates.isEmpty()) {
            List<EntityNode> selectedEntries = new ArrayList<>();
            for (LlmSelectionCandidate candidate : this.fallbackCandidates) {
               selectedEntries.add(candidate.getEntry());
            }
            return selectedEntries;
         }
         return this.originalEntries;
      }

      private List<LlmSelectionCandidate> getSelectedCandidates() {
         return this.selectionResult == null ? this.fallbackCandidates : this.selectionResult.getRankedCandidates();
      }

   }

   private interface PerEntryArtifactProcessor {
      void process(EntityNode entry, int rank);
   }

   private static final class RunLogCapture implements AutoCloseable {
      private final PrintStream originalOut;
      private final PrintStream originalErr;
      private final FileOutputStream fileOutputStream;
      private final PrintStream teeOut;
      private final PrintStream teeErr;

      private RunLogCapture(
         PrintStream originalOut,
         PrintStream originalErr,
         FileOutputStream fileOutputStream,
         PrintStream teeOut,
         PrintStream teeErr
      ) {
         this.originalOut = originalOut;
         this.originalErr = originalErr;
         this.fileOutputStream = fileOutputStream;
         this.teeOut = teeOut;
         this.teeErr = teeErr;
      }

      static RunLogCapture start(Path logPath) throws IOException {
         Files.createDirectories(logPath.getParent());
         PrintStream originalOut = System.out;
         PrintStream originalErr = System.err;
         FileOutputStream fileOutputStream = new FileOutputStream(logPath.toFile(), true);
         Object lock = new Object();
         PrintStream teeOut = new PrintStream(new TeeOutputStream(originalOut, fileOutputStream, lock), true);
         PrintStream teeErr = new PrintStream(new TeeOutputStream(originalErr, fileOutputStream, lock), true);
         System.setOut(teeOut);
         System.setErr(teeErr);
         return new RunLogCapture(originalOut, originalErr, fileOutputStream, teeOut, teeErr);
      }

      public void close() throws IOException {
         System.out.flush();
         System.err.flush();
         System.setOut(this.originalOut);
         System.setErr(this.originalErr);
         this.teeOut.close();
         this.teeErr.close();
         this.fileOutputStream.close();
      }
   }

   private static final class TeeOutputStream extends OutputStream {
      private final OutputStream consoleStream;
      private final OutputStream fileStream;
      private final Object lock;

      private TeeOutputStream(OutputStream consoleStream, OutputStream fileStream, Object lock) {
         this.consoleStream = consoleStream;
         this.fileStream = fileStream;
         this.lock = lock;
      }

      public void write(int b) throws IOException {
         synchronized(this.lock) {
            this.consoleStream.write(b);
            this.fileStream.write(b);
         }
      }

      public void write(byte[] b) throws IOException {
         synchronized(this.lock) {
            this.consoleStream.write(b);
            this.fileStream.write(b);
         }
      }

      public void write(byte[] b, int off, int len) throws IOException {
         synchronized(this.lock) {
            this.consoleStream.write(b, off, len);
            this.fileStream.write(b, off, len);
         }
      }

      public void flush() throws IOException {
         synchronized(this.lock) {
            this.consoleStream.flush();
            this.fileStream.flush();
         }
      }

      public void close() throws IOException {
         this.flush();
      }
   }
}
