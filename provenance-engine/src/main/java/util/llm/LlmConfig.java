package util.llm;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;

public class LlmConfig {
   private static final String CONFIG_SYSTEM_PROPERTY = "progql.llm.config";
   private static final String DEFAULT_CONFIG_FILE = "progql-llm.properties";
   public static final double DEFAULT_ENTRY_RANKING_IMPACT_WEIGHT = 0.7;
   public static final double DEFAULT_ENTRY_RANKING_TIME_WEIGHT = 0.3;

   public enum NoiseMode {
      BATCH("batch"),
      SLICE("slice"),
      ONE_SHOT("one_shot"),
      SUBGRAPH("subgraph");

      private final String configValue;

      NoiseMode(String configValue) {
         this.configValue = configValue;
      }

      public String getConfigValue() {
         return this.configValue;
      }
   }

   private final Path sourcePath;
   private final String provider;
   private final String endpoint;
   private final String apiKey;
   private final String model;
   private final double temperature;
   private final int connectTimeoutMs;
   private final int readTimeoutMs;
   private final int entrySelectionMaxEvidencePathsPerCandidate;
   private final int entrySelectionMaxEvidenceSearchStatesPerPath;
   private final boolean noiseEnabled;
   private final NoiseMode noiseMode;
   private final int noiseBatchSize;
   private final int noiseSliceSize;
   private final int noiseRunningSummaryMaxChars;
   private final boolean prefilterEnabled;
   private final boolean repairAgentEnabled;
   private final int repairAgentMaxCycles;
   private final int repairAgentMaxGaps;
   private final int repairAgentMaxCandidateEdges;
   private final int repairAgentMaxSelectedEdgesPerCycle;
   private final int repairAgentUnselectedCandidatePenalty;
   private final int repairAgentGapRetrievalMaxAnchorHops;
   private final int subgraphMaxUpstreamDepth;
   private final int subgraphMaxDownstreamDepth;
   private final double subgraphProcessDegreeQuantile;
   private final int subgraphProcessDegreeMinimum;
   private final int subgraphProcessDegreeMaximum;
   private final int subgraphEdgeFilterBatchSize;

   private LlmConfig(Path sourcePath, Properties properties) {
      this.sourcePath = sourcePath;
      this.provider = require(properties, "llm.provider");
      this.endpoint = require(properties, "llm.endpoint");
      this.apiKey = require(properties, "llm.apiKey");
      this.model = require(properties, "llm.model");
      this.temperature = parseDouble(properties, "llm.temperature");
      this.connectTimeoutMs = parseInt(properties, "llm.connectTimeoutMs");
      this.readTimeoutMs = parseInt(properties, "llm.readTimeoutMs");
      this.entrySelectionMaxEvidencePathsPerCandidate = parsePositiveIntOrDefault(
         properties, "progql.llm.entrySelection.maxEvidencePathsPerCandidate", 3
      );
      this.entrySelectionMaxEvidenceSearchStatesPerPath = parsePositiveIntOrDefault(
         properties, "progql.llm.entrySelection.maxEvidenceSearchStatesPerPath", 3000
      );
      this.noiseEnabled = Boolean.parseBoolean(properties.getProperty("progql.llm.noise.enabled", "true").trim());
      this.noiseMode = parseNoiseMode(properties);
      this.noiseBatchSize = parseIntOrDefault(properties, "progql.llm.noise.batch.size", 60);
      this.noiseSliceSize = this.noiseMode == NoiseMode.SLICE
         ? parsePositiveInt(properties, "progql.llm.noise.slice.size")
         : 0;
      this.noiseRunningSummaryMaxChars = parseIntOrDefault(properties, "progql.llm.noise.runningSummary.maxChars", 2000);
      this.prefilterEnabled = Boolean.parseBoolean(properties.getProperty("progql.llm.prefilter.enabled", "true").trim());
      this.repairAgentEnabled = Boolean.parseBoolean(properties.getProperty("progql.llm.repair.agent.enabled", "false").trim());
      this.repairAgentMaxCycles = parseIntOrDefault(properties, "progql.llm.repair.agent.maxCycles", 2);
      this.repairAgentMaxGaps = parseIntOrDefault(properties, "progql.llm.repair.agent.maxGaps", 3);
      this.repairAgentMaxCandidateEdges = parseIntOrDefault(properties, "progql.llm.repair.agent.maxCandidateEdges", 120);
      this.repairAgentMaxSelectedEdgesPerCycle = parseIntOrDefault(properties, "progql.llm.repair.agent.maxSelectedEdgesPerCycle", 20);
      this.repairAgentUnselectedCandidatePenalty = parseNonNegativeIntOrDefault(
         properties, "progql.llm.repair.agent.unselectedCandidatePenalty", 5
      );
      this.repairAgentGapRetrievalMaxAnchorHops = parsePositiveIntOrDefault(
         properties, "progql.llm.repair.agent.gapRetrieval.maxAnchorHops", 1
      );
      this.subgraphMaxUpstreamDepth = parseNonNegativeIntOrDefault(
         properties, "progql.llm.noise.subgraph.maxUpstreamDepth", 20
      );
      this.subgraphMaxDownstreamDepth = parseNonNegativeIntOrDefault(
         properties, "progql.llm.noise.subgraph.maxDownstreamDepth", 20
      );
      this.subgraphProcessDegreeQuantile = parseDoubleOrDefault(
         properties, "progql.llm.noise.subgraph.processDegree.quantile", 0.95
      );
      if (this.subgraphProcessDegreeQuantile <= 0.0 || this.subgraphProcessDegreeQuantile > 1.0) {
         throw new IllegalStateException("LLM config key must be in (0, 1]: progql.llm.noise.subgraph.processDegree.quantile");
      }
      this.subgraphProcessDegreeMinimum = parseNonNegativeIntOrDefault(
         properties, "progql.llm.noise.subgraph.processDegree.minimum", 1
      );
      this.subgraphProcessDegreeMaximum = parseNonNegativeIntOrDefault(
         properties, "progql.llm.noise.subgraph.processDegree.maximum", 2000
      );
      if (this.subgraphProcessDegreeMinimum > this.subgraphProcessDegreeMaximum) {
         throw new IllegalStateException("LLM config key minimum must not exceed maximum: progql.llm.noise.subgraph.processDegree");
      }
      this.subgraphEdgeFilterBatchSize = parsePositiveIntOrDefault(
         properties, "progql.llm.noise.subgraph.edgeFilter.batchSize", 15
      );
   }

   public static LlmConfig load() {
      return load(resolveConfigPath());
   }

   /** Loads a complete LLM connection configuration from an explicit file. */
   public static LlmConfig load(Path configPath) {
      if (configPath == null || !Files.isRegularFile(configPath)) {
         throw new IllegalStateException("LLM config file not found: " + (configPath == null ? "<null>" : configPath.toAbsolutePath()));
      }
      Properties properties = new Properties();

      try (InputStream inputStream = Files.newInputStream(configPath)) {
         properties.load(inputStream);
      } catch (IOException ex) {
         throw new IllegalStateException("Failed to read LLM config: " + configPath.toAbsolutePath(), ex);
      }

      return new LlmConfig(configPath.toAbsolutePath().normalize(), properties);
   }

   /** Reads optional entry-ranking weights without requiring a complete LLM configuration. */
   public static double[] loadEntryRankingWeightsOrDefault() {
      double impactWeight = DEFAULT_ENTRY_RANKING_IMPACT_WEIGHT;
      double timeWeight = DEFAULT_ENTRY_RANKING_TIME_WEIGHT;
      try {
         Path configPath = resolveConfigPath();
         Properties properties = new Properties();
         try (InputStream inputStream = Files.newInputStream(configPath)) {
            properties.load(inputStream);
         }
         impactWeight = parseOptionalNonNegativeDouble(
            properties, "progql.llm.entrySelection.impactWeight", impactWeight
         );
         timeWeight = parseOptionalNonNegativeDouble(
            properties, "progql.llm.entrySelection.timeWeight", timeWeight
         );
      } catch (Exception ignored) {
         // Ordinary queries must keep working when the optional LLM config is unavailable.
      }

      double total = impactWeight + timeWeight;
      if (!(total > 0.0) || Double.isInfinite(total) || Double.isNaN(total)) {
         return new double[]{DEFAULT_ENTRY_RANKING_IMPACT_WEIGHT, DEFAULT_ENTRY_RANKING_TIME_WEIGHT};
      }
      return new double[]{impactWeight / total, timeWeight / total};
   }

   private static Path resolveConfigPath() {
      String configuredPath = System.getProperty(CONFIG_SYSTEM_PROPERTY);
      Path path;
      if (configuredPath != null && !configuredPath.trim().isEmpty()) {
         path = Paths.get(configuredPath.trim());
      } else {
         path = Paths.get(DEFAULT_CONFIG_FILE);
      }

      if (!Files.isRegularFile(path)) {
         throw new IllegalStateException("LLM config file not found: " + path.toAbsolutePath());
      }

      return path;
   }

   private static String require(Properties properties, String key) {
      String value = properties.getProperty(key);
      if (value == null || value.trim().isEmpty()) {
         throw new IllegalStateException("Missing required LLM config key: " + key);
      }

      return value.trim();
   }

   private static int parseInt(Properties properties, String key) {
      try {
         return Integer.parseInt(require(properties, key));
      } catch (NumberFormatException ex) {
         throw new IllegalStateException("Invalid integer for LLM config key: " + key, ex);
      }
   }

   private static int parseIntOrDefault(Properties properties, String key, int defaultValue) {
      String value = properties.getProperty(key);
      if (value == null || value.trim().isEmpty()) {
         return defaultValue;
      }
      try {
         return Integer.parseInt(value.trim());
      } catch (NumberFormatException ex) {
         throw new IllegalStateException("Invalid integer for LLM config key: " + key, ex);
      }
   }

   private static int parsePositiveIntOrDefault(Properties properties, String key, int defaultValue) {
      int value = parseIntOrDefault(properties, key, defaultValue);
      if (value <= 0) {
         throw new IllegalStateException("LLM config key must be a positive integer: " + key);
      }
      return value;
   }

   private static int parseNonNegativeIntOrDefault(Properties properties, String key, int defaultValue) {
      int value = parseIntOrDefault(properties, key, defaultValue);
      if (value < 0) {
         throw new IllegalStateException("LLM config key must be a non-negative integer: " + key);
      }
      return value;
   }

   private static int parsePositiveInt(Properties properties, String key) {
      int value = parseInt(properties, key);
      if (value <= 0) {
         throw new IllegalStateException("LLM config key must be a positive integer: " + key);
      }
      return value;
   }

   private static NoiseMode parseNoiseMode(Properties properties) {
      String configuredMode = properties.getProperty("progql.llm.noise.mode", NoiseMode.SUBGRAPH.getConfigValue());
      if (configuredMode == null || configuredMode.trim().isEmpty()) {
         configuredMode = NoiseMode.SUBGRAPH.getConfigValue();
      }

      String normalizedMode = configuredMode.trim().toLowerCase();
      for (NoiseMode mode : NoiseMode.values()) {
         if (mode.getConfigValue().equals(normalizedMode)) {
            return mode;
         }
      }

      throw new IllegalStateException(
         "Invalid LLM config key progql.llm.noise.mode: " + configuredMode
            + "; expected subgraph, batch, slice, or one_shot."
      );
   }

   private static double parseDouble(Properties properties, String key) {
      try {
         return Double.parseDouble(require(properties, key));
      } catch (NumberFormatException ex) {
         throw new IllegalStateException("Invalid decimal for LLM config key: " + key, ex);
      }
   }

   public Path getSourcePath() {
      return this.sourcePath;
   }

   public String getProvider() {
      return this.provider;
   }

   public String getEndpoint() {
      return this.endpoint;
   }

   public String getApiKey() {
      return this.apiKey;
   }

   public String getModel() {
      return this.model;
   }

   public double getTemperature() {
      return this.temperature;
   }

   public int getConnectTimeoutMs() {
      return this.connectTimeoutMs;
   }

   public int getReadTimeoutMs() {
      return this.readTimeoutMs;
   }

   public int getEntrySelectionMaxEvidencePathsPerCandidate() {
      return this.entrySelectionMaxEvidencePathsPerCandidate;
   }

   public int getEntrySelectionMaxEvidenceSearchStatesPerPath() {
      return this.entrySelectionMaxEvidenceSearchStatesPerPath;
   }

   public boolean isNoiseEnabled() {
      return this.noiseEnabled;
   }

   public NoiseMode getNoiseMode() {
      return this.noiseMode;
   }

   public int getNoiseBatchSize() {
      return this.noiseBatchSize;
   }

   private static double parseDoubleOrDefault(Properties properties, String key, double defaultValue) {
      String value = properties.getProperty(key);
      if (value == null || value.trim().isEmpty()) return defaultValue;
      try {
         return Double.parseDouble(value.trim());
      } catch (NumberFormatException ex) {
         throw new IllegalStateException("Invalid decimal for LLM config key: " + key, ex);
      }
   }

   private static double parseOptionalNonNegativeDouble(Properties properties, String key, double defaultValue) {
      String value = properties.getProperty(key);
      if (value == null || value.trim().isEmpty()) {
         return defaultValue;
      }
      try {
         double parsed = Double.parseDouble(value.trim());
         if (parsed < 0.0 || Double.isInfinite(parsed) || Double.isNaN(parsed)) {
            return defaultValue;
         }
         return parsed;
      } catch (NumberFormatException ex) {
         return defaultValue;
      }
   }

   public int getNoiseSliceSize() {
      return this.noiseSliceSize;
   }

   public int getNoiseRunningSummaryMaxChars() {
      return this.noiseRunningSummaryMaxChars;
   }

   public boolean isPrefilterEnabled() {
      return this.prefilterEnabled;
   }

   public boolean isRepairAgentEnabled() { return this.repairAgentEnabled; }
   public int getRepairAgentMaxCycles() { return this.repairAgentMaxCycles; }
   public int getRepairAgentMaxGaps() { return this.repairAgentMaxGaps; }
   public int getRepairAgentMaxCandidateEdges() { return this.repairAgentMaxCandidateEdges; }
   public int getRepairAgentMaxSelectedEdgesPerCycle() { return this.repairAgentMaxSelectedEdgesPerCycle; }
   public int getRepairAgentUnselectedCandidatePenalty() { return this.repairAgentUnselectedCandidatePenalty; }
   public int getRepairAgentGapRetrievalMaxAnchorHops() { return this.repairAgentGapRetrievalMaxAnchorHops; }
   public int getSubgraphMaxUpstreamDepth() { return this.subgraphMaxUpstreamDepth; }
   public int getSubgraphMaxDownstreamDepth() { return this.subgraphMaxDownstreamDepth; }
   public double getSubgraphProcessDegreeQuantile() { return this.subgraphProcessDegreeQuantile; }
   public int getSubgraphProcessDegreeMinimum() { return this.subgraphProcessDegreeMinimum; }
   public int getSubgraphProcessDegreeMaximum() { return this.subgraphProcessDegreeMaximum; }
   public int getSubgraphEdgeFilterBatchSize() { return this.subgraphEdgeFilterBatchSize; }
}
