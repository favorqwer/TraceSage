package util.llm;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Loads deterministic LLM content-filter rules from the repository root. */
final class LlmEdgePrefilterConfig {
   private static final String DEFAULT_CONFIG_FILE = "progql-llm-prefilter.properties";
   private static final Pattern RULE_KEY_PATTERN = Pattern.compile("rule\\.(any|read_only)\\.([1-9][0-9]*)", Pattern.CASE_INSENSITIVE);
   private final List<ContentRule> contentRules;
   private final String status;

   private LlmEdgePrefilterConfig(
      List<ContentRule> contentRules,
      String status
   ) {
      this.contentRules = Collections.unmodifiableList(new ArrayList<>(contentRules));
      this.status = status;
   }

   static LlmEdgePrefilterConfig loadDefault() {
      return load(resolveDefaultConfigPath());
   }

   private static Path resolveDefaultConfigPath() {
      Path current = Paths.get("").toAbsolutePath().normalize();
      while (current != null) {
         Path candidate = current.resolve(DEFAULT_CONFIG_FILE);
         if (Files.isRegularFile(candidate)) {
            return candidate;
         }
         current = current.getParent();
      }
      return Paths.get(DEFAULT_CONFIG_FILE).toAbsolutePath();
   }

   static LlmEdgePrefilterConfig load(Path configPath) {
      if (configPath == null) {
         return disabled("configuration path is null");
      }
      if (!Files.isRegularFile(configPath)) {
         return disabled("configuration file not found: " + configPath.toAbsolutePath());
      }

      Properties properties = new Properties();
      try (InputStream inputStream = Files.newInputStream(configPath)) {
         properties.load(inputStream);
      } catch (IOException ex) {
         return disabled("failed to read " + configPath.toAbsolutePath() + ": " + ex.getMessage());
      }

      try {
         List<ContentRule> rules = parseRules(properties);
         if (rules.isEmpty()) {
            return new LlmEdgePrefilterConfig(
               Collections.<ContentRule>emptyList(),
               "disabled: configuration contains no content rules: " + configPath.toAbsolutePath()
            );
         }
         return new LlmEdgePrefilterConfig(
            rules,
            "enabled(" + rules.size() + " rules)"
         );
      } catch (IllegalArgumentException ex) {
         return disabled("invalid configuration " + configPath.toAbsolutePath() + ": " + ex.getMessage());
      }
   }

   private static List<ContentRule> parseRules(Properties properties) {
      List<ContentRule> rules = new ArrayList<>();
      for (String key : properties.stringPropertyNames()) {
         Matcher matcher = RULE_KEY_PATTERN.matcher(key);
         if (!matcher.matches()) {
            throw new IllegalArgumentException("unsupported property '" + key + "'");
         }
         EventScope scope = EventScope.fromConfigValue(matcher.group(1));
         int order = Integer.parseInt(matcher.group(2));
         String value = properties.getProperty(key);
         String[] parts = value == null ? new String[0] : value.split("\\|", 2);
         if (parts.length != 2 || parts[0].trim().isEmpty() || parts[1].trim().isEmpty()) {
            throw new IllegalArgumentException("rule '" + key + "' must use <exact|prefix|contains|regex>|<pattern>");
         }
         rules.add(new ContentRule(scope, order, MatchType.fromConfigValue(parts[0]), parts[1]));
      }
      rules.sort(Comparator.comparing(ContentRule::getScope).thenComparingInt(ContentRule::getOrder));
      return rules;
   }

   private static LlmEdgePrefilterConfig disabled(String reason) {
      return new LlmEdgePrefilterConfig(
         Collections.<ContentRule>emptyList(),
         "disabled: " + reason
      );
   }

   boolean isContentFilteringEnabled() {
      return !this.contentRules.isEmpty();
   }

   String getStatus() {
      return this.status;
   }

   boolean matches(String event, String sourceValue, String sinkValue) {
      for (ContentRule rule : this.contentRules) {
         if (rule.matches(event, sourceValue) || rule.matches(event, sinkValue)) {
            return true;
         }
      }
      return false;
   }

   private enum EventScope {
      ANY,
      READ_ONLY;

      private static EventScope fromConfigValue(String value) {
         return EventScope.valueOf(value.trim().toUpperCase(Locale.US));
      }
   }

   private enum MatchType {
      EXACT,
      PREFIX,
      CONTAINS,
      REGEX;

      private static MatchType fromConfigValue(String value) {
         return MatchType.valueOf(value.trim().toUpperCase(Locale.US));
      }
   }

   private static final class ContentRule {
      private final EventScope scope;
      private final int order;
      private final MatchType matchType;
      private final String pattern;
      private final Pattern compiledPattern;

      private ContentRule(EventScope scope, int order, MatchType matchType, String pattern) {
         this.scope = scope;
         this.order = order;
         this.matchType = matchType;
         this.pattern = normalize(pattern);
         this.compiledPattern = matchType == MatchType.REGEX
            ? Pattern.compile(this.pattern, Pattern.CASE_INSENSITIVE)
            : null;
      }

      private EventScope getScope() {
         return this.scope;
      }

      private int getOrder() {
         return this.order;
      }

      private boolean matches(String event, String value) {
         if (value.isEmpty() || (this.scope == EventScope.READ_ONLY && !isReadOnlyEvent(event))) {
            return false;
         }
         if (this.matchType == MatchType.EXACT) {
            return value.equals(this.pattern);
         }
         if (this.matchType == MatchType.PREFIX) {
            return value.startsWith(this.pattern);
         }
         if (this.matchType == MatchType.CONTAINS) {
            return value.contains(this.pattern);
         }
         return this.compiledPattern.matcher(value).matches();
      }
   }

   private static String normalize(String value) {
      return value == null ? "" : value.trim().toLowerCase(Locale.US);
   }

   private static boolean isReadOnlyEvent(String event) {
      return "read".equals(event)
         || "readv".equals(event)
         || "pread".equals(event)
         || "pread64".equals(event)
         || "preadv".equals(event)
         || "preadv2".equals(event)
         || "stat".equals(event)
         || "lstat".equals(event)
         || "fstat".equals(event)
         || "fstatat".equals(event)
         || "newfstatat".equals(event)
         || "statx".equals(event)
         || "statfs".equals(event)
         || "statfs64".equals(event)
         || "fstatfs".equals(event)
         || "fstatfs64".equals(event)
         || "access".equals(event)
         || "faccessat".equals(event)
         || "faccessat2".equals(event)
         || "readlink".equals(event)
         || "readlinkat".equals(event)
         || "getdents".equals(event)
         || "getdents64".equals(event)
         || "getxattr".equals(event)
         || "lgetxattr".equals(event)
         || "fgetxattr".equals(event)
         || "listxattr".equals(event)
         || "llistxattr".equals(event)
         || "flistxattr".equals(event);
   }
}
