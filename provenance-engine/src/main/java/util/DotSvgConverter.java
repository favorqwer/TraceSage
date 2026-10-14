package util;

import guru.nidi.graphviz.engine.Format;
import guru.nidi.graphviz.engine.Graphviz;
import guru.nidi.graphviz.engine.GraphvizEngine;
import guru.nidi.graphviz.engine.GraphvizJdkEngine;
import guru.nidi.graphviz.engine.GraphvizV8Engine;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;

public final class DotSvgConverter {
   private static final int SVG_TOTAL_MEMORY_BYTES = 536870912;
   private static final Object ENGINE_LOCK = new Object();
   private static volatile boolean engineConfigured = false;
   private static volatile boolean usingFallbackEngine = false;

   private DotSvgConverter() {
   }

   public static void convert(Path dotPath, Path svgPath) throws IOException {
      configureEngine();

      try {
         Files.createDirectories(svgPath.getParent());
         Graphviz.fromFile(dotPath.toFile()).totalMemory(SVG_TOTAL_MEMORY_BYTES).render(Format.SVG).toFile(svgPath.toFile());
      } catch (RuntimeException e) {
         if (tryFallbackEngine(dotPath, svgPath, e)) {
            return;
         }

         throw new IOException("Failed to render SVG from DOT file: " + dotPath, e);
      }
   }

   private static void configureEngine() {
      if (engineConfigured) {
         return;
      }

      synchronized(ENGINE_LOCK) {
         if (engineConfigured) {
            return;
         }

         GraphvizEngine engine = createEngine();
         Graphviz.useEngine(engine);
         engineConfigured = true;
      }
   }

   private static GraphvizEngine createEngine() {
      String osName = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
      if (osName.contains("win")) {
         return new GraphvizV8Engine();
      }

      return new GraphvizJdkEngine();
   }

   private static boolean tryFallbackEngine(Path dotPath, Path svgPath, RuntimeException originalError) {
      String osName = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
      if (!osName.contains("win")) {
         return false;
      }

      synchronized(ENGINE_LOCK) {
         if (usingFallbackEngine) {
            return false;
         }

         try {
            Graphviz.useEngine(new GraphvizJdkEngine());
            usingFallbackEngine = true;
            Graphviz.fromFile(dotPath.toFile()).totalMemory(SVG_TOTAL_MEMORY_BYTES).render(Format.SVG).toFile(svgPath.toFile());
            return true;
         } catch (IOException | RuntimeException fallbackError) {
            Graphviz.useEngine(new GraphvizV8Engine());
            usingFallbackEngine = false;
            fallbackError.addSuppressed(originalError);
            return false;
         }
      }
   }
}
