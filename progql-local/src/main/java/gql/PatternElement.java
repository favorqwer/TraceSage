package gql;

public class PatternElement extends Clause {
   Clause nodePattern;
   Clause patternElementChain;

   public PatternElement(Clause nodePattern) {
      this.nodePattern = nodePattern;
   }

   @Override
   public String toString() {
      return this.nodePattern.toString();
   }
}
