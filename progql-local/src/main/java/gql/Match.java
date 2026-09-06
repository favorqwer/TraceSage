package gql;

public class Match extends Clause {
   Pattern pattern;
   Where where;

   public Match(Pattern pattern) {
      this.pattern = pattern;
   }

   public Match(Pattern pattern, Where where) {
      this.pattern = pattern;
      this.where = where;
   }

   public Pattern getPattern() {
      return this.pattern;
   }

   public void setPattern(Pattern pattern) {
      this.pattern = pattern;
   }

   public Where getWhere() {
      return this.where;
   }

   public void setWhere(Where where) {
      this.where = where;
   }

   @Override
   public String toString() {
      return this.where != null ? "MATCH " + this.pattern.toString() + " " + this.where.toString() : "MATCH " + this.pattern.toString();
   }
}
