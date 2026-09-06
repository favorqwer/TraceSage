package gql;

public class LlmClause extends Clause {
   private final int topK;

   public LlmClause(int topK) {
      this.topK = topK;
   }

   public int getTopK() {
      return this.topK;
   }

   @Override
   public String toString() {
      return "LLM TOP " + this.topK;
   }
}
