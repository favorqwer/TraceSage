package gql;

public class WithQuery extends Clause {
   Variable variable;
   Where where;
   Match match;
   BFS bfs;
   Yield yield;
   Return ret;

   public WithQuery(Variable variable, Where where) {
      this.variable = variable;
      this.where = where;
   }

   public WithQuery(Variable variable, Match match, BFS bfs, Yield yield, Return ret) {
      this.variable = variable;
      this.match = match;
      this.bfs = bfs;
      this.yield = yield;
      this.ret = ret;
   }

   public Variable getVariable() {
      return this.variable;
   }

   public void setVariable(Variable variable) {
      this.variable = variable;
   }

   public Match getMatch() {
      return this.match;
   }

   public void setMatch(Match match) {
      this.match = match;
   }

   public BFS getBfs() {
      return this.bfs;
   }

   public void setBfs(BFS bfs) {
      this.bfs = bfs;
   }

   public Yield getYield() {
      return this.yield;
   }

   public void setYield(Yield yield) {
      this.yield = yield;
   }

   public Return getRet() {
      return this.ret;
   }

   public void setRet(Return ret) {
      this.ret = ret;
   }

   public Where getWhere() {
      return this.where;
   }

   public void setWhere(Where where) {
      this.where = where;
   }

   @Override
   public String toString() {
      return this.where != null
         ? "WITH " + this.variable.toString() + " " + this.where.toString()
         : "WITH "
            + this.variable.toString()
            + " = "
            + this.match.toString()
            + (this.bfs != null ? " " + this.bfs.toString() : "")
            + (this.yield != null ? " " + this.yield.toString() : "")
            + (this.ret != null ? " " + this.ret.toString() : "");
   }
}
