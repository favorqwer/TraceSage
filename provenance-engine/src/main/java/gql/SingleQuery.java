package gql;

import java.util.List;

public class SingleQuery extends Clause {
   List<Match> matchLst;
   List<SET> setLst;
   Match match;
   BFS bfs;
   Yield yield;
   Unwind unwind;
   WithQuery withquery;
   Return ret;

   public SingleQuery(Match match, BFS bfs, Yield yield, Return ret) {
      this.match = match;
      this.bfs = bfs;
      this.yield = yield;
      this.ret = ret;
   }

   public SingleQuery(List<Match> matchLst, BFS bfs, Yield yield, Unwind unwind, List<SET> setLst, Return ret) {
      this.matchLst = matchLst;
      this.bfs = bfs;
      this.yield = yield;
      this.unwind = unwind;
      this.setLst = setLst;
      this.ret = ret;
   }

   public SingleQuery(List<Match> matchLst, BFS bfs, Yield yield, Unwind unwind, List<SET> setLst, WithQuery withquery, Return ret) {
      this.matchLst = matchLst;
      this.bfs = bfs;
      this.yield = yield;
      this.unwind = unwind;
      this.setLst = setLst;
      this.withquery = withquery;
      this.ret = ret;
   }

   public List<Match> getMatchLst() {
      return this.matchLst;
   }

   public void setMatchLst(List<Match> matchLst) {
      this.matchLst = matchLst;
   }

   public List<SET> getSetLst() {
      return this.setLst;
   }

   public void setSetLst(List<SET> setLst) {
      this.setLst = setLst;
   }

   public WithQuery getWithquery() {
      return this.withquery;
   }

   public void setWithquery(WithQuery withquery) {
      this.withquery = withquery;
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

   public Unwind getUnwind() {
      return this.unwind;
   }

   public void setUnwind(Unwind unwind) {
      this.unwind = unwind;
   }

   public Return getRet() {
      return this.ret;
   }

   public void setRet(Return ret) {
      this.ret = ret;
   }

   @Override
   public String toString() {
      String s = "";
      if (this.match != null && this.bfs != null && this.setLst == null && this.yield != null && this.unwind == null) {
         s = this.match.toString() + " " + this.bfs.toString() + " " + this.yield.toString() + " " + this.ret.toString();
      }

      if (this.matchLst != null
         && this.setLst != null
         && this.matchLst.size() >= 1
         && this.matchLst.size() == this.setLst.size()
         && this.bfs != null
         && this.yield != null
         && this.unwind != null) {
         int i = 0;

         for (Match match : this.matchLst) {
            if (i == 0) {
               s = match.toString()
                  + " "
                  + this.bfs.toString()
                  + " "
                  + this.yield.toString()
                  + " "
                  + this.unwind.toString()
                  + " "
                  + this.setLst.get(i).toString()
                  + " ";
            } else {
               s = s + match.toString() + " " + this.setLst.get(i).toString() + " ";
            }

            i++;
         }

         s = s + this.ret.toString();
      }

      if (this.matchLst != null
         && this.setLst != null
         && this.matchLst.size() == 1
         && this.matchLst.size() == this.setLst.size()
         && this.bfs != null
         && this.yield != null
         && this.unwind != null
         && this.withquery != null) {
         s = this.matchLst.get(0).toString()
            + " "
            + this.bfs.toString()
            + " "
            + this.yield.toString()
            + " "
            + this.unwind.toString()
            + " "
            + this.setLst.get(0).toString()
            + " "
            + this.withquery.toString()
            + " "
            + this.ret.toString();
      }

      return s;
   }
}
