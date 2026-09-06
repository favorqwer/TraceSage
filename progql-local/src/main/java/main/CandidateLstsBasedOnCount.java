package main;

import java.util.List;
import model.EntityNode;

class CandidateLstsBasedOnCount {
   List<EntityNode> fileLst;
   List<EntityNode> networkLst;
   List<EntityNode> processLst;

   public CandidateLstsBasedOnCount(List<EntityNode> fileLst, List<EntityNode> networkLst, List<EntityNode> processLst) {
      this.fileLst = fileLst;
      this.networkLst = networkLst;
      this.processLst = processLst;
   }
}
