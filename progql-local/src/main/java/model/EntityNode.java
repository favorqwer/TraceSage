package model;

import java.util.Map;

public class EntityNode {
   private long id;
   private FileEntity f;
   private NetworkEntity n;
   private ProcessEntity p;
   private String signature;
   public double reputation;
   Map<String, String> attributes;

   public EntityNode(FileEntity f) {
      this.f = f;
      this.id = f.getUniqID();
      this.n = null;
      this.p = null;
      this.reputation = f.getReputation();
      this.signature = f.getUniqID() + ": " + f.getPath();
   }

   public EntityNode(ProcessEntity p) {
      this.p = p;
      this.f = null;
      this.n = null;
      this.id = p.getUniqID();
      this.reputation = p.getReputation();
      String displayName = p.getExePath();
      if (displayName == null || displayName.isEmpty()) {
         displayName = p.getName();
      }
      if (displayName == null || displayName.isEmpty()) {
         displayName = p.getPid();
      }
      this.signature = p.getUniqID() + ": " + (displayName == null || displayName.isEmpty() ? "[unknown-process]" : displayName);
   }

   public EntityNode(NetworkEntity n) {
      this.n = n;
      this.f = null;
      this.p = null;
      this.id = n.getUniqID();
      this.reputation = n.getReputation();
      this.signature = n.getUniqID() + ": " + n.getDisplaySrcAndDstIP();
   }

   EntityNode(EntityNode e) {
      this.f = e.getF();
      this.n = e.getN();
      this.p = e.getP();
      this.id = e.getId();
      this.signature = e.getSignature();
      this.reputation = e.reputation;
   }

   public EntityNode(EntityNode old, long id) {
      this.f = old.getF();
      this.n = old.getN();
      this.p = old.getP();
      this.id = id;
      this.signature = old.getSignature();
      this.reputation = old.reputation;
   }

   public EntityNode(long id, double reputation, String signature, Map<String, String> attributes) {
      this.id = id;
      this.reputation = reputation;
      this.f = null;
      this.p = null;
      this.n = null;
      this.attributes = attributes;
      this.signature = signature;
   }

   EntityNode(long id, double reputation, String signature) {
      this.id = id;
      this.reputation = reputation;
      this.signature = signature;
      this.f = null;
      this.n = null;
      this.p = null;
   }

   public long getId() {
      return this.id;
   }

   public void setId(long id) {
      this.id = id;
   }

   public FileEntity getF() {
      return this.f;
   }

   public void setF(FileEntity f) {
      this.f = f;
   }

   public NetworkEntity getN() {
      return this.n;
   }

   public void setN(NetworkEntity n) {
      this.n = n;
   }

   public ProcessEntity getP() {
      return this.p;
   }

   public void setP(ProcessEntity p) {
      this.p = p;
   }

   public String getSignature() {
      return this.signature;
   }

   public void setReputation(double r) {
      this.reputation = r;
   }

   public double getReputation() {
      return this.reputation;
   }

   @Override
   public boolean equals(Object o) {
      if (this == o) {
         return true;
      } else if (!(o instanceof EntityNode)) {
         return false;
      } else {
         EntityNode that = (EntityNode)o;
         if (this.id != that.id) {
            return false;
         } else if (this.f != null ? this.f.equals(that.f) : that.f == null) {
            if (this.n != null ? this.n.equals(that.n) : that.n == null) {
               return (this.p != null ? this.p.equals(that.p) : that.p == null) ? this.signature.equals(that.signature) : false;
            } else {
               return false;
            }
         } else {
            return false;
         }
      }
   }

   @Override
   public int hashCode() {
      int result = (int)(this.id ^ this.id >>> 32);
      result = 31 * result + (this.f != null ? this.f.hashCode() : 0);
      result = 31 * result + (this.n != null ? this.n.hashCode() : 0);
      result = 31 * result + (this.p != null ? this.p.hashCode() : 0);
      return 31 * result + (this.signature != null ? this.signature.hashCode() : 0);
   }

   @Override
   public String toString() {
      return this.getId() + " " + this.getSignature();
   }
}
