package model;

import java.io.Serializable;

public class Entity implements Serializable {
   private double reputation;
   private long id;
   private long timestamp1;
   private long timestamp2;
   private long uniqID;
   private String host;
   private String uuid;

   public Entity(long id, long uniqID) {
      this.id = id;
      this.reputation = 0.0;
      this.uniqID = uniqID;
   }

   public Entity(double reputation, long id, String time1, String time2, long uniqID) {
      this.reputation = reputation;
      this.id = id;
      this.timestamp1 = Long.valueOf(time1);
      this.timestamp2 = Long.valueOf(time2);
      this.uniqID = uniqID;
   }

   public Entity(long uniqID, String host, String uuid) {
      this.uniqID = uniqID;
      this.host = host;
      this.uuid = uuid;
   }

   public double getReputation() {
      return this.reputation;
   }

   public void setReputation(double r) {
      this.reputation = r;
   }

   public long getId() {
      return this.id;
   }

   public void setId(long id) {
      this.id = id;
   }

   public String getTimestamp() {
      return String.valueOf(this.timestamp1) + "." + this.timestamp2;
   }

   public long getUniqID() {
      return this.uniqID;
   }

   public void setUniqID(long uniqID) {
      this.uniqID = uniqID;
   }

   public String getHost() {
      return this.host;
   }

   public void setHost(String host) {
      this.host = host;
   }

   public String getUuid() {
      return this.uuid;
   }

   public void setUuid(String uuid) {
      this.uuid = uuid;
   }
}
