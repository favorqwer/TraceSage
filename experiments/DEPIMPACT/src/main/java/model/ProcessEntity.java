package model;

public class ProcessEntity extends Entity {
   private String pid;
   private String uid;
   private String groupID;
   private String name;
   private String exePath;
   private long startMs;
   private String type;
   private String parentUuid;
   private long uniqID;

   public ProcessEntity(
      double reputation, long id, String pid, String uid, String groupID, String time1, String stime, String name, long uniqID, String exePath
   ) {
      super(reputation, id, time1, stime, uniqID);
      this.pid = pid;
      this.uid = uid;
      this.groupID = groupID;
      this.name = name;
      this.exePath = exePath;
      this.uniqID = uniqID;
   }

   public ProcessEntity(
      String pid,
      String uid,
      String groupID,
      String location,
      String name,
      long uniqID,
      String exePath,
      String host,
      String uuid,
      long startMs,
      String type,
      String parentUuid
   ) {
      super(uniqID, host, uuid);
      this.pid = pid;
      this.uid = uid;
      this.groupID = groupID;
      this.name = name;
      this.exePath = exePath;
      this.startMs = startMs;
      this.type = type;
      this.parentUuid = parentUuid;
      this.uniqID = uniqID;
   }

   public ProcessEntity(long id, String pid, String uid, long uniqID, String exePath) {
      super(id, uniqID);
      if (pid.startsWith("=")) {
         pid = pid.substring(1);
      }

      this.pid = pid;
      this.uid = uid;
      this.groupID = null;
      this.exePath = exePath;
      this.uniqID = uniqID;
   }

   public String getPid() {
      return this.pid;
   }

   public String getUid() {
      return this.uid;
   }

   public String getGroupID() {
      return this.groupID;
   }

   public String getName() {
      return this.name;
   }

   public String getExePath() {
      return this.exePath;
   }

   public String getPidAndName() {
      return this.pid + this.exePath;
   }

   public long getStartMs() {
      return this.startMs;
   }

   public void setStartMs(long startMs) {
      this.startMs = startMs;
   }

   public String getType() {
      return this.type;
   }

   public void setType(String type) {
      this.type = type;
   }

   public String getParentUuid() {
      return this.parentUuid;
   }

   public void setParentUuid(String parentUuid) {
      this.parentUuid = parentUuid;
   }

   @Override
   public boolean equals(Object o) {
      if (this == o) {
         return true;
      } else if (!(o instanceof ProcessEntity)) {
         return false;
      } else {
         ProcessEntity that = (ProcessEntity)o;
         return this.uniqID == that.uniqID;
      }
   }

   @Override
   public int hashCode() {
      return Long.hashCode(this.uniqID);
   }
}
