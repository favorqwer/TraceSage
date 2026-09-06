package model;

public class FileEntity extends Entity {
   private String user_ID;
   private String group_ID;
   private String path;
   private long uniqID;

   public FileEntity(double reputation, long id, String time1, String time2, String user_ID, String group_ID, String path, long uniqID) {
      super(reputation, id, time1, time2, uniqID);
      this.user_ID = user_ID;
      this.group_ID = group_ID;
      this.path = path;
      this.uniqID = uniqID;
   }

   public FileEntity(String user_ID, String group_ID, String path, long uniqID, String host, String uuid) {
      super(uniqID, host, uuid);
      this.user_ID = user_ID;
      this.group_ID = group_ID;
      this.path = path;
      this.uniqID = uniqID;
   }

   public String getUser_ID() {
      return this.user_ID;
   }

   public String getGroup_ID() {
      return this.group_ID;
   }

   public String getPath() {
      return this.path;
   }

   @Override
   public boolean equals(Object o) {
      if (this == o) {
         return true;
      } else if (!(o instanceof FileEntity)) {
         return false;
      } else {
         FileEntity that = (FileEntity)o;
         return this.uniqID == that.uniqID;
      }
   }

   @Override
   public int hashCode() {
      return Long.hashCode(this.uniqID);
   }
}
