package model;

public class NetworkEntity extends Entity {
   private String srcAddress;
   private String dstAddress;
   private String sPort;
   private String dPort;
   private long uniqID;

   public NetworkEntity(double reputation, long id, String time1, String time2, String srcAddress, String dstAddress, String sPort, String dPort, long uniqID) {
      super(reputation, id, time1, time2, uniqID);
      this.srcAddress = srcAddress;
      this.dstAddress = dstAddress;
      this.sPort = sPort;
      this.dPort = dPort;
      this.uniqID = uniqID;
   }

   public NetworkEntity(String srcAddress, String dstAddress, String sPort, String dPort, long uniqID, String host, String uuid) {
      super(uniqID, host, uuid);
      this.srcAddress = srcAddress;
      this.dstAddress = dstAddress;
      this.sPort = sPort;
      this.dPort = dPort;
      this.uniqID = uniqID;
   }

   public String getSrcAddress() {
      return this.srcAddress;
   }

   public String getDstAddress() {
      return this.dstAddress;
   }

   public String getsPort() {
      return this.sPort;
   }

   public String getdPort() {
      return this.dPort;
   }

   public String getSrcAndDstIP() {
      return this.srcAddress + ":" + this.sPort + "->" + this.dstAddress + ":" + this.dPort;
   }

   public String getDisplaySrcAndDstIP() {
      return stripNetworkPrefix(this.srcAddress) + ":" + this.sPort + "->" + stripNetworkPrefix(this.dstAddress) + ":" + this.dPort;
   }

   private static String stripNetworkPrefix(String address) {
      if (address == null) {
         return "";
      }

      int slashIndex = address.indexOf(47);
      return slashIndex >= 0 ? address.substring(0, slashIndex) : address;
   }

   @Override
   public boolean equals(Object o) {
      if (this == o) {
         return true;
      } else if (!(o instanceof NetworkEntity)) {
         return false;
      } else {
         NetworkEntity that = (NetworkEntity)o;
         return this.uniqID == that.uniqID;
      }
   }

   @Override
   public int hashCode() {
      return Long.hashCode(this.uniqID);
   }
}
