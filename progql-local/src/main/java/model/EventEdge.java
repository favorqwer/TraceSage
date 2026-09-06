package model;

import java.math.BigDecimal;

public class EventEdge {
   private EntityNode source;
   private EntityNode sink;
   public long id;
   public BigDecimal startTime;
   public BigDecimal endTime;
   private String type;
   private String event;
   private long size;
   public double weight;
   public Double timeWeight;
   public Double amountWeight;
   public Double structureWeight;
   private long startns;
   private long endns;
   private String uuid;
   private String host;

   public EventEdge(EntityNode source, EntityNode sink, long edgeid, String optype, long size, long startNs, long endNs, String uuid, String host) {
      this.source = source;
      this.sink = sink;
      this.id = edgeid;
      this.event = optype;
      this.size = size;
      this.startns = startNs;
      this.endns = endNs;
      this.uuid = uuid;
      this.host = host;
      String startNsStr = Long.toString(startNs);
      String endNsStr = Long.toString(endNs);
      this.startTime = startNsStr.equals("0") ? new BigDecimal("0") : new BigDecimal(startNsStr.substring(0, 10) + "." + startNsStr.substring(10));
      this.endTime = endNsStr.equals("0") ? new BigDecimal("0") : new BigDecimal(endNsStr.substring(0, 10) + "." + endNsStr.substring(10));
   }

   public EventEdge(EventEdge edge) {
      this.source = edge.getSource();
      this.sink = edge.getSink();
      this.id = edge.getID();
      this.startTime = edge.getStartTime();
      this.endTime = edge.getEndTime();
      this.type = edge.getType();
      this.event = edge.getEvent();
      this.size = edge.getSize();
      this.weight = edge.weight;
      this.startns = edge.getStartns();
      this.endns = edge.getEndns();
      this.host = edge.getHost();
   }

   public EventEdge(EntityNode source, EntityNode sink) {
      this.source = source;
      this.sink = sink;
   }

   public EventEdge merge(EventEdge e2) {
      this.endTime = e2.endTime;
      this.size = this.size + e2.size;
      this.endns = e2.endns;
      return this;
   }

   public void printInfo() {
   }

   public void setEdgeEvent(String event) {
      this.event = event;
   }

   public long getID() {
      return this.id;
   }

   public EntityNode getSource() {
      return this.source;
   }

   public EntityNode getSink() {
      return this.sink;
   }

   public BigDecimal getStartTime() {
      return this.startTime;
   }

   public BigDecimal getEndTime() {
      return this.endTime;
   }

   public long getStartns() {
      return this.startns;
   }

   public void setStartns(long startns) {
      this.startns = startns;
   }

   public long getEndns() {
      return this.endns;
   }

   public void setEndns(long endns) {
      this.endns = endns;
   }

   BigDecimal[] getInterval() {
      return new BigDecimal[]{this.startTime, this.endTime};
   }

   public String getType() {
      return this.type;
   }

   public String getEvent() {
      return this.event;
   }

   public boolean eventIsNull() {
      return this.event == null;
   }

   public long getSize() {
      return this.size;
   }

   public BigDecimal getDuration() {
      return this.endTime.subtract(this.startTime);
   }

   public String getHost() {
      return this.host;
   }

   public void setHost(String host) {
      this.host = host;
   }

   @Override
   public boolean equals(Object o) {
      if (this == o) {
         return true;
      } else if (!(o instanceof EventEdge)) {
         return false;
      } else {
         EventEdge eventEdge = (EventEdge)o;
         if (this.id != eventEdge.id) {
            return false;
         } else if (!this.source.equals(eventEdge.source)) {
            return false;
         } else if (!this.sink.equals(eventEdge.sink)) {
            return false;
         } else {
            if (!this.startTime.equals(eventEdge.startTime) || !this.endTime.equals(eventEdge.endTime)) {
               return false;
            }
            return this.host == null ? eventEdge.host == null : this.host.equals(eventEdge.host);
         }
      }
   }

   @Override
   public int hashCode() {
      int result = this.source.hashCode();
      result = 31 * result + this.sink.hashCode();
      result = 31 * result + (this.startTime != null ? this.startTime.hashCode() : 0);
      result = 31 * result + (this.endTime != null ? this.endTime.hashCode() : 0);
      return 31 * result + (this.host != null ? this.host.hashCode() : 0);
   }

   @Override
   public String toString() {
      return "EventEdge{source="
         + this.source.getSignature()
         + ", sink="
         + this.sink.getSignature()
         + ", id="
         + this.id
         + ", startTime="
         + this.startTime
         + ", endTime="
         + this.endTime
         + ", type='"
         + this.type
         + '\''
         + ", event='"
         + this.event
         + '\''
         + ", size="
         + this.size
         + '}';
   }
}
