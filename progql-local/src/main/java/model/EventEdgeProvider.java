package model;

import org.jgrapht.ext.ComponentNameProvider;

public class EventEdgeProvider implements ComponentNameProvider<EventEdge> {
   public String getName(EventEdge e) {
      String event = e.getEvent();
      if (event == null || event.trim().isEmpty()) {
         event = "unknown";
      }

      return event + " | " + String.format("%.3f", e.weight);
   }
}
