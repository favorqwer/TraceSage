package util;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import model.EntityNode;
import model.EventEdge;

public final class ProcessSubgraph {
   private final EntityNode rootProcess;
   private final Set<EventEdge> ownedEdges;
   private final Set<EventEdge> contextEdges;
   private final Set<Long> upstreamProcessIds;
   private final Set<Long> downstreamProcessIds;
   private final Map<Long, Integer> upstreamProcessDepths;
   private final Map<Long, Integer> downstreamProcessDepths;
   private final Set<String> boundaryReasons;

   ProcessSubgraph(EntityNode rootProcess, Set<EventEdge> ownedEdges, Set<EventEdge> contextEdges, Set<Long> upstreamProcessIds,
      Set<Long> downstreamProcessIds, Map<Long, Integer> upstreamProcessDepths, Map<Long, Integer> downstreamProcessDepths,
      Set<String> boundaryReasons) {
      this.rootProcess = rootProcess;
      this.ownedEdges = Collections.unmodifiableSet(new LinkedHashSet<>(ownedEdges));
      this.contextEdges = Collections.unmodifiableSet(new LinkedHashSet<>(contextEdges));
      this.upstreamProcessIds = Collections.unmodifiableSet(new LinkedHashSet<>(upstreamProcessIds));
      this.downstreamProcessIds = Collections.unmodifiableSet(new LinkedHashSet<>(downstreamProcessIds));
      this.upstreamProcessDepths = Collections.unmodifiableMap(new LinkedHashMap<>(upstreamProcessDepths));
      this.downstreamProcessDepths = Collections.unmodifiableMap(new LinkedHashMap<>(downstreamProcessDepths));
      this.boundaryReasons = Collections.unmodifiableSet(new LinkedHashSet<>(boundaryReasons));
   }

   public EntityNode getRootProcess() { return this.rootProcess; }
   public Set<EventEdge> getOwnedEdges() { return this.ownedEdges; }
   public Set<EventEdge> getContextEdges() { return this.contextEdges; }
   public Set<Long> getUpstreamProcessIds() { return this.upstreamProcessIds; }
   public Set<Long> getDownstreamProcessIds() { return this.downstreamProcessIds; }
   public Map<Long, Integer> getUpstreamProcessDepths() { return this.upstreamProcessDepths; }
   public Map<Long, Integer> getDownstreamProcessDepths() { return this.downstreamProcessDepths; }
   public Set<String> getBoundaryReasons() { return this.boundaryReasons; }
}
