package cluster

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Clustering and High Availability implementation

// NodeState represents the state of a cluster node
type NodeState string

const (
	NodeStateUnknown   NodeState = "unknown"
	NodeStateJoining   NodeState = "joining"
	NodeStateActive    NodeState = "active"
	NodeStateLeaving   NodeState = "leaving"
	NodeStateSuspected NodeState = "suspected"
	NodeStateDead      NodeState = "dead"
)

// NodeRole represents the role of a node in the cluster
type NodeRole string

const (
	RoleLeader   NodeRole = "leader"
	RoleFollower NodeRole = "follower"
	RoleCandidate NodeRole = "candidate"
)

// Node represents a cluster node
type Node struct {
	ID          uuid.UUID          `json:"id"`
	Name        string             `json:"name"`
	Address     string             `json:"address"`      // host:port
	RPCAddress  string             `json:"rpc_address"`  // RPC endpoint
	HTTPAddress string             `json:"http_address"` // HTTP endpoint
	
	// State
	State       NodeState          `json:"state"`
	Role        NodeRole           `json:"role"`
	
	// Metadata
	Version     string             `json:"version"`
	Datacenter  string             `json:"datacenter,omitempty"`
	Region      string             `json:"region,omitempty"`
	Zone        string             `json:"zone,omitempty"`
	Tags        map[string]string  `json:"tags,omitempty"`
	
	// Capacity
	MaxConnections int             `json:"max_connections"`
	MaxMailboxes   int             `json:"max_mailboxes"`
	Weight         int             `json:"weight"` // For weighted load balancing
	
	// Current load
	Connections    int             `json:"connections"`
	Mailboxes      int             `json:"mailboxes"`
	CPUUsage       float64         `json:"cpu_usage"`
	MemoryUsage    float64         `json:"memory_usage"`
	DiskUsage      float64         `json:"disk_usage"`
	
	// Timing
	JoinedAt       time.Time       `json:"joined_at"`
	LastSeen       time.Time       `json:"last_seen"`
	LastHeartbeat  time.Time       `json:"last_heartbeat"`
}

// ClusterConfig holds cluster configuration
type ClusterConfig struct {
	NodeID         uuid.UUID `json:"node_id"`
	NodeName       string    `json:"node_name"`
	BindAddress    string    `json:"bind_address"`
	AdvertiseAddress string  `json:"advertise_address"`
	RPCPort        int       `json:"rpc_port"`
	HTTPPort       int       `json:"http_port"`
	
	// Discovery
	BootstrapNodes []string  `json:"bootstrap_nodes,omitempty"`
	JoinRetries    int       `json:"join_retries"`
	JoinRetryDelay time.Duration `json:"join_retry_delay"`
	
	// Timing
	HeartbeatInterval time.Duration `json:"heartbeat_interval"`
	FailureTimeout    time.Duration `json:"failure_timeout"`
	DeadTimeout       time.Duration `json:"dead_timeout"`
	
	// Replication
	ReplicationFactor int       `json:"replication_factor"`
	ReadQuorum        int       `json:"read_quorum"`
	WriteQuorum       int       `json:"write_quorum"`
	
	// Metadata
	Datacenter    string            `json:"datacenter,omitempty"`
	Region        string            `json:"region,omitempty"`
	Zone          string            `json:"zone,omitempty"`
	Tags          map[string]string `json:"tags,omitempty"`
}

// DefaultConfig returns default cluster configuration
func DefaultConfig() *ClusterConfig {
	return &ClusterConfig{
		NodeID:            uuid.New(),
		BindAddress:       "0.0.0.0",
		RPCPort:           7946,
		HTTPPort:          7947,
		JoinRetries:       5,
		JoinRetryDelay:    5 * time.Second,
		HeartbeatInterval: 1 * time.Second,
		FailureTimeout:    5 * time.Second,
		DeadTimeout:       30 * time.Second,
		ReplicationFactor: 3,
		ReadQuorum:        2,
		WriteQuorum:       2,
	}
}

// Cluster manages the cluster membership and coordination
type Cluster struct {
	mu            sync.RWMutex
	config        *ClusterConfig
	localNode     *Node
	nodes         map[uuid.UUID]*Node
	
	// Leadership
	leaderID      *uuid.UUID
	term          uint64
	
	// Channels
	shutdownCh    chan struct{}
	membershipCh  chan MembershipEvent
	
	// Components
	gossip        *GossipProtocol
	raft          *RaftConsensus
	router        *Router
	replicator    *Replicator
	
	logger        Logger
}

// MembershipEvent represents a cluster membership change
type MembershipEvent struct {
	Type    string    `json:"type"` // join, leave, fail, update
	Node    *Node     `json:"node"`
	Time    time.Time `json:"time"`
}

// Logger interface
type Logger interface {
	Info(msg string, args ...interface{})
	Error(msg string, args ...interface{})
	Debug(msg string, args ...interface{})
	Warn(msg string, args ...interface{})
}

// NewCluster creates a new cluster instance
func NewCluster(config *ClusterConfig, logger Logger) (*Cluster, error) {
	if config == nil {
		config = DefaultConfig()
	}

	localNode := &Node{
		ID:          config.NodeID,
		Name:        config.NodeName,
		Address:     fmt.Sprintf("%s:%d", config.AdvertiseAddress, config.RPCPort),
		RPCAddress:  fmt.Sprintf("%s:%d", config.AdvertiseAddress, config.RPCPort),
		HTTPAddress: fmt.Sprintf("%s:%d", config.AdvertiseAddress, config.HTTPPort),
		State:       NodeStateJoining,
		Role:        RoleFollower,
		Datacenter:  config.Datacenter,
		Region:      config.Region,
		Zone:        config.Zone,
		Tags:        config.Tags,
		Weight:      100,
		JoinedAt:    time.Now(),
		LastSeen:    time.Now(),
	}

	c := &Cluster{
		config:       config,
		localNode:    localNode,
		nodes:        make(map[uuid.UUID]*Node),
		shutdownCh:   make(chan struct{}),
		membershipCh: make(chan MembershipEvent, 100),
		logger:       logger,
	}

	// Add self to nodes
	c.nodes[localNode.ID] = localNode

	// Initialize gossip protocol
	c.gossip = NewGossipProtocol(c, logger)
	
	// Initialize Raft consensus
	c.raft = NewRaftConsensus(c, logger)
	
	// Initialize router
	c.router = NewRouter(c, logger)
	
	// Initialize replicator
	c.replicator = NewReplicator(c, logger)

	return c, nil
}

// Start starts the cluster
func (c *Cluster) Start() error {
	c.logger.Info("starting cluster node", "id", c.localNode.ID, "name", c.localNode.Name)

	// Start gossip protocol
	if err := c.gossip.Start(); err != nil {
		return fmt.Errorf("failed to start gossip: %w", err)
	}

	// Start Raft consensus
	if err := c.raft.Start(); err != nil {
		return fmt.Errorf("failed to start raft: %w", err)
	}

	// Start router
	if err := c.router.Start(); err != nil {
		return fmt.Errorf("failed to start router: %w", err)
	}

	// Start replicator
	if err := c.replicator.Start(); err != nil {
		return fmt.Errorf("failed to start replicator: %w", err)
	}

	// Join bootstrap nodes if specified
	if len(c.config.BootstrapNodes) > 0 {
		go c.joinBootstrapNodes()
	}

	// Start background goroutines
	go c.heartbeatLoop()
	go c.failureDetectionLoop()

	c.localNode.State = NodeStateActive
	c.logger.Info("cluster node started")
	return nil
}

// Stop stops the cluster
func (c *Cluster) Stop() error {
	c.logger.Info("stopping cluster node")
	
	close(c.shutdownCh)
	
	c.localNode.State = NodeStateLeaving
	
	// Notify other nodes we're leaving
	c.gossip.Broadcast(MembershipEvent{
		Type: "leave",
		Node: c.localNode,
		Time: time.Now(),
	})
	
	// Stop components
	c.replicator.Stop()
	c.router.Stop()
	c.raft.Stop()
	c.gossip.Stop()
	
	return nil
}

// Join joins an existing cluster
func (c *Cluster) Join(addresses []string) error {
	for _, addr := range addresses {
		if err := c.gossip.Join(addr); err != nil {
			c.logger.Warn("failed to join", "address", addr, "error", err)
			continue
		}
		c.logger.Info("joined cluster via", "address", addr)
		return nil
	}
	return fmt.Errorf("failed to join any node")
}

// Leave gracefully leaves the cluster
func (c *Cluster) Leave() error {
	return c.Stop()
}

// Members returns all known cluster members
func (c *Cluster) Members() []*Node {
	c.mu.RLock()
	defer c.mu.RUnlock()

	nodes := make([]*Node, 0, len(c.nodes))
	for _, node := range c.nodes {
		nodes = append(nodes, node)
	}
	return nodes
}

// ActiveMembers returns only active cluster members
func (c *Cluster) ActiveMembers() []*Node {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var nodes []*Node
	for _, node := range c.nodes {
		if node.State == NodeStateActive {
			nodes = append(nodes, node)
		}
	}
	return nodes
}

// LocalNode returns the local node
func (c *Cluster) LocalNode() *Node {
	return c.localNode
}

// Leader returns the current leader node
func (c *Cluster) Leader() *Node {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.leaderID == nil {
		return nil
	}
	return c.nodes[*c.leaderID]
}

// IsLeader returns true if this node is the leader
func (c *Cluster) IsLeader() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.leaderID != nil && *c.leaderID == c.localNode.ID
}

// MembershipEvents returns a channel of membership events
func (c *Cluster) MembershipEvents() <-chan MembershipEvent {
	return c.membershipCh
}

// Internal methods

func (c *Cluster) joinBootstrapNodes() {
	for i := 0; i < c.config.JoinRetries; i++ {
		if err := c.Join(c.config.BootstrapNodes); err == nil {
			return
		}
		time.Sleep(c.config.JoinRetryDelay)
	}
	c.logger.Warn("failed to join bootstrap nodes after retries")
}

func (c *Cluster) heartbeatLoop() {
	ticker := time.NewTicker(c.config.HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.shutdownCh:
			return
		case <-ticker.C:
			c.sendHeartbeat()
		}
	}
}

func (c *Cluster) sendHeartbeat() {
	c.localNode.LastHeartbeat = time.Now()
	c.localNode.LastSeen = time.Now()
	
	// Update load metrics
	c.updateLocalMetrics()
	
	// Broadcast to gossip
	c.gossip.Broadcast(MembershipEvent{
		Type: "heartbeat",
		Node: c.localNode,
		Time: time.Now(),
	})
}

func (c *Cluster) updateLocalMetrics() {
	// Would gather actual metrics here
	// For now, just placeholder values
}

func (c *Cluster) failureDetectionLoop() {
	ticker := time.NewTicker(c.config.HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.shutdownCh:
			return
		case <-ticker.C:
			c.checkNodeHealth()
		}
	}
}

func (c *Cluster) checkNodeHealth() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for id, node := range c.nodes {
		if id == c.localNode.ID {
			continue
		}

		timeSinceHeartbeat := now.Sub(node.LastHeartbeat)
		
		if timeSinceHeartbeat > c.config.DeadTimeout && node.State != NodeStateDead {
			node.State = NodeStateDead
			c.membershipCh <- MembershipEvent{
				Type: "fail",
				Node: node,
				Time: now,
			}
			c.logger.Warn("node marked as dead", "id", node.ID, "name", node.Name)
		} else if timeSinceHeartbeat > c.config.FailureTimeout && node.State == NodeStateActive {
			node.State = NodeStateSuspected
			c.logger.Warn("node suspected failed", "id", node.ID, "name", node.Name)
		}
	}
}

func (c *Cluster) handleMembershipEvent(event MembershipEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()

	switch event.Type {
	case "join":
		c.nodes[event.Node.ID] = event.Node
		c.logger.Info("node joined", "id", event.Node.ID, "name", event.Node.Name)
		
	case "leave":
		if node, ok := c.nodes[event.Node.ID]; ok {
			node.State = NodeStateDead
		}
		c.logger.Info("node left", "id", event.Node.ID, "name", event.Node.Name)
		
	case "heartbeat":
		if node, ok := c.nodes[event.Node.ID]; ok {
			node.LastHeartbeat = event.Time
			node.LastSeen = event.Time
			if node.State == NodeStateSuspected {
				node.State = NodeStateActive
			}
			// Update node metrics
			node.Connections = event.Node.Connections
			node.CPUUsage = event.Node.CPUUsage
			node.MemoryUsage = event.Node.MemoryUsage
		} else {
			// Unknown node, add it
			c.nodes[event.Node.ID] = event.Node
		}
		
	case "update":
		if node, ok := c.nodes[event.Node.ID]; ok {
			node.Tags = event.Node.Tags
			node.Weight = event.Node.Weight
		}
	}
	
	// Forward to membership channel
	select {
	case c.membershipCh <- event:
	default:
	}
}

// GossipProtocol handles gossip-based cluster membership
type GossipProtocol struct {
	cluster  *Cluster
	listener net.Listener
	logger   Logger
	stopCh   chan struct{}
}

// NewGossipProtocol creates a new gossip protocol instance
func NewGossipProtocol(cluster *Cluster, logger Logger) *GossipProtocol {
	return &GossipProtocol{
		cluster: cluster,
		logger:  logger,
		stopCh:  make(chan struct{}),
	}
}

func (g *GossipProtocol) Start() error {
	addr := fmt.Sprintf("%s:%d", g.cluster.config.BindAddress, g.cluster.config.RPCPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	g.listener = listener
	
	go g.acceptLoop()
	return nil
}

func (g *GossipProtocol) Stop() {
	close(g.stopCh)
	if g.listener != nil {
		g.listener.Close()
	}
}

func (g *GossipProtocol) acceptLoop() {
	for {
		select {
		case <-g.stopCh:
			return
		default:
		}
		
		conn, err := g.listener.Accept()
		if err != nil {
			continue
		}
		go g.handleConnection(conn)
	}
}

func (g *GossipProtocol) handleConnection(conn net.Conn) {
	defer conn.Close()
	
	decoder := json.NewDecoder(conn)
	var event MembershipEvent
	if err := decoder.Decode(&event); err != nil {
		return
	}
	
	g.cluster.handleMembershipEvent(event)
}

func (g *GossipProtocol) Join(addr string) error {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	
	// Send join request
	event := MembershipEvent{
		Type: "join",
		Node: g.cluster.localNode,
		Time: time.Now(),
	}
	
	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(event); err != nil {
		return err
	}
	
	// Receive cluster state
	decoder := json.NewDecoder(conn)
	var nodes []*Node
	if err := decoder.Decode(&nodes); err != nil {
		return err
	}
	
	// Add received nodes
	for _, node := range nodes {
		g.cluster.handleMembershipEvent(MembershipEvent{
			Type: "join",
			Node: node,
			Time: time.Now(),
		})
	}
	
	return nil
}

func (g *GossipProtocol) Broadcast(event MembershipEvent) {
	nodes := g.cluster.ActiveMembers()
	
	for _, node := range nodes {
		if node.ID == g.cluster.localNode.ID {
			continue
		}
		go g.sendToNode(node, event)
	}
}

func (g *GossipProtocol) sendToNode(node *Node, event MembershipEvent) {
	conn, err := net.DialTimeout("tcp", node.RPCAddress, 2*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()
	
	encoder := json.NewEncoder(conn)
	encoder.Encode(event)
}

// RaftConsensus handles Raft-based leader election
type RaftConsensus struct {
	cluster    *Cluster
	logger     Logger
	
	// Raft state
	currentTerm uint64
	votedFor    *uuid.UUID
	
	// Timing
	electionTimeout  time.Duration
	heartbeatTimeout time.Duration
	
	stopCh chan struct{}
}

// NewRaftConsensus creates a new Raft consensus instance
func NewRaftConsensus(cluster *Cluster, logger Logger) *RaftConsensus {
	return &RaftConsensus{
		cluster:          cluster,
		logger:           logger,
		electionTimeout:  150 * time.Millisecond,
		heartbeatTimeout: 50 * time.Millisecond,
		stopCh:           make(chan struct{}),
	}
}

func (r *RaftConsensus) Start() error {
	go r.runElectionTimer()
	return nil
}

func (r *RaftConsensus) Stop() {
	close(r.stopCh)
}

func (r *RaftConsensus) runElectionTimer() {
	timeout := r.randomElectionTimeout()
	timer := time.NewTimer(timeout)
	
	for {
		select {
		case <-r.stopCh:
			timer.Stop()
			return
		case <-timer.C:
			if r.cluster.localNode.Role != RoleLeader {
				r.startElection()
			}
			timer.Reset(r.randomElectionTimeout())
		}
	}
}

func (r *RaftConsensus) randomElectionTimeout() time.Duration {
	// Random timeout between 150-300ms
	return r.electionTimeout + time.Duration(time.Now().UnixNano()%150)*time.Millisecond
}

func (r *RaftConsensus) startElection() {
	r.currentTerm++
	r.cluster.localNode.Role = RoleCandidate
	r.votedFor = &r.cluster.localNode.ID
	
	r.logger.Info("starting election", "term", r.currentTerm)
	
	votes := 1 // Vote for self
	nodes := r.cluster.ActiveMembers()
	needed := len(nodes)/2 + 1
	
	// Request votes from other nodes
	voteCh := make(chan bool, len(nodes))
	for _, node := range nodes {
		if node.ID == r.cluster.localNode.ID {
			continue
		}
		go func(n *Node) {
			voteCh <- r.requestVote(n)
		}(node)
	}
	
	// Collect votes with timeout
	timeout := time.After(r.electionTimeout)
	for {
		select {
		case granted := <-voteCh:
			if granted {
				votes++
			}
			if votes >= needed {
				r.becomeLeader()
				return
			}
		case <-timeout:
			r.cluster.localNode.Role = RoleFollower
			return
		}
	}
}

func (r *RaftConsensus) requestVote(node *Node) bool {
	// Would send RPC request to node
	// For now, simplified implementation
	return false
}

func (r *RaftConsensus) becomeLeader() {
	r.logger.Info("became leader", "term", r.currentTerm)
	r.cluster.localNode.Role = RoleLeader
	r.cluster.mu.Lock()
	r.cluster.leaderID = &r.cluster.localNode.ID
	r.cluster.term = r.currentTerm
	r.cluster.mu.Unlock()
	
	// Start sending heartbeats
	go r.leaderHeartbeat()
}

func (r *RaftConsensus) leaderHeartbeat() {
	ticker := time.NewTicker(r.heartbeatTimeout)
	defer ticker.Stop()
	
	for {
		select {
		case <-r.stopCh:
			return
		case <-ticker.C:
			if r.cluster.localNode.Role != RoleLeader {
				return
			}
			// Send heartbeats to followers
			r.cluster.gossip.Broadcast(MembershipEvent{
				Type: "heartbeat",
				Node: r.cluster.localNode,
				Time: time.Now(),
			})
		}
	}
}

// Router handles request routing in the cluster
type Router struct {
	cluster *Cluster
	logger  Logger
	
	// Load balancing
	algorithm string // round-robin, least-connections, weighted
	index     uint64
	
	stopCh chan struct{}
}

// NewRouter creates a new router
func NewRouter(cluster *Cluster, logger Logger) *Router {
	return &Router{
		cluster:   cluster,
		logger:    logger,
		algorithm: "least-connections",
		stopCh:    make(chan struct{}),
	}
}

func (r *Router) Start() error {
	return nil
}

func (r *Router) Stop() {
	close(r.stopCh)
}

// Route returns the best node for a request
func (r *Router) Route(key string) *Node {
	nodes := r.cluster.ActiveMembers()
	if len(nodes) == 0 {
		return nil
	}

	switch r.algorithm {
	case "round-robin":
		return r.roundRobin(nodes)
	case "least-connections":
		return r.leastConnections(nodes)
	case "weighted":
		return r.weighted(nodes)
	case "consistent-hash":
		return r.consistentHash(nodes, key)
	default:
		return r.roundRobin(nodes)
	}
}

func (r *Router) roundRobin(nodes []*Node) *Node {
	r.index++
	return nodes[r.index%uint64(len(nodes))]
}

func (r *Router) leastConnections(nodes []*Node) *Node {
	var best *Node
	minConn := -1
	
	for _, node := range nodes {
		if minConn == -1 || node.Connections < minConn {
			best = node
			minConn = node.Connections
		}
	}
	return best
}

func (r *Router) weighted(nodes []*Node) *Node {
	totalWeight := 0
	for _, node := range nodes {
		totalWeight += node.Weight
	}
	
	if totalWeight == 0 {
		return r.roundRobin(nodes)
	}
	
	random := int(time.Now().UnixNano() % int64(totalWeight))
	for _, node := range nodes {
		random -= node.Weight
		if random < 0 {
			return node
		}
	}
	return nodes[0]
}

func (r *Router) consistentHash(nodes []*Node, key string) *Node {
	// Simple consistent hashing
	hash := 0
	for _, c := range key {
		hash = hash*31 + int(c)
	}
	if hash < 0 {
		hash = -hash
	}
	return nodes[hash%len(nodes)]
}

// RouteMailbox routes to the node that owns a mailbox
func (r *Router) RouteMailbox(mailboxID uuid.UUID) *Node {
	// Use consistent hashing for mailbox routing
	return r.consistentHash(r.cluster.ActiveMembers(), mailboxID.String())
}

// Replicator handles data replication between nodes
type Replicator struct {
	cluster *Cluster
	logger  Logger
	
	// Replication state
	replicationFactor int
	readQuorum        int
	writeQuorum       int
	
	stopCh chan struct{}
}

// NewReplicator creates a new replicator
func NewReplicator(cluster *Cluster, logger Logger) *Replicator {
	return &Replicator{
		cluster:           cluster,
		logger:            logger,
		replicationFactor: cluster.config.ReplicationFactor,
		readQuorum:        cluster.config.ReadQuorum,
		writeQuorum:       cluster.config.WriteQuorum,
		stopCh:            make(chan struct{}),
	}
}

func (r *Replicator) Start() error {
	return nil
}

func (r *Replicator) Stop() {
	close(r.stopCh)
}

// ReplicaNodes returns the nodes that should hold replicas for a key
func (r *Replicator) ReplicaNodes(key string) []*Node {
	nodes := r.cluster.ActiveMembers()
	if len(nodes) <= r.replicationFactor {
		return nodes
	}

	// Use consistent hashing to find primary, then take next N-1 nodes
	primary := r.cluster.router.consistentHash(nodes, key)
	replicas := make([]*Node, 0, r.replicationFactor)
	replicas = append(replicas, primary)
	
	// Find index of primary
	primaryIdx := 0
	for i, n := range nodes {
		if n.ID == primary.ID {
			primaryIdx = i
			break
		}
	}
	
	// Add next nodes in ring
	for i := 1; i < r.replicationFactor && i < len(nodes); i++ {
		idx := (primaryIdx + i) % len(nodes)
		replicas = append(replicas, nodes[idx])
	}
	
	return replicas
}

// Write writes data with replication
func (r *Replicator) Write(ctx context.Context, key string, data []byte) error {
	nodes := r.ReplicaNodes(key)
	successCount := 0
	var lastErr error
	
	// Write to all replica nodes
	for _, node := range nodes {
		if err := r.writeToNode(ctx, node, key, data); err != nil {
			lastErr = err
			r.logger.Warn("failed to write to node", "node", node.Name, "error", err)
		} else {
			successCount++
		}
	}
	
	// Check write quorum
	if successCount < r.writeQuorum {
		return fmt.Errorf("write quorum not met: %d/%d, last error: %v", 
			successCount, r.writeQuorum, lastErr)
	}
	
	return nil
}

func (r *Replicator) writeToNode(ctx context.Context, node *Node, key string, data []byte) error {
	if node.ID == r.cluster.localNode.ID {
		// Local write
		return r.localWrite(key, data)
	}
	
	// Remote write via RPC
	// Would use actual RPC client here
	return nil
}

func (r *Replicator) localWrite(key string, data []byte) error {
	// Would write to local storage
	return nil
}

// Read reads data with quorum
func (r *Replicator) Read(ctx context.Context, key string) ([]byte, error) {
	nodes := r.ReplicaNodes(key)
	resultCh := make(chan []byte, len(nodes))
	errCh := make(chan error, len(nodes))
	
	// Read from all replica nodes
	for _, node := range nodes {
		go func(n *Node) {
			data, err := r.readFromNode(ctx, n, key)
			if err != nil {
				errCh <- err
			} else {
				resultCh <- data
			}
		}(node)
	}
	
	// Wait for quorum
	var results [][]byte
	errorCount := 0
	timeout := time.After(5 * time.Second)
	
	for {
		select {
		case data := <-resultCh:
			results = append(results, data)
			if len(results) >= r.readQuorum {
				// Return most common result (read repair would happen here)
				return results[0], nil
			}
		case <-errCh:
			errorCount++
			if errorCount > len(nodes)-r.readQuorum {
				return nil, fmt.Errorf("read quorum not achievable")
			}
		case <-timeout:
			return nil, fmt.Errorf("read timeout")
		}
	}
}

func (r *Replicator) readFromNode(ctx context.Context, node *Node, key string) ([]byte, error) {
	if node.ID == r.cluster.localNode.ID {
		return r.localRead(key)
	}
	
	// Remote read via RPC
	return nil, nil
}

func (r *Replicator) localRead(key string) ([]byte, error) {
	// Would read from local storage
	return nil, nil
}

// ClusterHandler provides HTTP endpoints for cluster management
type ClusterHandler struct {
	cluster *Cluster
}

// NewClusterHandler creates a new cluster handler
func NewClusterHandler(cluster *Cluster) *ClusterHandler {
	return &ClusterHandler{cluster: cluster}
}

// Mount mounts cluster endpoints
func (h *ClusterHandler) Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /cluster/members", h.handleMembers)
	mux.HandleFunc("GET /cluster/status", h.handleStatus)
	mux.HandleFunc("POST /cluster/join", h.handleJoin)
	mux.HandleFunc("POST /cluster/leave", h.handleLeave)
}

func (h *ClusterHandler) handleMembers(w http.ResponseWriter, r *http.Request) {
	members := h.cluster.Members()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"members": members,
		"count":   len(members),
	})
}

func (h *ClusterHandler) handleStatus(w http.ResponseWriter, r *http.Request) {
	leader := h.cluster.Leader()
	var leaderName string
	if leader != nil {
		leaderName = leader.Name
	}
	
	json.NewEncoder(w).Encode(map[string]interface{}{
		"node":       h.cluster.LocalNode(),
		"leader":     leaderName,
		"is_leader":  h.cluster.IsLeader(),
		"members":    len(h.cluster.Members()),
		"term":       h.cluster.term,
	})
}

func (h *ClusterHandler) handleJoin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Addresses []string `json:"addresses"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	
	if err := h.cluster.Join(req.Addresses); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	
	w.WriteHeader(http.StatusOK)
}

func (h *ClusterHandler) handleLeave(w http.ResponseWriter, r *http.Request) {
	if err := h.cluster.Leave(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// SQLite state storage for persistent cluster state

// SQLiteClusterStore stores cluster state in SQLite
type SQLiteClusterStore struct {
	db *sql.DB
}

// NewSQLiteClusterStore creates a new cluster store
func NewSQLiteClusterStore(db *sql.DB) (*SQLiteClusterStore, error) {
	store := &SQLiteClusterStore{db: db}
	if err := store.migrate(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *SQLiteClusterStore) migrate() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS cluster_nodes (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			address TEXT NOT NULL,
			rpc_address TEXT NOT NULL,
			http_address TEXT NOT NULL,
			state TEXT NOT NULL,
			role TEXT NOT NULL,
			version TEXT,
			datacenter TEXT,
			region TEXT,
			zone TEXT,
			tags TEXT,
			max_connections INTEGER DEFAULT 1000,
			max_mailboxes INTEGER DEFAULT 10000,
			weight INTEGER DEFAULT 100,
			connections INTEGER DEFAULT 0,
			mailboxes INTEGER DEFAULT 0,
			cpu_usage REAL DEFAULT 0,
			memory_usage REAL DEFAULT 0,
			disk_usage REAL DEFAULT 0,
			joined_at DATETIME,
			last_seen DATETIME,
			last_heartbeat DATETIME
		)`,
		
		`CREATE TABLE IF NOT EXISTS cluster_state (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		
		`CREATE TABLE IF NOT EXISTS mailbox_assignments (
			mailbox_id TEXT PRIMARY KEY,
			primary_node TEXT NOT NULL,
			replica_nodes TEXT NOT NULL,
			version INTEGER DEFAULT 0,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		
		`CREATE INDEX IF NOT EXISTS idx_cluster_node_state ON cluster_nodes(state)`,
		`CREATE INDEX IF NOT EXISTS idx_mailbox_primary ON mailbox_assignments(primary_node)`,
	}

	for _, q := range queries {
		if _, err := s.db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

// SaveNode saves a node to the store
func (s *SQLiteClusterStore) SaveNode(ctx context.Context, node *Node) error {
	tagsJSON, _ := json.Marshal(node.Tags)
	
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO cluster_nodes (id, name, address, rpc_address, http_address, state, role, version,
			datacenter, region, zone, tags, max_connections, max_mailboxes, weight, connections,
			mailboxes, cpu_usage, memory_usage, disk_usage, joined_at, last_seen, last_heartbeat)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			state = excluded.state,
			role = excluded.role,
			connections = excluded.connections,
			cpu_usage = excluded.cpu_usage,
			memory_usage = excluded.memory_usage,
			disk_usage = excluded.disk_usage,
			last_seen = excluded.last_seen,
			last_heartbeat = excluded.last_heartbeat`,
		node.ID.String(), node.Name, node.Address, node.RPCAddress, node.HTTPAddress,
		string(node.State), string(node.Role), node.Version, node.Datacenter, node.Region,
		node.Zone, string(tagsJSON), node.MaxConnections, node.MaxMailboxes, node.Weight,
		node.Connections, node.Mailboxes, node.CPUUsage, node.MemoryUsage, node.DiskUsage,
		node.JoinedAt, node.LastSeen, node.LastHeartbeat)

	return err
}

// GetNode retrieves a node from the store
func (s *SQLiteClusterStore) GetNode(ctx context.Context, id uuid.UUID) (*Node, error) {
	var node Node
	var idStr string
	var tagsJSON string
	var state, role string
	
	err := s.db.QueryRowContext(ctx, `
		SELECT id, name, address, rpc_address, http_address, state, role, version,
			datacenter, region, zone, tags, max_connections, max_mailboxes, weight,
			connections, mailboxes, cpu_usage, memory_usage, disk_usage, joined_at,
			last_seen, last_heartbeat
		FROM cluster_nodes WHERE id = ?`, id.String()).Scan(
		&idStr, &node.Name, &node.Address, &node.RPCAddress, &node.HTTPAddress,
		&state, &role, &node.Version, &node.Datacenter, &node.Region, &node.Zone,
		&tagsJSON, &node.MaxConnections, &node.MaxMailboxes, &node.Weight,
		&node.Connections, &node.Mailboxes, &node.CPUUsage, &node.MemoryUsage,
		&node.DiskUsage, &node.JoinedAt, &node.LastSeen, &node.LastHeartbeat)
	if err != nil {
		return nil, err
	}
	
	node.ID, _ = uuid.Parse(idStr)
	node.State = NodeState(state)
	node.Role = NodeRole(role)
	json.Unmarshal([]byte(tagsJSON), &node.Tags)
	
	return &node, nil
}

// ListNodes lists all nodes in the store
func (s *SQLiteClusterStore) ListNodes(ctx context.Context) ([]*Node, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, address, rpc_address, http_address, state, role, version,
			datacenter, region, zone, tags, max_connections, max_mailboxes, weight,
			connections, mailboxes, cpu_usage, memory_usage, disk_usage, joined_at,
			last_seen, last_heartbeat
		FROM cluster_nodes`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var nodes []*Node
	for rows.Next() {
		var node Node
		var idStr string
		var tagsJSON string
		var state, role string
		
		err := rows.Scan(&idStr, &node.Name, &node.Address, &node.RPCAddress, &node.HTTPAddress,
			&state, &role, &node.Version, &node.Datacenter, &node.Region, &node.Zone,
			&tagsJSON, &node.MaxConnections, &node.MaxMailboxes, &node.Weight,
			&node.Connections, &node.Mailboxes, &node.CPUUsage, &node.MemoryUsage,
			&node.DiskUsage, &node.JoinedAt, &node.LastSeen, &node.LastHeartbeat)
		if err != nil {
			return nil, err
		}
		
		node.ID, _ = uuid.Parse(idStr)
		node.State = NodeState(state)
		node.Role = NodeRole(role)
		json.Unmarshal([]byte(tagsJSON), &node.Tags)
		
		nodes = append(nodes, &node)
	}
	
	return nodes, rows.Err()
}

// DeleteNode deletes a node from the store
func (s *SQLiteClusterStore) DeleteNode(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM cluster_nodes WHERE id = ?", id.String())
	return err
}

// SaveMailboxAssignment saves a mailbox assignment
func (s *SQLiteClusterStore) SaveMailboxAssignment(ctx context.Context, mailboxID uuid.UUID, primary uuid.UUID, replicas []uuid.UUID) error {
	var replicaStrs []string
	for _, r := range replicas {
		replicaStrs = append(replicaStrs, r.String())
	}
	replicasJSON, _ := json.Marshal(replicaStrs)
	
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO mailbox_assignments (mailbox_id, primary_node, replica_nodes, version, updated_at)
		VALUES (?, ?, ?, 1, CURRENT_TIMESTAMP)
		ON CONFLICT(mailbox_id) DO UPDATE SET
			primary_node = excluded.primary_node,
			replica_nodes = excluded.replica_nodes,
			version = mailbox_assignments.version + 1,
			updated_at = CURRENT_TIMESTAMP`,
		mailboxID.String(), primary.String(), string(replicasJSON))
	
	return err
}

// GetMailboxAssignment gets a mailbox assignment
func (s *SQLiteClusterStore) GetMailboxAssignment(ctx context.Context, mailboxID uuid.UUID) (primary uuid.UUID, replicas []uuid.UUID, err error) {
	var primaryStr, replicasJSON string
	
	err = s.db.QueryRowContext(ctx,
		"SELECT primary_node, replica_nodes FROM mailbox_assignments WHERE mailbox_id = ?",
		mailboxID.String()).Scan(&primaryStr, &replicasJSON)
	if err != nil {
		return
	}
	
	primary, _ = uuid.Parse(primaryStr)
	
	var replicaStrs []string
	json.Unmarshal([]byte(replicasJSON), &replicaStrs)
	for _, r := range replicaStrs {
		id, _ := uuid.Parse(r)
		replicas = append(replicas, id)
	}
	
	return
}
