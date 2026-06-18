package runtime

import (
	"log"
	"strconv"
	"time"

	"github.com/compliwise/capture/internal/certiwise"
	cwconfig "github.com/compliwise/capture/internal/certiwise/config"
	"github.com/compliwise/capture/internal/certiwise/store"
)

type remoteConfigState struct {
	configEtag string
}

func (s *remoteConfigState) apply(
	cfg *cwconfig.Config,
	pull *certiwise.AssignmentsPullResponse,
) (pollChanged bool, heartbeatChanged bool) {
	if pull == nil || pull.ConfigEtag == "" || pull.ConfigEtag == s.configEtag {
		return false, false
	}

	remote := pull.Config
	nextPoll := time.Duration(remote.PollIntervalSeconds) * time.Second
	nextHeartbeat := time.Duration(remote.HeartbeatIntervalSeconds) * time.Second
	if nextPoll < 15*time.Second {
		nextPoll = 15 * time.Second
	}
	if nextHeartbeat < 15*time.Second {
		nextHeartbeat = 15 * time.Second
	}

	pollChanged = cfg.PollInterval != nextPoll
	heartbeatChanged = cfg.HeartbeatInterval != nextHeartbeat

	cfg.PollInterval = nextPoll
	cfg.HeartbeatInterval = nextHeartbeat
	if remote.TelemetryBatchSize > 0 {
		cfg.TelemetryBatchSize = remote.TelemetryBatchSize
	}
	if remote.TelemetryFlushSeconds > 0 {
		cfg.TelemetryFlushSeconds = remote.TelemetryFlushSeconds
	}

	s.configEtag = pull.ConfigEtag

	if err := persistAgentEnv(cfg); err != nil {
		log.Printf("certiwise: warning: failed to persist remote config: %v", err)
	} else {
		log.Printf(
			"certiwise: applied remote config poll=%ds heartbeat=%ds telemetryBatch=%d telemetryFlush=%ds",
			int(cfg.PollInterval.Seconds()),
			int(cfg.HeartbeatInterval.Seconds()),
			cfg.TelemetryBatchSize,
			cfg.TelemetryFlushSeconds,
		)
	}

	return pollChanged, heartbeatChanged
}

func persistAgentEnv(cfg *cwconfig.Config) error {
	values := map[string]string{
		"COMPLIWISE_API_URL":            cfg.APIURL,
		"COMPLIWISE_ORG_ID":             cfg.OrgID,
		"COMPLIWISE_AGENT_ID":           cfg.AgentID,
		"COMPLIWISE_AGENT_TOKEN":        cfg.AgentToken,
		"COMPLIWISE_POLL_INTERVAL":      strconv.Itoa(int(cfg.PollInterval.Seconds())),
		"COMPLIWISE_HEARTBEAT_INTERVAL": strconv.Itoa(int(cfg.HeartbeatInterval.Seconds())),
	}
	if cfg.TelemetryBatchSize > 0 {
		values["COMPLIWISE_TELEMETRY_BATCH_SIZE"] = strconv.Itoa(cfg.TelemetryBatchSize)
	}
	if cfg.TelemetryFlushSeconds > 0 {
		values["COMPLIWISE_TELEMETRY_FLUSH_SECONDS"] = strconv.Itoa(cfg.TelemetryFlushSeconds)
	}
	return store.WriteEnvFile(cfg.AgentEnvPath, values)
}
