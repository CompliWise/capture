package runtime

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/bluewave-labs/capture/internal/certiwise"
	cwconfig "github.com/bluewave-labs/capture/internal/certiwise/config"
	"github.com/bluewave-labs/capture/internal/certiwise/discovery"
	"github.com/bluewave-labs/capture/internal/certiwise/store"
)

// Start launches the CompliWise control-plane loop when COMPLIWISE_API_URL is configured.
func Start(cfg *cwconfig.Config, agentVersion string) {
	if cfg == nil {
		return
	}

	go func() {
		if err := run(context.Background(), cfg, agentVersion); err != nil {
			log.Printf("certiwise: control plane stopped: %v", err)
		}
	}()
}

func run(ctx context.Context, cfg *cwconfig.Config, agentVersion string) error {
	client, err := certiwise.NewClient(certiwise.ClientConfig{
		BaseURL:            cfg.APIURL,
		AgentToken:         cfg.AgentToken,
		ProxyURL:           cfg.ProxyURL,
		MtlsCertPath:       cfg.MtlsCertPath,
		MtlsKeyPath:        cfg.MtlsKeyPath,
		MtlsCAPath:         cfg.MtlsCAPath,
		APICABundlePath:    cfg.APICABundlePath,
		APIPinSHA256:       cfg.APIPinSHA256,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
	})
	if err != nil {
		return fmt.Errorf("create API client: %w", err)
	}

	hostname, platform := certiwise.HostIdentity()

	if cfg.AgentToken == "" {
		if cfg.EnrollmentCode == "" {
			return fmt.Errorf("COMPLIWISE_AGENT_TOKEN or COMPLIWISE_ENROLLMENT_CODE is required")
		}

		enrollResp, err := client.Enroll(certiwise.EnrollRequest{
			EnrollmentCode: cfg.EnrollmentCode,
			Hostname:       hostname,
			Platform:       platform,
			AgentVersion:   agentVersion,
		})
		if err != nil {
			return fmt.Errorf("enroll agent: %w", err)
		}

		cfg.AgentToken = enrollResp.Token
		if cfg.AgentID == "" {
			cfg.AgentID = enrollResp.AgentID
		}
		if cfg.OrgID == "" {
			cfg.OrgID = enrollResp.OrganizationID
		}
		if enrollResp.PollIntervalSeconds >= 15 {
			cfg.PollInterval = time.Duration(enrollResp.PollIntervalSeconds) * time.Second
		}

		if err := persistAgentEnv(cfg); err != nil {
			log.Printf("certiwise: warning: failed to persist agent env: %v", err)
		}

		log.Printf("certiwise: enrolled agent %s with CompliWise API", cfg.AgentID)
	}

	if err := sendHeartbeat(client, agentVersion, hostname, platform); err != nil {
		log.Printf("certiwise: initial heartbeat failed: %v", err)
	} else {
		log.Printf("certiwise: heartbeat accepted for agent %s", cfg.AgentID)
	}

	tracker := newAssignmentTracker()
	discoveryScheduler := discovery.NewScheduler()

	pull, deploySucceeded, err := syncAssignments(ctx, client, tracker)
	if err != nil {
		log.Printf("certiwise: initial assignment sync failed: %v", err)
	} else if pull != nil {
		if err := discoveryScheduler.RunIfDue(ctx, client, cfg, pull); err != nil {
			log.Printf("certiwise: discovery scan failed: %v", err)
		}
		if deploySucceeded {
			if err := discoveryScheduler.RunPostDeploy(ctx, client, cfg, pull); err != nil {
				log.Printf("certiwise: post-deploy discovery scan failed: %v", err)
			}
		}
	}

	heartbeatTicker := time.NewTicker(cfg.HeartbeatInterval)
	defer heartbeatTicker.Stop()

	pollTicker := time.NewTicker(cfg.PollInterval)
	defer pollTicker.Stop()

	var discoveryTicker *time.Ticker
	var discoveryC <-chan time.Time
	if cfg.DiscoveryEnabled {
		discoveryTicker = time.NewTicker(cfg.DiscoveryInterval)
		defer discoveryTicker.Stop()
		discoveryC = discoveryTicker.C
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-heartbeatTicker.C:
			if err := sendHeartbeat(client, agentVersion, hostname, platform); err != nil {
				log.Printf("certiwise: heartbeat failed: %v", err)
			}
		case <-pollTicker.C:
			pull, deploySucceeded, err := syncAssignments(ctx, client, tracker)
			if err != nil {
				log.Printf("certiwise: assignment sync failed: %v", err)
				continue
			}
			if pull == nil {
				continue
			}
			if err := discoveryScheduler.RunIfDue(ctx, client, cfg, pull); err != nil {
				log.Printf("certiwise: discovery scan failed: %v", err)
			}
			if deploySucceeded {
				if err := discoveryScheduler.RunPostDeploy(ctx, client, cfg, pull); err != nil {
					log.Printf("certiwise: post-deploy discovery scan failed: %v", err)
				}
			}
		case <-discoveryC:
			if discoveryC == nil {
				continue
			}
			pull, err := client.PullAssignments()
			if err != nil {
				log.Printf("certiwise: discovery pull failed: %v", err)
				continue
			}
			if err := discoveryScheduler.RunIfDue(ctx, client, cfg, pull); err != nil {
				log.Printf("certiwise: scheduled discovery scan failed: %v", err)
			}
		}
	}
}

func sendHeartbeat(client *certiwise.Client, agentVersion, hostname, platform string) error {
	resp, err := client.Heartbeat(certiwise.HeartbeatRequest{
		AgentVersion: agentVersion,
		Hostname:     hostname,
		Platform:     platform,
	})
	if err != nil {
		return err
	}

	log.Printf("certiwise: heartbeat status=%s lastHeartbeatAt=%s", resp.Status, resp.LastHeartbeatAt)
	return nil
}

func persistAgentEnv(cfg *cwconfig.Config) error {
	return store.WriteEnvFile(cfg.AgentEnvPath, map[string]string{
		"COMPLIWISE_API_URL":            cfg.APIURL,
		"COMPLIWISE_ORG_ID":             cfg.OrgID,
		"COMPLIWISE_AGENT_ID":           cfg.AgentID,
		"COMPLIWISE_AGENT_TOKEN":        cfg.AgentToken,
		"COMPLIWISE_POLL_INTERVAL":      strconv.Itoa(int(cfg.PollInterval.Seconds())),
		"COMPLIWISE_HEARTBEAT_INTERVAL": strconv.Itoa(int(cfg.HeartbeatInterval.Seconds())),
	})
}
