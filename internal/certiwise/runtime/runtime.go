package runtime

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/bluewave-labs/capture/internal/certiwise"
	cwconfig "github.com/bluewave-labs/capture/internal/certiwise/config"
	"github.com/bluewave-labs/capture/internal/certiwise/connectivity"
	"github.com/bluewave-labs/capture/internal/certiwise/discovery"
	"github.com/bluewave-labs/capture/internal/certiwise/probe"
	"github.com/bluewave-labs/capture/internal/certiwise/synthetic"
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

	hostMetadata := certiwise.CollectHostMetadata()

	if cfg.AgentToken == "" {
		if cfg.EnrollmentCode == "" {
			return fmt.Errorf("COMPLIWISE_AGENT_TOKEN or COMPLIWISE_ENROLLMENT_CODE is required")
		}

		enrollResp, err := client.Enroll(certiwise.EnrollRequest{
			EnrollmentCode: cfg.EnrollmentCode,
			Hostname:       hostMetadata.Hostname,
			Platform:       hostMetadata.Platform,
			AgentVersion:   agentVersion,
			OsPrettyName:   hostMetadata.OsPrettyName,
			OsFamily:       hostMetadata.OsFamily,
			OsPlatform:     hostMetadata.OsPlatform,
			OsVersion:      hostMetadata.OsVersion,
			KernelVersion:  hostMetadata.KernelVersion,
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

	hbState := newHeartbeatState()

	if version, err := sendHeartbeat(client, agentVersion, hbState); err != nil {
		log.Printf("certiwise: initial heartbeat failed: %v", err)
	} else {
		agentVersion = version
		log.Printf("certiwise: heartbeat accepted for agent %s", cfg.AgentID)
	}

	tracker := newAssignmentTracker()
	discoveryScheduler := discovery.NewScheduler()
	connectivityScheduler := connectivity.NewScheduler()
	probeScheduler := probe.NewScheduler()

	var syntheticRunner *synthetic.Runner
	if cfg.SyntheticEnabled {
		syntheticRunner = synthetic.NewRunner(cfg.SyntheticMaxWorkers)
		defer syntheticRunner.StopAll()
		if err := synthetic.SyncMonitors(ctx, client, syntheticRunner, cfg, agentVersion); err != nil {
			log.Printf("certiwise: initial synthetic monitor sync failed: %v", err)
		}
	}

	probe.RegisterManualRunner(func(ctx context.Context) (int, error) {
		pull, err := client.PullAssignments()
		if err != nil {
			return 0, err
		}
		return probeScheduler.RunManual(ctx, client, cfg, pull)
	})

	remoteConfig := &remoteConfigState{}
	heartbeatTicker := newResettableTicker(cfg.HeartbeatInterval)
	defer heartbeatTicker.Stop()

	pollTicker := newResettableTicker(cfg.PollInterval)
	defer pollTicker.Stop()

	pull, succeeded, err := syncAssignments(ctx, client, tracker)
	if err != nil {
		log.Printf("certiwise: initial assignment sync failed: %v", err)
	} else if pull != nil {
		pollChanged, heartbeatChanged := remoteConfig.apply(cfg, pull)
		if pollChanged {
			pollTicker.Reset(cfg.PollInterval)
		}
		if heartbeatChanged {
			heartbeatTicker.Reset(cfg.HeartbeatInterval)
		}
		if err := connectivityScheduler.RunIfRequested(ctx, client, cfg, pull); err != nil {
			log.Printf("certiwise: connectivity test failed: %v", err)
		}
		if err := discoveryScheduler.RunIfDue(ctx, client, cfg, pull); err != nil {
			log.Printf("certiwise: discovery scan failed: %v", err)
		}
		if err := probeScheduler.RunIfDue(ctx, client, cfg, pull); err != nil {
			log.Printf("certiwise: TLS probe failed: %v", err)
		}
		for _, assignment := range succeeded {
			if err := probeScheduler.RunPostDeploy(ctx, client, cfg, assignment); err != nil {
				log.Printf("certiwise: post-deploy TLS probe failed: %v", err)
			}
		}
		if len(succeeded) > 0 {
			if err := discoveryScheduler.RunPostDeploy(ctx, client, cfg, pull); err != nil {
				log.Printf("certiwise: post-deploy discovery scan failed: %v", err)
			}
		}
	}

	var discoveryTicker *time.Ticker
	var discoveryC <-chan time.Time
	if cfg.DiscoveryEnabled {
		discoveryTicker = time.NewTicker(cfg.DiscoveryInterval)
		defer discoveryTicker.Stop()
		discoveryC = discoveryTicker.C
	}

	var probeTicker *time.Ticker
	var probeC <-chan time.Time
	if cfg.ProbeEnabled {
		probeTicker = time.NewTicker(cfg.ProbeInterval)
		defer probeTicker.Stop()
		probeC = probeTicker.C
	}

	var syntheticTicker *time.Ticker
	var syntheticC <-chan time.Time
	if cfg.SyntheticEnabled && syntheticRunner != nil {
		syntheticTicker = time.NewTicker(cfg.SyntheticSyncInterval)
		defer syntheticTicker.Stop()
		syntheticC = syntheticTicker.C
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-heartbeatTicker.C:
			if version, err := sendHeartbeat(client, agentVersion, hbState); err != nil {
				log.Printf("certiwise: heartbeat failed: %v", err)
			} else {
				agentVersion = version
			}
		case <-pollTicker.C:
			pull, succeeded, err := syncAssignments(ctx, client, tracker)
			if err != nil {
				log.Printf("certiwise: assignment sync failed: %v", err)
				continue
			}
			if pull == nil {
				continue
			}
			pollChanged, heartbeatChanged := remoteConfig.apply(cfg, pull)
			if pollChanged {
				pollTicker.Reset(cfg.PollInterval)
			}
			if heartbeatChanged {
				heartbeatTicker.Reset(cfg.HeartbeatInterval)
			}
			if err := connectivityScheduler.RunIfRequested(ctx, client, cfg, pull); err != nil {
				log.Printf("certiwise: connectivity test failed: %v", err)
			}
			if err := discoveryScheduler.RunIfDue(ctx, client, cfg, pull); err != nil {
				log.Printf("certiwise: discovery scan failed: %v", err)
			}
			if err := probeScheduler.RunIfDue(ctx, client, cfg, pull); err != nil {
				log.Printf("certiwise: TLS probe failed: %v", err)
			}
			for _, assignment := range succeeded {
				if err := probeScheduler.RunPostDeploy(ctx, client, cfg, assignment); err != nil {
					log.Printf("certiwise: post-deploy TLS probe failed: %v", err)
				}
			}
			if len(succeeded) > 0 {
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
		case <-probeC:
			if probeC == nil {
				continue
			}
			pull, err := client.PullAssignments()
			if err != nil {
				log.Printf("certiwise: probe pull failed: %v", err)
				continue
			}
			if err := probeScheduler.RunIfDue(ctx, client, cfg, pull); err != nil {
				log.Printf("certiwise: scheduled TLS probe failed: %v", err)
			}
		case <-syntheticC:
			if syntheticC == nil || syntheticRunner == nil {
				continue
			}
			if err := synthetic.SyncMonitors(ctx, client, syntheticRunner, cfg, agentVersion); err != nil {
				log.Printf("certiwise: scheduled synthetic monitor sync failed: %v", err)
			}
		}
	}
}

func sendHeartbeat(client *certiwise.Client, agentVersion string, state *heartbeatState) (string, error) {
	hostMetadata := certiwise.CollectHostMetadata()
	req := certiwise.HeartbeatRequest{
		AgentVersion:  agentVersion,
		Hostname:      hostMetadata.Hostname,
		Platform:      hostMetadata.Platform,
		OsPrettyName:  hostMetadata.OsPrettyName,
		OsFamily:      hostMetadata.OsFamily,
		OsPlatform:    hostMetadata.OsPlatform,
		OsVersion:     hostMetadata.OsVersion,
		KernelVersion: hostMetadata.KernelVersion,
	}
	if state != nil && state.upgradeStatus != "" {
		req.UpgradeStatus = state.upgradeStatus
	}

	resp, err := client.Heartbeat(req)
	if err != nil {
		return agentVersion, err
	}

	if state != nil && resp != nil && resp.Upgrade != nil {
		agentVersion = maybeRunUpgrade(context.Background(), client, hostMetadata.Platform, agentVersion, state, resp)
	}

	log.Printf("certiwise: heartbeat status=%s lastHeartbeatAt=%s", resp.Status, resp.LastHeartbeatAt)
	return agentVersion, nil
}
