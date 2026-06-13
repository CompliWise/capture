package handler

import (
	"net/http"

	"github.com/bluewave-labs/capture/internal/certiwise/probe"
	"github.com/gin-gonic/gin"
)

// ProbeHandler exposes operator debug endpoints for CertiWise probes.
type ProbeHandler struct{}

// NewProbeHandler creates a CertiWise probe handler.
func NewProbeHandler() *ProbeHandler {
	return &ProbeHandler{}
}

// TriggerProbe runs all configured TLS probe targets immediately.
func (h *ProbeHandler) TriggerProbe(c *gin.Context) {
	probed, err := probe.TriggerManual(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"message": err.Error()})
		return
	}

	c.JSON(http.StatusAccepted, gin.H{"status": "accepted", "probed": probed})
}
