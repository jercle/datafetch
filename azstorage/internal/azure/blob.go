package azure

import (
	"context"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// blobAPIVersion is the storage REST version the listings ask for.
const blobAPIVersion = "2023-11-03"

// ListOptions is what a container listing includes besides current blobs.
type ListOptions struct {
	Snapshots, Versions, Deleted bool
	// MaxBlobs stops the listing; zero or less is no limit.
	MaxBlobs int64
}

// Tier is the blobs of one access tier.
type Tier struct {
	Bytes, Count int64
}

// ContainerUsage is what a container's blobs add up to.
type ContainerUsage struct {
	CurrentBytes, SnapshotBytes, VersionBytes, DeletedBytes int64
	// Blobs is the current blobs; Objects everything listed.
	Blobs, Objects int64
	Tiers          map[string]Tier
	// Truncated: MaxBlobs was reached, so the sizes are a lower bound.
	Truncated bool
}

// Total is the size of everything listed.
func (u ContainerUsage) Total() int64 {
	return u.CurrentBytes + u.SnapshotBytes + u.VersionBytes + u.DeletedBytes
}

type blobList struct {
	Blobs []struct {
		Snapshot         string `xml:"Snapshot"`
		VersionID        string `xml:"VersionId"`
		IsCurrentVersion string `xml:"IsCurrentVersion"`
		Deleted          string `xml:"Deleted"`
		Size             int64  `xml:"Properties>Content-Length"`
		AccessTier       string `xml:"Properties>AccessTier"`
		ResourceType     string `xml:"Properties>ResourceType"`
	} `xml:"Blobs>Blob"`
	NextMarker string `xml:"NextMarker"`
}

// ContainerUsage lists every blob of a container through the blob endpoint
// and adds up their sizes. The service principal needs Storage Blob Data
// Reader, and the account's network rules must let the collector in.
//
// On an error, what was listed up to then is returned with it.
func (c *Client) ContainerUsage(ctx context.Context, blobEndpoint, container string, o ListOptions) (ContainerUsage, error) {
	u, err := c.listBlobs(ctx, blobEndpoint, container, o)
	var api *APIError
	// Some accounts refuse an include (versions on an account with a
	// hierarchical namespace, for one). Their current blobs can still be
	// measured.
	if errors.As(err, &api) && api.Status == http.StatusBadRequest && (o.Snapshots || o.Versions || o.Deleted) {
		if c.Log != nil {
			c.Log.Debug("listing without snapshots, versions and deleted blobs", "container", container, "error", err.Error())
		}
		return c.listBlobs(ctx, blobEndpoint, container, ListOptions{MaxBlobs: o.MaxBlobs})
	}
	return u, err
}

func (c *Client) listBlobs(ctx context.Context, blobEndpoint, container string, o ListOptions) (ContainerUsage, error) {
	usage := ContainerUsage{Tiers: map[string]Tier{}}
	var include []string
	if o.Snapshots {
		include = append(include, "snapshots")
	}
	if o.Versions {
		include = append(include, "versions")
	}
	if o.Deleted {
		include = append(include, "deleted")
	}
	base := strings.TrimRight(blobEndpoint, "/") + "/" + url.PathEscape(container)
	marker := ""
	for {
		q := url.Values{"restype": {"container"}, "comp": {"list"}, "maxresults": {"5000"}}
		if len(include) > 0 {
			q.Set("include", strings.Join(include, ","))
		}
		if marker != "" {
			q.Set("marker", marker)
		}
		var page blobList
		err := c.send(ctx, call{
			method: http.MethodGet, url: base + "?" + q.Encode(), scope: c.Endpoints.StorageScope,
			header: map[string]string{"x-ms-version": blobAPIVersion, "Accept": "application/xml"},
			client: c.Data, attempts: dataAttempts,
			decode: func(r io.Reader) error { return xml.NewDecoder(r).Decode(&page) },
		})
		if err != nil {
			return usage, err
		}
		for _, b := range page.Blobs {
			// Directories of a hierarchical namespace are listed as blobs.
			if strings.EqualFold(b.ResourceType, "directory") {
				continue
			}
			switch {
			case b.Deleted == "true":
				usage.DeletedBytes += b.Size
			case b.Snapshot != "":
				usage.SnapshotBytes += b.Size
			case b.VersionID != "" && b.IsCurrentVersion != "true":
				usage.VersionBytes += b.Size
			default:
				usage.CurrentBytes += b.Size
				usage.Blobs++
			}
			usage.Objects++
			name := b.AccessTier
			if name == "" {
				name = "None"
			}
			t := usage.Tiers[name]
			t.Bytes += b.Size
			t.Count++
			usage.Tiers[name] = t
		}
		marker = page.NextMarker
		if marker == "" {
			return usage, nil
		}
		if o.MaxBlobs > 0 && usage.Objects >= o.MaxBlobs {
			usage.Truncated = true
			return usage, nil
		}
	}
}
