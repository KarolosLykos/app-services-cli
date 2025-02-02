package addon

import (
	"github.com/redhat-developer/app-services-cli/pkg/cmd/connector/connectorcmdutil"
	"github.com/redhat-developer/app-services-cli/pkg/core/cmdutil/flagutil"
	"github.com/redhat-developer/app-services-cli/pkg/core/ioutil/dump"
	"github.com/redhat-developer/app-services-cli/pkg/shared/connection"
	"github.com/redhat-developer/app-services-cli/pkg/shared/factory"
	connectormgmtclient "github.com/redhat-developer/app-services-sdk-go/connectormgmt/apiv1/client"

	"github.com/spf13/cobra"
)

// row is the details of the addon parameters needed to print to a table
type itemRow struct {
	ID    string `json:"id" header:"ID"`
	Value string `json:"value" header:"Value"`
}

type options struct {
	outputFormat string
	id           string

	f *factory.Factory
}

// NewParametersCommand creates a new command to list addon parameters of a connector cluster
func NewParametersCommand(f *factory.Factory) *cobra.Command {
	opts := &options{
		f: f,
	}

	cmd := &cobra.Command{
		Use:     "addon-parameters",
		Short:   f.Localizer.MustLocalize("connector.cluster.addonParams.cmd.shortDescription"),
		Long:    f.Localizer.MustLocalize("connector.cluster.addonParams.cmd.longDescription"),
		Example: f.Localizer.MustLocalize("connector.cluster.addonParams.cmd.example"),
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.outputFormat != "" && !flagutil.IsValidInput(opts.outputFormat, flagutil.ValidOutputFormats...) {
				return flagutil.InvalidValueError("output", opts.outputFormat, flagutil.ValidOutputFormats...)
			}

			return runList(opts)
		},
	}

	flags := connectorcmdutil.NewFlagSet(cmd, f)

	flags.AddOutput(&opts.outputFormat)
	_ = flags.AddConnectorID(&opts.id).Required()

	return cmd
}

func runList(opts *options) error {
	f := opts.f
	conn, err := f.Connection(connection.DefaultConfigSkipMasAuth)
	if err != nil {
		return err
	}

	api := conn.API()

	a := api.ConnectorsMgmt().ConnectorClustersApi.GetConnectorClusterAddonParameters(f.Context, opts.id)

	response, _, err := a.Execute()
	if err != nil {
		return err
	}

	switch opts.outputFormat {
	case dump.EmptyFormat:
		rows := mapResponseItemsToRows(response)

		dump.Table(f.IOStreams.Out, rows)
		f.Logger.Info("")
		return nil
	default:
		return dump.Formatted(f.IOStreams.Out, opts.outputFormat, response)
	}

}

func mapResponseItemsToRows(items []connectormgmtclient.AddonParameter) []itemRow {
	rows := make([]itemRow, len(items))

	for i := range items {
		k := items[i]

		row := itemRow{
			ID:    k.GetId(),
			Value: k.GetValue(),
		}

		rows[i] = row
	}

	return rows
}
