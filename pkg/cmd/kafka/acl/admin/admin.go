package admin

import (
	"context"
	"fmt"

	"github.com/redhat-developer/app-services-cli/internal/config"
	"github.com/redhat-developer/app-services-cli/pkg/cmd/factory"
	"github.com/redhat-developer/app-services-cli/pkg/connection"
	"github.com/redhat-developer/app-services-cli/pkg/icon"
	"github.com/redhat-developer/app-services-cli/pkg/iostreams"
	"github.com/redhat-developer/app-services-cli/pkg/kafka/acl"
	"github.com/redhat-developer/app-services-cli/pkg/localize"
	"github.com/redhat-developer/app-services-cli/pkg/logging"
	"github.com/spf13/cobra"

	kafkainstanceclient "github.com/redhat-developer/app-services-sdk-go/kafkainstance/apiv1internal/client"
)

type options struct {
	Config     config.IConfig
	Connection factory.ConnectionFunc
	Logger     logging.Logger
	IO         *iostreams.IOStreams
	localizer  localize.Localizer
	Context    context.Context

	kafkaID     string
	user        string
	svcAccount  string
	allAccounts bool
}

// NewAdminACLCommand creates ACL rule to aloow user to add and delete ACL rules
func NewAdminACLCommand(f *factory.Factory) *cobra.Command {

	opts := &options{
		Config:     f.Config,
		Connection: f.Connection,
		Logger:     f.Logger,
		IO:         f.IOStreams,
		localizer:  f.Localizer,
		Context:    f.Context,
	}

	cmd := &cobra.Command{
		Use:     "admin",
		Short:   f.Localizer.MustLocalize("kafka.acl.admin.cmd.shortDescription"),
		Long:    f.Localizer.MustLocalize("kafka.acl.admin.cmd.longDescription"),
		Example: f.Localizer.MustLocalize("kafka.acl.admin.cmd.example"),
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {

			cfg, err := opts.Config.Load()
			if err != nil {
				return err
			}

			if !cfg.HasKafka() {
				return opts.localizer.MustLocalizeError("kafka.acl.common.error.noKafkaSelected")
			}

			opts.kafkaID = cfg.Services.Kafka.ClusterID

			// check if priincipal is provided
			if opts.user == "" && opts.svcAccount == "" && !opts.allAccounts {
				return opts.localizer.MustLocalizeError("kafka.acl.grantPermissions.error.noPrincipalsSelected")
			}

			// user and service account can't be along with "--all-accounts" flag
			if opts.allAccounts && (opts.svcAccount != "" || opts.user != "") {
				return opts.localizer.MustLocalizeError("kafka.acl.grantPermissions.allPrinciapls.error.notAllowed")
			}

			return runAdmin(opts)
		},
	}

	cmd.Flags().StringVar(&opts.user, "user", "", opts.localizer.MustLocalize("kafka.acl.common.flag.user.description"))
	cmd.Flags().StringVar(&opts.svcAccount, "service-account", "", opts.localizer.MustLocalize("kafka.acl.common.flag.serviceAccount.description"))
	cmd.Flags().BoolVar(&opts.allAccounts, "all-accounts", false, opts.localizer.MustLocalize("kafka.acl.common.flag.allAccounts.description"))

	return cmd
}

func runAdmin(opts *options) (err error) {

	conn, err := opts.Connection(connection.DefaultConfigRequireMasAuth)
	if err != nil {
		return err
	}

	api, kafkaInstance, err := conn.API().KafkaAdmin(opts.kafkaID)
	if err != nil {
		return err
	}

	kafkaName := kafkaInstance.GetName()

	var userArg string

	if opts.user != "" {
		userArg = buildPrincipal(opts.user)
	}

	if opts.svcAccount != "" {
		userArg = buildPrincipal(opts.svcAccount)
	}

	if opts.allAccounts {
		userArg = buildPrincipal(acl.Wildcard)
	}

	req := api.AclsApi.CreateAcl(opts.Context)

	aclBindClusterAlter := *kafkainstanceclient.NewAclBinding(
		kafkainstanceclient.ACLRESOURCETYPE_CLUSTER,
		acl.KafkaCluster,
		kafkainstanceclient.ACLPATTERNTYPE_LITERAL,
		userArg,
		kafkainstanceclient.ACLOPERATION_ALTER,
		kafkainstanceclient.ACLPERMISSIONTYPE_ALLOW,
	)

	req = req.AclBinding(aclBindClusterAlter)

	err = acl.ExecuteACLRuleCreate(req, opts.localizer, kafkaName)
	if err != nil {
		return err
	}

	opts.Logger.Info(icon.SuccessPrefix(), opts.localizer.MustLocalize("kafka.acl.grantPermissions.log.info.aclsCreated", localize.NewEntry("InstanceName", kafkaName)))

	return nil
}

func buildPrincipal(user string) string {
	return fmt.Sprintf("User:%s", user)
}
