package aquasec

import (
	"context"
	"fmt"
	"strings"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceHostRuntimePolicyJson() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceHostRuntimePolicyJsonCreate,
		ReadContext:   resourceHostRuntimePolicyJsonRead,
		UpdateContext: resourceHostRuntimePolicyJsonUpdate,
		DeleteContext: resourceHostRuntimePolicyJsonDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Description: "Name of the host runtime policy",
				Required:    true,
				ForceNew:    true,
			},
			"description": {
				Type:        schema.TypeString,
				Description: "The description of the host runtime policy",
				Optional:    true,
			},
			"application_scopes": {
				Type:        schema.TypeList,
				Description: "Indicates the application scope of the service.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional: true,
				Computed: true,
			},
			"scope_expression": {
				Type:        schema.TypeString,
				Description: "Logical expression of how to compute the dependency of the scope variables.",
				Optional:    true,
				Computed:    true,
			},
			"scope_variables": {
				Type:        schema.TypeList,
				Description: "List of scope attributes.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"attribute": {
							Type:        schema.TypeString,
							Description: "Class of supported scope.",
							Required:    true,
						},
						"name": {
							Type:        schema.TypeString,
							Description: "Name assigned to the attribute.",
							Optional:    true,
						},
						"value": {
							Type:        schema.TypeString,
							Description: "Value assigned to the attribute.",
							Required:    true,
						},
					},
				},
				Optional: true,
				Computed: true,
			},
			"enabled": {
				Type:        schema.TypeBool,
				Description: "Indicates if the runtime policy is enabled or not.",
				Default:     true,
				Optional:    true,
			},
			"enforce": {
				Type:        schema.TypeBool,
				Description: "Indicates that policy should effect container execution (not just for audit).",
				Default:     false,
				Optional:    true,
			},
			"enforce_after_days": {
				Type:        schema.TypeInt,
				Description: "Indicates the number of days after which the runtime policy will be changed to enforce mode.",
				Optional:    true,
			},
			"author": {
				Type:        schema.TypeString,
				Description: "Username of the account that created the service.",
				Computed:    true,
				Optional:    true,
			},
			"id": {
				Type:        schema.TypeString,
				Description: "Username of the account that created the service.",
				Computed:    true,
				Optional:    true,
			},
			// controls
			"block_cryptocurrency_mining": {
				Type:        schema.TypeBool,
				Description: "Detect and prevent communication to DNS/IP addresses known to be used for Cryptocurrency Mining",
				Optional:    true,
			},
			"audit_brute_force_login": {
				Type:        schema.TypeBool,
				Description: "Detects brute force login attempts",
				Optional:    true,
			},
			"enable_ip_reputation_security": {
				Type:        schema.TypeBool,
				Description: "If true, detect and prevent communication from containers to IP addresses known to have a bad reputation.",
				Optional:    true,
			},
			"blocked_files": {
				Type:        schema.TypeList,
				Description: "List of files that are prevented from being read, modified and executed in the containers.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional: true,
			},
			"file_integrity_monitoring": {
				Type:        schema.TypeList,
				MaxItems:    1,
				Description: "Configuration for file integrity monitoring.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"monitor_create": {
							Type:         schema.TypeBool,
							Description:  "If true, create operations will be monitored.",
							Optional:     true,
							RequiredWith: []string{"file_integrity_monitoring.0.monitored_paths"},
						},
						"monitor_read": {
							Type:         schema.TypeBool,
							Description:  "If true, read operations will be monitored.",
							Optional:     true,
							RequiredWith: []string{"file_integrity_monitoring.0.monitored_paths"},
						},
						"monitor_modify": {
							Type:         schema.TypeBool,
							Description:  "If true, modification operations will be monitored.",
							Optional:     true,
							RequiredWith: []string{"file_integrity_monitoring.0.monitored_paths"},
						},
						"monitor_delete": {
							Type:         schema.TypeBool,
							Description:  "If true, deletion operations will be monitored.",
							Optional:     true,
							RequiredWith: []string{"file_integrity_monitoring.0.monitored_paths"},
						},
						"monitor_attributes": {
							Type:         schema.TypeBool,
							Description:  "If true, add attributes operations will be monitored.",
							Optional:     true,
							RequiredWith: []string{"file_integrity_monitoring.0.monitored_paths"},
						},
						"monitored_paths": {
							Type:        schema.TypeList,
							Description: "List of paths to be monitored.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
						"excluded_paths": {
							Type:        schema.TypeList,
							Description: "List of paths to be excluded from being monitored.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional:     true,
							RequiredWith: []string{"file_integrity_monitoring.0.monitored_paths"},
						},
						"monitored_processes": {
							Type:        schema.TypeList,
							Description: "List of processes to be monitored.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional:     true,
							RequiredWith: []string{"file_integrity_monitoring.0.monitored_paths"},
						},
						"excluded_processes": {
							Type:        schema.TypeList,
							Description: "List of processes to be excluded from being monitored.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional:     true,
							RequiredWith: []string{"file_integrity_monitoring.0.monitored_paths"},
						},
						"monitored_users": {
							Type:        schema.TypeList,
							Description: "List of users to be monitored.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional:     true,
							RequiredWith: []string{"file_integrity_monitoring.0.monitored_paths"},
						},
						"excluded_users": {
							Type:        schema.TypeList,
							Description: "List of users to be excluded from being monitored.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional:     true,
							RequiredWith: []string{"file_integrity_monitoring.0.monitored_paths"},
						},
					},
				},
				Optional: true,
			},
			"audit_all_os_user_activity": {
				Type:        schema.TypeBool,
				Description: "If true, all process activity will be audited.",
				Optional:    true,
			},
			"audit_full_command_arguments": {
				Type:        schema.TypeBool,
				Description: "If true, full command arguments will be audited.",
				Optional:    true,
			},
			"audit_host_successful_login_events": {
				Type:        schema.TypeBool,
				Description: "If true, host successful logins will be audited.",
				Optional:    true,
			},
			"audit_host_failed_login_events": {
				Type:        schema.TypeBool,
				Description: "If true, host failed logins will be audited.",
				Optional:    true,
			},
			"audit_user_account_management": {
				Type:        schema.TypeBool,
				Description: "If true, account management will be audited.",
				Optional:    true,
			},
			"os_users_allowed": {
				Type:        schema.TypeList,
				Description: "List of OS (Linux or Windows) users that are allowed to authenticate to the host, and block authentication requests from all others.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional: true,
			},
			"os_groups_allowed": {
				Type:        schema.TypeList,
				Description: "List of OS (Linux or Windows) groups that are allowed to authenticate to the host, and block authentication requests from all others. Groups can be either Linux groups or Windows AD groups.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional: true,
			},
			"os_users_blocked": {
				Type:        schema.TypeList,
				Description: "List of OS (Linux or Windows) users that are not allowed to authenticate to the host, and block authentication requests from all others.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional: true,
			},
			"os_groups_blocked": {
				Type:        schema.TypeList,
				Description: "List of OS (Linux or Windows) groups that are not allowed to authenticate to the host, and block authentication requests from all others. Groups can be either Linux groups or Windows AD groups.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional: true,
			},
			"package_block": {
				Type:        schema.TypeList,
				Description: "List of packages that are not allowed read, write or execute all files that under the packages.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional: true,
			},
			"port_scanning_detection": {
				Type:        schema.TypeBool,
				Description: "If true, port scanning behaviors will be audited.",
				Optional:    true,
			},
			"monitor_system_time_changes": {
				Type:        schema.TypeBool,
				Description: "If true, system time changes will be monitored.",
				Optional:    true,
			},
			"monitor_windows_services": {
				Type:        schema.TypeBool,
				Description: "If true, windows service operations will be monitored.",
				Optional:    true,
			},
			"monitor_system_log_integrity": {
				Type:        schema.TypeBool,
				Description: "If true, system log will be monitored.",
				Optional:    true,
			},
			"windows_registry_monitoring": {
				Type:        schema.TypeList,
				MaxItems:    1,
				Description: "Configuration for windows registry monitoring.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"monitor_create": {
							Type:         schema.TypeBool,
							Description:  "If true, create operations will be monitored.",
							Optional:     true,
							RequiredWith: []string{"windows_registry_monitoring.0.monitored_paths"},
						},
						"monitor_read": {
							Type:         schema.TypeBool,
							Description:  "If true, read operations will be monitored.",
							Optional:     true,
							RequiredWith: []string{"windows_registry_monitoring.0.monitored_paths"},
						},
						"monitor_modify": {
							Type:         schema.TypeBool,
							Description:  "If true, modification operations will be monitored.",
							Optional:     true,
							RequiredWith: []string{"windows_registry_monitoring.0.monitored_paths"},
						},
						"monitor_delete": {
							Type:         schema.TypeBool,
							Description:  "If true, deletion operations will be monitored.",
							Optional:     true,
							RequiredWith: []string{"windows_registry_monitoring.0.monitored_paths"},
						},
						"monitor_attributes": {
							Type:         schema.TypeBool,
							Description:  "If true, add attributes operations will be monitored.",
							Optional:     true,
							RequiredWith: []string{"windows_registry_monitoring.0.monitored_paths"},
						},
						"monitored_paths": {
							Type:        schema.TypeList,
							Description: "List of paths to be monitored.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
						"excluded_paths": {
							Type:        schema.TypeList,
							Description: "List of paths to be excluded from being monitored.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional:     true,
							RequiredWith: []string{"windows_registry_monitoring.0.monitored_paths"},
						},
						"monitored_processes": {
							Type:        schema.TypeList,
							Description: "List of registry processes to be monitored.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional:     true,
							RequiredWith: []string{"windows_registry_monitoring.0.monitored_paths"},
						},
						"excluded_processes": {
							Type:        schema.TypeList,
							Description: "List of registry processes to be excluded from being monitored.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional:     true,
							RequiredWith: []string{"windows_registry_monitoring.0.monitored_paths"},
						},
						"monitored_users": {
							Type:        schema.TypeList,
							Description: "List of registry users to be monitored.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional:     true,
							RequiredWith: []string{"windows_registry_monitoring.0.monitored_paths"},
						},
						"excluded_users": {
							Type:        schema.TypeList,
							Description: "List of registry users to be excluded from being monitored.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional:     true,
							RequiredWith: []string{"windows_registry_monitoring.0.monitored_paths"},
						},
					},
				},
				Optional: true,
			},
			"windows_registry_protection": {
				Type:        schema.TypeList,
				MaxItems:    1,
				Description: "Configuration for windows registry protection.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"protected_paths": {
							Type:        schema.TypeList,
							Description: "List of registry paths to be protected.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
						"excluded_paths": {
							Type:        schema.TypeList,
							Description: "List of registry paths to be excluded from being protected.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional:     true,
							RequiredWith: []string{"windows_registry_protection.0.protected_paths"},
						},
						"protected_processes": {
							Type:        schema.TypeList,
							Description: "List of registry processes to be protected.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional:     true,
							RequiredWith: []string{"windows_registry_protection.0.protected_paths"},
						},
						"excluded_processes": {
							Type:        schema.TypeList,
							Description: "List of registry processes to be excluded from being protected.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional:     true,
							RequiredWith: []string{"windows_registry_protection.0.protected_paths"},
						},
						"protected_users": {
							Type:        schema.TypeList,
							Description: "List of registry users to be protected.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional:     true,
							RequiredWith: []string{"windows_registry_protection.0.protected_paths"},
						},
						"excluded_users": {
							Type:        schema.TypeList,
							Description: "List of registry paths to be users from being protected.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional:     true,
							RequiredWith: []string{"windows_registry_protection.0.protected_paths"},
						},
					},
				},
				Optional: true,
			},
			"malware_scan_options": {
				Type:        schema.TypeList,
				MaxItems:    1,
				Description: "Configuration for Real-Time Malware Protection.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"enabled": {
							Type:        schema.TypeBool,
							Description: "Defines if enabled or not",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
						"action": {
							Type:        schema.TypeString,
							Description: "Set Action, Defaults to 'Alert' when empty",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
						"exclude_directories": {
							Type:        schema.TypeList,
							Description: "List of registry paths to be excluded from being protected.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
						"exclude_processes": {
							Type:        schema.TypeList,
							Description: "List of registry processes to be excluded from being protected.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
					},
				},
				Optional: true,
			},
			// added for JSON
			"assurance_type": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"lastupdate": {
				Type:        schema.TypeString,
				Description: "Indicates if the cvss severity is scanned.",
				Optional:    true,
			},
			"custom_severity_enabled": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"cvss_severity": {
				Type:        schema.TypeString,
				Description: "Identifier of the cvss severity.",
				Optional:    true,
			},
			"custom_severity": {
				Type:        schema.TypeString,
				Description: "Identifier of the cvss severity.",
				Optional:    true,
			},
			"vulnerability_exploitability": {
				Type:        schema.TypeBool,
				Description: "Indicates if the cvss severity is scanned.",
				Optional:    true,
			},
			"disallow_exploit_types": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"cvss_severity_exclude_no_fix": {
				Type:        schema.TypeBool,
				Description: "Indicates that policy should ignore cvss cases that do not have a known fix.",
				Optional:    true,
			},
			"maximum_score_enabled": {
				Type:        schema.TypeBool,
				Description: "Indicates if exceeding the maximum score is scanned.",
				Optional:    true,
			},
			"maximum_score": {
				Type:        schema.TypeFloat,
				Description: "Value of allowed maximum score.",
				Optional:    true,
			},
			"maximum_score_exclude_no_fix": {
				Type:        schema.TypeBool,
				Description: "Indicates that policy should ignore cases that do not have a known fix.",
				Optional:    true,
			},
			"custom_checks_enabled": {
				Type:        schema.TypeBool,
				Description: "Indicates if scanning should include custom checks.",
				Optional:    true,
			},
			"scap_enabled": {
				Type:        schema.TypeBool,
				Description: "Indicates if scanning should include scap.",
				Optional:    true,
			},
			"cves_black_list_enabled": {
				Type:        schema.TypeBool,
				Description: "Indicates if cves blacklist is relevant.",
				Optional:    true,
			},
			"cves_white_list_enabled": {
				Type:        schema.TypeBool,
				Description: "Indicates if cves blacklist is relevant.",
				Optional:    true,
			},
			"packages_black_list_enabled": {
				Type:        schema.TypeBool,
				Description: "Indicates if packages blacklist is relevant.",
				Optional:    true,
			},
			"packages_white_list_enabled": {
				Type:        schema.TypeBool,
				Description: "Indicates if packages whitelist is relevant.",
				Optional:    true,
			},
			"cvss_severity_enabled": {
				Type:        schema.TypeBool,
				Description: "Indicates if the cvss severity is scanned.",
				Optional:    true,
			},
			"only_none_root_users": {
				Type:        schema.TypeBool,
				Description: "Indicates if raise a warning for images that should only be run as root.",
				Optional:    true,
			},
			"trusted_base_images_enabled": {
				Type:        schema.TypeBool,
				Description: "Indicates if list of trusted base images is relevant.",
				Optional:    true,
			},
			"scan_sensitive_data": {
				Type:        schema.TypeBool,
				Description: "Indicates if scan should include sensitive data in the image.",
				Optional:    true,
			},
			"audit_on_failure": {
				Type:        schema.TypeBool,
				Description: "Indicates if auditing for failures.",
				Optional:    true,
				Default:     true,
			},
			"fail_cicd": {
				Type:        schema.TypeBool,
				Description: "Indicates if cicd failures will fail the image.",
				Optional:    true,
				Default:     true,
			},
			"block_failed": {
				Type:        schema.TypeBool,
				Description: "Indicates if failed images are blocked.",
				Optional:    true,
				Default:     true,
			},
			"blacklisted_licenses_enabled": {
				Type:        schema.TypeBool,
				Description: "Lndicates if license blacklist is relevant.",
				Optional:    true,
			},
			"blacklisted_licenses": {
				Type:        schema.TypeList,
				Description: "List of blacklisted licenses.",
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"whitelisted_licenses_enabled": {
				Type:        schema.TypeBool,
				Description: "Indicates if license blacklist is relevant.",
				Optional:    true,
			},
			"whitelisted_licenses": {
				Type:        schema.TypeList,
				Description: "List of whitelisted licenses.",
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"custom_checks": {
				Type:        schema.TypeList,
				Description: "List of Custom user scripts for checks.",
				Optional:    true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"script_id": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"name": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"path": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"last_modified": {
							Type:     schema.TypeInt,
							Optional: true,
						},
						"description": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"engine": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"snippet": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"read_only": {
							Type:     schema.TypeBool,
							Optional: true,
						},
						"severity": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"author": {
							Type:        schema.TypeString,
							Description: "Name of user account that created the policy.",
							Optional:    true,
						},
					},
				},
			},
			"scap_files": {
				Type:        schema.TypeList,
				Description: "List of SCAP user scripts for checks.",
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"scope": {
				Type:     schema.TypeSet,
				Optional: true,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"expression": {
							Type:     schema.TypeString,
							Optional: true,
							Computed: true,
						},
						"variables": {
							Type:     schema.TypeList,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"attribute": {
										Type:     schema.TypeString,
										Optional: true,
										Computed: true,
									},
									"value": {
										Type:     schema.TypeString,
										Optional: true,
										Computed: true,
									},
									"name": {
										Type:     schema.TypeString,
										Optional: true,
									},
								},
							},
						},
					},
				},
			},
			"registries": {
				Type:        schema.TypeList,
				Description: "List of registries.",
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"labels": {
				Type:        schema.TypeList,
				Description: "List of labels.",
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"images": {
				Type:        schema.TypeList,
				Description: "List of images.",
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"cves_black_list": {
				Type:        schema.TypeList,
				Description: "List of cves blacklisted items.",
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"packages_black_list": {
				Type:        schema.TypeSet,
				Description: "List of backlisted images.",
				Optional:    true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"format": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"name": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"epoch": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"version": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"version_range": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"release": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"arch": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"license": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"display": {
							Type:     schema.TypeString,
							Optional: true,
						},
					},
				},
			},
			"packages_white_list": {
				Type:        schema.TypeSet,
				Description: "List of whitelisted images.",
				Optional:    true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"format": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"name": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"epoch": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"version": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"version_range": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"release": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"arch": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"license": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"display": {
							Type:     schema.TypeString,
							Optional: true,
						},
					},
				},
			},
			"allowed_images": {
				Type:        schema.TypeList,
				Description: "List of explicitly allowed images.",
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"trusted_base_images": {
				Type:        schema.TypeSet,
				Description: "List of trusted images.",
				Optional:    true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"registry": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"imagename": {
							Type:     schema.TypeString,
							Optional: true,
						},
					},
				},
			},
			"read_only": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"force_microenforcer": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"cves_white_list": {
				Type:        schema.TypeList,
				Description: "List of cves whitelisted licenses",
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"partial_results_image_fail": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"control_exclude_no_fix": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"ignore_recently_published_vln": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"ignore_recently_published_vln_period": {
				Type:     schema.TypeInt,
				Optional: true,
			},
			"ignore_risk_resources_enabled": {
				Type:        schema.TypeBool,
				Description: "Indicates if risk resources are ignored.",
				Optional:    true,
			},
			"ignore_base_image_vln": {
				Type:        schema.TypeBool,
				Description: "Lndicates if license blacklist is relevant.",
				Optional:    true,
			},
			"ignored_risk_resources": {
				Type:        schema.TypeList,
				Description: "List of ignored risk resources.",
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"ignored_sensitive_resources": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"permission": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"dta_severity": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"dta_enabled": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"disallow_malware": {
				Type:        schema.TypeBool,
				Description: "Indicates if malware should block the image.",
				Optional:    true,
			},
			"monitored_malware_paths": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"exceptional_monitored_malware_paths": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"scan_malware_in_archives": {
				Type:        schema.TypeBool,
				Description: "Indicates if the linux cis is enabled.",
				Optional:    true,
			},
			"malware_action": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"scan_nfs_mounts": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"required_labels_enabled": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"required_labels": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"key": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"value": {
							Type:     schema.TypeString,
							Optional: true,
						},
					},
				},
			},
			"kubernetes_controls_avd_ids": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"kubernetes_controls_names": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"kubernetes_controls": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"forbidden_labels_enabled": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"forbidden_labels": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"key": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"value": {
							Type:     schema.TypeString,
							Optional: true,
						},
					},
				},
			},
			"scan_process_memory": {
				Type:        schema.TypeBool,
				Description: "Indicates if the openshift hardening is enabled.",
				Optional:    true,
			},
			"scan_windows_registry": {
				Type:        schema.TypeBool,
				Description: "Indicates if the openshift hardening is enabled.",
				Optional:    true,
			},
			"policy_settings": {
				Type:     schema.TypeMap,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"exclude_application_scopes": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"docker_cis_enabled": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"kube_cis_enabled": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"enforce_excessive_permissions": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"blacklist_permissions_enabled": {
				Type:        schema.TypeBool,
				Description: "Indicates if blacklist permissions is relevant.",
				Optional:    true,
			},
			"blacklist_permissions": {
				Type:        schema.TypeList,
				Description: "List of function's forbidden permissions.",
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"linux_cis_enabled": {
				Type:        schema.TypeBool,
				Description: "Indicates if the linux cis is enabled.",
				Optional:    true,
			},
			"openshift_hardening_enabled": {
				Type:        schema.TypeBool,
				Description: "Indicates if the openshift hardening is enabled.",
				Optional:    true,
			},
			"function_integrity_enabled": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"auto_scan_enabled": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"auto_scan_configured": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"auto_scan_time": {
				Type:     schema.TypeSet,
				Optional: true,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"iteration_type": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"time": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"iteration": {
							Type:     schema.TypeInt,
							Optional: true,
							Computed: true,
						},
						"week_days": {
							Type:     schema.TypeList,
							Optional: true,
							Computed: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
					},
				},
			},
			"aggregated_vulnerability": {
				Type:     schema.TypeMap,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeInt,
				},
			},
			"vulnerability_score_range": {
				Type:     schema.TypeList,
				Optional: true,
				MinItems: 2,
				MaxItems: 2,
				Elem: &schema.Schema{
					Type: schema.TypeInt,
				},
			},
		},
	}
}

func resourceHostRuntimePolicyJsonCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)
	name := d.Get("name").(string)

	crp := expandHostRuntimePolicyJson(d)
	err := c.CreateRuntimePolicy(crp)
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId(name)
	return resourceHostRuntimePolicyJsonRead(ctx, d, m)

}

func resourceHostRuntimePolicyJsonRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)

	crp, err := c.GetRuntimePolicy(d.Id())

	if err != nil {
		if strings.Contains(fmt.Sprintf("%s", err), "404") {
			d.SetId("")
			return nil
		}
		return diag.FromErr(err)
	}

	d.Set("name", crp.Name)
	d.Set("description", crp.Description)
	d.Set("application_scopes", crp.ApplicationScopes)
	d.Set("scope_expression", crp.Scope.Expression)
	d.Set("scope_variables", flattenScopeVariables(crp.Scope.Variables))
	d.Set("enabled", crp.Enabled)
	d.Set("enforce", crp.Enforce)
	d.Set("enforce_after_days", crp.EnforceAfterDays)
	d.Set("author", crp.Author)
	d.Set("block_cryptocurrency_mining", crp.EnableCryptoMiningDns)
	d.Set("audit_brute_force_login", crp.AuditBruteForceLogin)
	d.Set("enable_ip_reputation_security", crp.EnableIPReputation)
	d.Set("blocked_files", crp.FileBlock.FilenameBlockList)
	d.Set("file_integrity_monitoring", flattenFileIntegrityMonitoring(crp.FileIntegrityMonitoring))
	d.Set("audit_all_os_user_activity", crp.Auditing.AuditOsUserActivity)
	d.Set("audit_full_command_arguments", crp.Auditing.AuditProcessCmdline)
	d.Set("audit_host_successful_login_events", crp.Auditing.AuditSuccessLogin)
	d.Set("audit_host_failed_login_events", crp.Auditing.AuditFailedLogin)
	d.Set("os_users_allowed", crp.WhitelistedOsUsers.UserWhiteList)
	d.Set("os_groups_allowed", crp.WhitelistedOsUsers.GroupWhiteList)
	d.Set("os_users_blocked", crp.BlacklistedOsUsers.UserBlackList)
	d.Set("os_groups_blocked", crp.BlacklistedOsUsers.GroupBlackList)
	d.Set("malware_scan_options", flattenMalwareScanOptions(crp.MalwareScanOptions))
	d.Set("monitor_system_time_changes", crp.SystemIntegrityProtection.AuditSystemtimeChange)
	d.Set("monitor_windows_services", crp.SystemIntegrityProtection.WindowsServicesMonitoring)
	d.Set("windows_registry_monitoring", flattenWindowsRegistryMonitoring(crp.RegistryAccessMonitoring))
	d.Set("windows_registry_protection", flattenWindowsRegistryProtection(crp.ReadonlyRegistry))
	// JSON added
	d.Set("auto_scan_time", flattenAutoScanTime(crp.AutoScanTime))
	d.Set("auto_scan_configured", crp.AutoScanConfigured)
	d.Set("auto_scan_enabled", crp.AutoScanEnabled)
	d.Set("function_integrity_enabled", crp.FunctionIntegrityEnabled)
	d.Set("blacklist_permissions_enabled", crp.BlacklistPermissionsEnabled)
	d.Set("blacklist_permissions", crp.BlacklistPermissions)
	d.Set("enforce_excessive_permissions", crp.EnforceExcessivePermissions)
	d.Set("kube_cis_enabled", crp.KubeCisEnabled)
	d.Set("docker_cis_enabled", crp.KubeCisEnabled)
	d.Set("forbidden_labels_enabled", crp.ForbiddenLabelsEnabled)
	d.Set("forbidden_labels", flattenLabels(crp.ForbiddenLabels))
	d.Set("required_labels_enabled", crp.RequiredLabelsEnabled)
	d.Set("required_labels", flattenLabels(crp.RequiredLabels))
	d.Set("scan_nfs_mounts", crp.ScanNfsMounts)
	d.Set("malware_action", crp.MalwareAction)
	d.Set("exceptional_monitored_malware_paths", crp.ExceptionalMonitoredMalwarePaths)
	d.Set("monitored_malware_paths", crp.MonitoredMalwarePaths)
	d.Set("disallow_malware", crp.DisallowMalware)
	d.Set("dta_enabled", crp.DtaEnabled)
	d.Set("dta_severity", crp.DtaSeverity)
	d.Set("ignored_risk_resources", crp.IgnoredRiskResources)
	d.Set("ignore_risk_resources_enabled", crp.IgnoreRiskResourcesEnabled)
	d.Set("ignore_recently_published_vln_period", crp.IgnoreRecentlyPublishedVlnPeriod)
	d.Set("ignore_recently_published_vln_period", crp.IgnoreRecentlyPublishedVlnPeriod)
	d.Set("control_exclude_no_fix", crp.ControlExcludeNoFix)
	d.Set("cves_white_list_enabled", crp.CvesWhiteListEnabled)
	d.Set("cves_white_list", crp.CvesWhiteList)
	d.Set("force_microenforcer", crp.ForceMicroenforcer)
	d.Set("read_only", crp.ReadOnly)
	d.Set("trusted_base_images", flattenTrustedBaseImages(crp.TrustedBaseImages))
	d.Set("allowed_images", crp.AllowedImages)
	d.Set("packages_black_list", flattenPackages(crp.PackagesBlackList))
	d.Set("packages_white_list", flattenPackages(crp.PackagesWhiteList))
	d.Set("cves_black_list", crp.CvesBlackList)
	d.Set("images", crp.Images)
	d.Set("labels", crp.Labels)
	d.Set("registries", crp.Registries)
	//d.Set("scope", flatteniapscope(crp.Scope))
	d.Set("scap_files", crp.ScapFiles)
	d.Set("custom_checks", flattenCustomChecks(crp.CustomChecks))
	d.Set("blacklisted_licenses_enabled", crp.BlacklistedLicensesEnabled)
	d.Set("blacklisted_licenses", crp.BlacklistedLicenses)
	d.Set("whitelisted_licenses_enabled", crp.WhitelistedLicensesEnabled)
	d.Set("whitelisted_licenses", crp.WhitelistedLicenses)
	d.Set("block_failed", crp.BlockFailed)
	d.Set("cves_black_list_enabled", crp.CvesBlackListEnabled)
	d.Set("packages_black_list_enabled", crp.PackagesBlackListEnabled)
	d.Set("packages_white_list_enabled", crp.PackagesWhiteListEnabled)
	d.Set("only_none_root_users", crp.OnlyNoneRootUsers)
	d.Set("trusted_base_images_enabled", crp.TrustedBaseImagesEnabled)
	d.Set("scan_sensitive_data", crp.ScanSensitiveData)
	d.Set("audit_on_failure", crp.AuditOnFailure)
	d.Set("cvss_severity_enabled", crp.CvssSeverityEnabled)
	d.Set("packages_black_list_enabled", crp.PackagesBlackListEnabled)
	d.Set("packages_white_list_enabled", crp.PackagesWhiteListEnabled)
	d.Set("cves_white_list_enabled", crp.CvesWhiteListEnabled)
	d.Set("cves_black_list_enabled", crp.CvesBlackListEnabled)
	d.Set("scap_enabled", crp.ScapEnabled)
	d.Set("custom_checks_enabled", crp.CustomChecksEnabled)
	d.Set("maximum_score_exclude_no_fix", crp.MaximumScoreExcludeNoFix)
	d.Set("maximum_score_enabled", crp.MaximumScoreEnabled)
	d.Set("maximum_score", crp.MaximumScore)
	d.Set("cvss_severity_exclude_no_fix", crp.CvssSeverityExcludeNoFix)
	d.Set("cvss_severity", crp.CvssSeverity)
	d.Set("custom_severity_enabled", crp.CustomSeverityEnabled)
	d.Set("assurance_type", crp.AssuranceType)

	d.SetId(crp.Name)

	return nil
}

func resourceHostRuntimePolicyJsonUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)
	name := d.Get("name").(string)

	if d.HasChanges("description",
		"application_scopes",
		"scope_expression",
		"scope_variables",
		"enabled",
		"enforce",
		"enforce_after_days",
		"author",
		"block_cryptocurrency_mining",
		"audit_brute_force_login",
		"enable_ip_reputation_security",
		"blocked_files",
		"file_integrity_monitoring",
		"audit_all_os_user_activity",
		"audit_full_command_arguments",
		"audit_host_successful_login_events",
		"audit_host_failed_login_events",
		"audit_user_account_management",
		"os_users_allowed",
		"os_groups_allowed",
		"os_users_blocked",
		"os_groups_blocked",
		"package_block",
		"port_scanning_detection",
		"malware_scan_options",
		"monitor_system_time_changes",
		"monitor_windows_services",
		"monitor_system_log_integrity",
		"windows_registry_monitoring",
		"windows_registry_protection",
		// JSON added
		"auto_scan_time",
		"auto_scan_configured",
		"auto_scan_enabled",
		"function_integrity_enabled",
		"blacklist_permissions_enabled",
		"blacklist_permissions",
		"enforce_excessive_permissions",
		"kube_cis_enabled",
		"docker_cis_enabled",
		"forbidden_labels_enabled",
		"forbidden_labels",
		"required_labels_enabled",
		"required_labels",
		"scan_nfs_mounts",
		"malware_action",
		"exceptional_monitored_malware_paths",
		"monitored_malware_paths",
		"disallow_malware",
		"dta_enabled",
		"dta_severity",
		"ignored_risk_resources",
		"ignore_risk_resources_enabled",
		"ignore_recently_published_vln_period",
		"control_exclude_no_fix",
		"cves_white_list_enabled",
		"cves_white_list",
		"force_microenforcer",
		"read_only",
		"trusted_base_images",
		"allowed_images",
		"packages_black_list",
		"packages_white_list",
		"cves_black_list",
		"images",
		"labels",
		"registries",
		"scope",
		"scap_files",
		"custom_checks",
		"blacklisted_licenses_enabled",
		"blacklisted_licenses",
		"whitelisted_licenses_enabled",
		"whitelisted_licenses",
		"block_failed",
		"cves_black_list_enabled",
		"packages_black_list_enabled",
		"packages_white_list_enabled",
		"only_none_root_users",
		"trusted_base_images_enabled",
		"scan_sensitive_data",
		"audit_on_failure",
		"cvss_severity_enabled",
		"packages_black_list_enabled",
		"packages_white_list_enabled",
		"cves_white_list_enabled",
		"cves_black_list_enabled",
		"scap_enabled",
		"custom_checks_enabled",
		"maximum_score_exclude_no_fix",
		"maximum_score_enabled",
		"maximum_score",
		"cvss_severity_exclude_no_fix",
		"cvss_severity",
		"custom_severity_enabled",
		"assurance_type",
	) {
		crp := expandHostRuntimePolicyJson(d)
		err := c.UpdateRuntimePolicy(crp)
		if err == nil {
			d.SetId(name)
		} else {
			return diag.FromErr(err)
		}
	}

	//d.SetId(name)

	return nil
}

func resourceHostRuntimePolicyJsonDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)
	name := d.Get("name").(string)

	err := c.DeleteRuntimePolicy(name)
	if err == nil {
		d.SetId("")
	} else {
		return diag.FromErr(err)
	}

	//d.SetId("")

	return nil
}

func expandHostRuntimePolicyJson(d *schema.ResourceData) *client.RuntimePolicy {
	crp := client.RuntimePolicy{
		Name:        d.Get("name").(string),
		RuntimeType: "host",
	}

	description, ok := d.GetOk("description")
	if ok {
		crp.Description = description.(string)
	}

	applicationScopes, ok := d.GetOk("application_scopes")
	if ok {
		crp.ApplicationScopes = convertStringArr(applicationScopes.([]interface{}))
	}

	scopeExpression, ok := d.GetOk("scope_expression")
	if ok {
		crp.Scope.Expression = scopeExpression.(string)
	}

	variables := make([]client.Variable, 0)
	variableMap, ok := d.GetOk("scope_variables")
	if ok {
		for _, v := range variableMap.([]interface{}) {
			ifc := v.(map[string]interface{})
			variables = append(variables, client.Variable{
				Attribute: ifc["attribute"].(string),
				Name:      ifc["name"].(string),
				Value:     ifc["value"].(string),
			})
		}
	}
	crp.Scope.Variables = variables

	enabled, ok := d.GetOk("enabled")
	if ok {
		crp.Enabled = enabled.(bool)
	}

	enforce, ok := d.GetOk("enforce")
	if ok {
		crp.Enforce = enforce.(bool)
	}

	enforceAfterDays, ok := d.GetOk("enforce_after_days")
	if ok {
		crp.EnforceAfterDays = enforceAfterDays.(int)
	}

	author, ok := d.GetOk("author")
	if ok {
		crp.Author = author.(string)
	}

	// controls

	blockCryptocurrencyMining, ok := d.GetOk("block_cryptocurrency_mining")
	if ok {
		crp.EnableCryptoMiningDns = blockCryptocurrencyMining.(bool)
	}

	auditBruteForceLogin, ok := d.GetOk("audit_brute_force_login")
	if ok {
		crp.AuditBruteForceLogin = auditBruteForceLogin.(bool)
	}

	enableIpReputation, ok := d.GetOk("enable_ip_reputation_security")
	if ok {
		crp.EnableIPReputation = enableIpReputation.(bool)
	}

	blockedFiles, ok := d.GetOk("blocked_files")
	if ok {
		strArr := convertStringArr(blockedFiles.([]interface{}))
		crp.FileBlock.Enabled = len(strArr) != 0
		crp.FileBlock.FilenameBlockList = strArr
	}

	crp.FileIntegrityMonitoring = client.FileIntegrityMonitoring{}
	fileIntegrityMonitoringMap, ok := d.GetOk("file_integrity_monitoring")
	if ok {
		v := fileIntegrityMonitoringMap.([]interface{})[0].(map[string]interface{})

		crp.FileIntegrityMonitoring = client.FileIntegrityMonitoring{
			Enabled:                            true,
			MonitoredFiles:                     convertStringArr(v["monitored_paths"].([]interface{})),
			ExceptionalMonitoredFiles:          convertStringArr(v["excluded_paths"].([]interface{})),
			MonitoredFilesProcesses:            convertStringArr(v["monitored_processes"].([]interface{})),
			ExceptionalMonitoredFilesProcesses: convertStringArr(v["excluded_processes"].([]interface{})),
			MonitoredFilesUsers:                convertStringArr(v["monitored_users"].([]interface{})),
			ExceptionalMonitoredFilesUsers:     convertStringArr(v["excluded_users"].([]interface{})),
			MonitoredFilesCreate:               v["monitor_create"].(bool),
			MonitoredFilesRead:                 v["monitor_read"].(bool),
			MonitoredFilesModify:               v["monitor_modify"].(bool),
			MonitoredFilesDelete:               v["monitor_delete"].(bool),
			MonitoredFilesAttributes:           v["monitor_attributes"].(bool),
		}
	}

	auditOsUserActivity, ok := d.GetOk("audit_all_os_user_activity")
	if ok {
		crp.Auditing.Enabled = true
		crp.Auditing.AuditOsUserActivity = auditOsUserActivity.(bool)
	}

	auditFullCommandArguments, ok := d.GetOk("audit_full_command_arguments")
	if ok {
		crp.Auditing.Enabled = true
		crp.Auditing.AuditProcessCmdline = auditFullCommandArguments.(bool)
	}

	auditHostSuccessfulLoginEvents, ok := d.GetOk("audit_host_successful_login_events")
	if ok {
		crp.Auditing.Enabled = true
		crp.Auditing.AuditSuccessLogin = auditHostSuccessfulLoginEvents.(bool)
	}

	auditHostFailedLoginEvents, ok := d.GetOk("audit_host_failed_login_events")
	if ok {
		crp.Auditing.Enabled = true
		crp.Auditing.AuditFailedLogin = auditHostFailedLoginEvents.(bool)
	}

	auditUserAccountManagement, ok := d.GetOk("audit_user_account_management")
	if ok {
		crp.Enabled = true
		crp.Auditing.AuditUserAccountManagement = auditUserAccountManagement.(bool)
	}

	crp.WhitelistedOsUsers.UserWhiteList = []string{}
	usersAllowed, ok := d.GetOk("os_users_allowed")
	if ok {
		strArr := convertStringArr(usersAllowed.([]interface{}))
		crp.WhitelistedOsUsers.Enabled = len(strArr) != 0
		crp.WhitelistedOsUsers.UserWhiteList = strArr
	}

	crp.WhitelistedOsUsers.GroupWhiteList = []string{}
	groupsAllowed, ok := d.GetOk("os_groups_allowed")
	if ok {
		strArr := convertStringArr(groupsAllowed.([]interface{}))
		crp.WhitelistedOsUsers.Enabled = len(strArr) != 0
		crp.WhitelistedOsUsers.GroupWhiteList = strArr
	}

	crp.BlacklistedOsUsers.UserBlackList = []string{}
	usersBlocked, ok := d.GetOk("os_users_blocked")
	if ok {
		strArr := convertStringArr(usersBlocked.([]interface{}))
		crp.BlacklistedOsUsers.Enabled = len(strArr) != 0
		crp.BlacklistedOsUsers.UserBlackList = strArr
	}

	crp.BlacklistedOsUsers.GroupBlackList = []string{}
	groupsBlocked, ok := d.GetOk("os_groups_blocked")
	if ok {
		strArr := convertStringArr(groupsBlocked.([]interface{}))
		crp.BlacklistedOsUsers.Enabled = len(strArr) != 0
		crp.BlacklistedOsUsers.GroupBlackList = strArr
	}

	crp.PackageBlock.PackagesBlackList = []string{}
	packageBlock, ok := d.GetOk("package_block")
	if ok {
		strArr := convertStringArr(packageBlock.([]interface{}))
		crp.PackageBlock.Enabled = len(strArr) != 0
		crp.PackageBlock.PackagesBlackList = strArr
	}

	portScanningDetection, ok := d.GetOk("port_scanning_detection")
	if ok {
		crp.EnablePortScanProtection = portScanningDetection.(bool)
	}

	systemTime, ok := d.GetOk("monitor_system_time_changes")
	if ok {
		crp.SystemIntegrityProtection.Enabled = systemTime.(bool)
		crp.SystemIntegrityProtection.AuditSystemtimeChange = systemTime.(bool)
	}

	windowsServices, ok := d.GetOk("monitor_windows_services")
	if ok {
		crp.SystemIntegrityProtection.Enabled = true
		crp.SystemIntegrityProtection.WindowsServicesMonitoring = windowsServices.(bool)
	}

	systemLogIntegrity, ok := d.GetOk("monitor_system_log_integrity")
	if ok {
		crp.SystemIntegrityProtection.Enabled = true
		crp.SystemIntegrityProtection.MonitorAuditLogIntegrity = systemLogIntegrity.(bool)
	}

	crp.RegistryAccessMonitoring = client.RegistryAccessMonitoring{}
	windowsMonitoringMap, ok := d.GetOk("windows_registry_monitoring")
	if ok {
		v := windowsMonitoringMap.([]interface{})[0].(map[string]interface{})

		crp.RegistryAccessMonitoring = client.RegistryAccessMonitoring{
			Enabled:                               true,
			MonitoredRegistryPaths:                convertStringArr(v["monitored_paths"].([]interface{})),
			ExceptionalMonitoredRegistryPaths:     convertStringArr(v["excluded_paths"].([]interface{})),
			MonitoredRegistryProcesses:            convertStringArr(v["monitored_processes"].([]interface{})),
			ExceptionalMonitoredRegistryProcesses: convertStringArr(v["excluded_processes"].([]interface{})),
			MonitoredRegistryUsers:                convertStringArr(v["monitored_users"].([]interface{})),
			ExceptionalMonitoredRegistryUsers:     convertStringArr(v["excluded_users"].([]interface{})),
			MonitoredRegistryCreate:               v["monitor_create"].(bool),
			MonitoredRegistryRead:                 v["monitor_read"].(bool),
			MonitoredRegistryModify:               v["monitor_modify"].(bool),
			MonitoredRegistryDelete:               v["monitor_delete"].(bool),
			MonitoredRegistryAttributes:           v["monitor_attributes"].(bool),
		}
	}

	crp.ReadonlyRegistry = client.ReadonlyRegistry{}
	windowsRegistryProtectionMap, ok := d.GetOk("windows_registry_protection")
	if ok {
		v := windowsRegistryProtectionMap.([]interface{})[0].(map[string]interface{})

		crp.ReadonlyRegistry = client.ReadonlyRegistry{
			Enabled:                              true,
			ReadonlyRegistryPaths:                convertStringArr(v["protected_paths"].([]interface{})),
			ExceptionalReadonlyRegistryPaths:     convertStringArr(v["excluded_paths"].([]interface{})),
			ReadonlyRegistryProcesses:            convertStringArr(v["protected_processes"].([]interface{})),
			ExceptionalReadonlyRegistryProcesses: convertStringArr(v["excluded_processes"].([]interface{})),
			ReadonlyRegistryUsers:                convertStringArr(v["protected_users"].([]interface{})),
			ExceptionalReadonlyRegistryUsers:     convertStringArr(v["excluded_users"].([]interface{})),
		}
	}

	crp.MalwareScanOptions = client.MalwareScanOptions{}
	malwareScanOptionsMap, ok := d.GetOk("malware_scan_options")
	if ok {
		v := malwareScanOptionsMap.([]interface{})[0].(map[string]interface{})

		crp.MalwareScanOptions = client.MalwareScanOptions{
			Enabled:            v["enabled"].(bool),
			Action:             v["action"].(string),
			ExcludeDirectories: convertStringArr(v["exclude_directories"].([]interface{})),
			ExcludeProcesses:   convertStringArr(v["exclude_processes"].([]interface{})),
		}
	}

	//JSON added
	auto_scan_time, ok := d.GetOk("auto_scan_time")
	if ok && auto_scan_time.(*schema.Set).Len() > 0 {
		for _, astMap := range auto_scan_time.(*schema.Set).List() {
			astentries, ok := astMap.(map[string]interface{})
			if !ok {
				continue
			}
			ScanTime := client.ScanTimeAuto{
				IterationType: astentries["iteration_type"].(string),
				Time:          astentries["time"].(string),
				Iteration:     astentries["iteration"].(int),
				WeekDays:      astentries["week_days"].([]interface{}),
			}
			crp.AutoScanTime = ScanTime
		}
	}

	auto_scan_enabled, ok := d.GetOk("auto_scan_enabled")
	if ok {
		crp.AutoScanEnabled = auto_scan_enabled.(bool)
	}

	auto_scan_configured, ok := d.GetOk("auto_scan_configured")
	if ok {
		crp.AutoScanConfigured = auto_scan_configured.(bool)
	}

	function_integrity_enabled, ok := d.GetOk("function_integrity_enabled")
	if ok {
		crp.FunctionIntegrityEnabled = function_integrity_enabled.(bool)
	}

	blacklist_permissions_enabled, ok := d.GetOk("blacklist_permissions_enabled")
	if ok {
		crp.BlacklistPermissionsEnabled = blacklist_permissions_enabled.(bool)
	}

	blacklist_permissions, ok := d.GetOk("blacklist_permissions")
	if ok {
		crp.BlacklistPermissions = blacklist_permissions.([]interface{})
	}

	enforce_excessive_permissions, ok := d.GetOk("enforce_excessive_permissions")
	if ok {
		crp.EnforceExcessivePermissions = enforce_excessive_permissions.(bool)
	}

	docker_cis_enabled, ok := d.GetOk("docker_cis_enabled")
	if ok {
		crp.DockerCisEnabled = docker_cis_enabled.(bool)
	}

	kube_cis_enabled, ok := d.GetOk("kube_cis_enabled")
	if ok {
		crp.KubeCisEnabled = kube_cis_enabled.(bool)
	}

	forbidden_labels_enabled, ok := d.GetOk("forbidden_labels_enabled")
	if ok {
		crp.ForbiddenLabelsEnabled = forbidden_labels_enabled.(bool)
	}

	forbidden_labels, ok := d.GetOk("forbidden_labels")
	if ok {
		forbiddenlabels := forbidden_labels.(*schema.Set).List()
		labelsarray := make([]client.Labels, len(forbiddenlabels))
		for i, Data := range forbiddenlabels {
			labels := Data.(map[string]interface{})
			ForbiddenLabel := client.Labels{
				Key:   labels["key"].(string),
				Value: labels["value"].(string),
			}
			labelsarray[i] = ForbiddenLabel
		}
		crp.ForbiddenLabels = labelsarray
	}

	required_labels_enabled, ok := d.GetOk("required_labels_enabled")
	if ok {
		crp.RequiredLabelsEnabled = required_labels_enabled.(bool)
	}

	required_labels, ok := d.GetOk("required_labels")
	if ok {
		requiredlabels := required_labels.(*schema.Set).List()
		labelsarray := make([]client.Labels, len(requiredlabels))
		for i, Data := range requiredlabels {
			labels := Data.(map[string]interface{})
			RequiredLabel := client.Labels{
				Key:   labels["key"].(string),
				Value: labels["value"].(string),
			}
			labelsarray[i] = RequiredLabel
		}
		crp.RequiredLabels = labelsarray
	}

	scan_nfs_mounts, ok := d.GetOk("scan_nfs_mounts")
	if ok {
		crp.ScanNfsMounts = scan_nfs_mounts.(bool)
	}

	malware_action, ok := d.GetOk("malware_action")
	if ok {
		crp.MalwareAction = malware_action.(string)
	}

	monitored_malware_paths, ok := d.GetOk("monitored_malware_paths")
	if ok {
		crp.MonitoredMalwarePaths = monitored_malware_paths.([]interface{})
	}

	exceptional_monitored_malware_paths, ok := d.GetOk("exceptional_monitored_malware_paths")
	if ok {
		crp.ExceptionalMonitoredMalwarePaths = exceptional_monitored_malware_paths.([]interface{})
	}

	disallow_malware, ok := d.GetOk("disallow_malware")
	if ok {
		crp.DisallowMalware = disallow_malware.(bool)
	}

	dta_enabled, ok := d.GetOk("dta_enabled")
	if ok {
		crp.DtaEnabled = dta_enabled.(bool)
	}

	dta_severity, ok := d.GetOk("dta_severity")
	if ok {
		crp.DtaSeverity = dta_severity.(string)
	}

	ignore_recently_published_vln_period, ok := d.GetOk("ignore_recently_published_vln_period")
	if ok {
		crp.IgnoreRecentlyPublishedVlnPeriod = ignore_recently_published_vln_period.(int)
	}

	ignore_risk_resources_enabled, ok := d.GetOk("ignore_risk_resources_enabled")
	if ok {
		crp.IgnoreRiskResourcesEnabled = ignore_risk_resources_enabled.(bool)
	}

	ignored_risk_resources, ok := d.GetOk("ignored_risk_resources")
	if ok {
		strArr := convertStringArr(ignored_risk_resources.([]interface{}))
		crp.IgnoredRiskResources = strArr
	}

	control_exclude_no_fix, ok := d.GetOk("control_exclude_no_fix")
	if ok {
		crp.ControlExcludeNoFix = control_exclude_no_fix.(bool)
	}

	cves_black_list_enabled, ok := d.GetOk("cves_black_list_enabled")
	if ok {
		crp.CvesBlackListEnabled = cves_black_list_enabled.(bool)
	}

	force_microenforcer, ok := d.GetOk("force_microenforcer")
	if ok {
		crp.ForceMicroenforcer = force_microenforcer.(bool)
	}

	read_only, ok := d.GetOk("read_only")
	if ok {
		crp.ReadOnly = read_only.(bool)
	}

	trusted_base_images_enabled, ok := d.GetOk("trusted_base_images_enabled")
	if ok {
		crp.TrustedBaseImagesEnabled = trusted_base_images_enabled.(bool)
	}

	allowed_images, ok := d.GetOk("allowed_images")
	if ok {
		crp.AllowedImages = allowed_images.([]interface{})
	}

	trusted_base_images, ok := d.GetOk("trusted_base_images")
	if ok {
		trustedbaseimages := trusted_base_images.(*schema.Set).List()
		baseimagesarray := make([]client.BaseImagesTrusted, len(trustedbaseimages))
		for i, Data := range trustedbaseimages {
			baseimages := Data.(map[string]interface{})
			BImage := client.BaseImagesTrusted{
				Registry:  baseimages["registry"].(string),
				Imagename: baseimages["imagename"].(string),
			}
			baseimagesarray[i] = BImage
		}
		crp.TrustedBaseImages = baseimagesarray
	}

	packages_black_list, ok := d.GetOk("packages_black_list")
	if ok {
		pkgsblacklist := packages_black_list.(*schema.Set).List()
		pkgsblacklistarray := make([]client.ListPackages, len(pkgsblacklist))
		for i, Data := range pkgsblacklist {
			blackLists := Data.(map[string]interface{})
			BlackList := client.ListPackages{
				Format:       blackLists["format"].(string),
				Name:         blackLists["name"].(string),
				Epoch:        blackLists["epoch"].(string),
				Version:      blackLists["version"].(string),
				VersionRange: blackLists["version_range"].(string),
				Release:      blackLists["release"].(string),
				Arch:         blackLists["arch"].(string),
				License:      blackLists["license"].(string),
				Display:      blackLists["display"].(string),
			}
			pkgsblacklistarray[i] = BlackList
		}
		crp.PackagesBlackList = pkgsblacklistarray
	}

	packages_white_list, ok := d.GetOk("packages_white_list")
	if ok {
		pkgswhitelist := packages_white_list.(*schema.Set).List()
		pkgswhitelistarray := make([]client.ListPackages, len(pkgswhitelist))
		for i, Data := range pkgswhitelist {
			WhiteLists := Data.(map[string]interface{})
			WhiteList := client.ListPackages{
				Format:       WhiteLists["format"].(string),
				Name:         WhiteLists["name"].(string),
				Epoch:        WhiteLists["epoch"].(string),
				Version:      WhiteLists["version"].(string),
				VersionRange: WhiteLists["version_range"].(string),
				Release:      WhiteLists["release"].(string),
				Arch:         WhiteLists["arch"].(string),
				License:      WhiteLists["license"].(string),
				Display:      WhiteLists["display"].(string),
			}
			pkgswhitelistarray[i] = WhiteList
		}
		crp.PackagesWhiteList = pkgswhitelistarray
	}

	cves_black_list, ok := d.GetOk("cves_black_list")
	if ok {
		strArr := convertStringArr(cves_black_list.([]interface{}))
		crp.CvesBlackList = strArr
	}

	registries, ok := d.GetOk("registries")
	if ok {
		crp.Registries = registries.([]interface{})
	}

	labels, ok := d.GetOk("labels")
	if ok {
		crp.Labels = labels.([]interface{})
	}

	images, ok := d.GetOk("images")
	if ok {
		crp.Images = images.([]interface{})
	}

	scap_files, ok := d.GetOk("scap_files")
	if ok {
		crp.ScapFiles = scap_files.([]interface{})
	}

	custom_checks, ok := d.GetOk("custom_checks")
	if ok {
		customcheckslist := custom_checks.([]interface{})
		custcheckskArr := make([]client.Checks, len(customcheckslist))
		for i, Data := range customcheckslist {
			customChecks := Data.(map[string]interface{})
			Check := client.Checks{
				ScriptID:     customChecks["script_id"].(string),
				Name:         customChecks["name"].(string),
				Path:         customChecks["path"].(string),
				LastModified: customChecks["last_modified"].(int),
				Description:  customChecks["description"].(string),
				Engine:       customChecks["engine"].(string),
				Snippet:      customChecks["snippet"].(string),
				ReadOnly:     customChecks["read_only"].(bool),
				Severity:     customChecks["severity"].(string),
				Author:       customChecks["author"].(string),
			}
			custcheckskArr[i] = Check
		}
		crp.CustomChecks = custcheckskArr
	}

	blacklisted_licenses_enabled, ok := d.GetOk("blacklisted_licenses_enabled")
	if ok {
		crp.BlacklistedLicensesEnabled = blacklisted_licenses_enabled.(bool)
	}

	blacklisted_licenses, ok := d.GetOk("blacklisted_licenses")
	if ok {
		strArr := convertStringArr(blacklisted_licenses.([]interface{}))
		crp.BlacklistedLicenses = strArr
	}

	whitelisted_licenses_enabled, ok := d.GetOk("whitelisted_licenses_enabled")
	if ok {
		crp.WhitelistedLicensesEnabled = whitelisted_licenses_enabled.(bool)
	}

	whitelisted_licenses, ok := d.GetOk("whitelisted_licenses")
	if ok {
		strArr := convertStringArr(whitelisted_licenses.([]interface{}))
		crp.WhitelistedLicenses = strArr
	}

	blockfailed, ok := d.GetOk("block_failed")
	if ok {
		crp.BlockFailed = blockfailed.(bool)
	}

	packages_black_list_enabled, ok := d.GetOk("packages_black_list_enabled")
	if ok {
		crp.PackagesBlackListEnabled = packages_black_list_enabled.(bool)
	}

	packages_white_list_enabled, ok := d.GetOk("packages_white_list_enabled")
	if ok {
		crp.PackagesWhiteListEnabled = packages_white_list_enabled.(bool)
	}

	only_none_root_users, ok := d.GetOk("only_none_root_users")
	if ok {
		crp.OnlyNoneRootUsers = only_none_root_users.(bool)
	}

	scan_sensitive_data, ok := d.GetOk("scan_sensitive_data")
	if ok {
		crp.ScanSensitiveData = scan_sensitive_data.(bool)
	}

	auditonfailure, ok := d.GetOk("audit_on_failure")
	if ok {
		crp.AuditOnFailure = auditonfailure.(bool)
	}

	cvssseverityenabled, ok := d.GetOk("cvss_severity_enabled")
	if ok {
		crp.CvssSeverityEnabled = cvssseverityenabled.(bool)
	}

	scap_enabled, ok := d.GetOk("scap_enabled")
	if ok {
		crp.ScapEnabled = scap_enabled.(bool)
	}

	custom_checks_enabled, ok := d.GetOk("custom_checks_enabled")
	if ok {
		crp.CustomChecksEnabled = custom_checks_enabled.(bool)
	}

	maximum_score_exclude_no_fix, ok := d.GetOk("maximum_score_exclude_no_fix")
	if ok {
		crp.MaximumScoreExcludeNoFix = maximum_score_exclude_no_fix.(bool)
	}

	maximum_score_enabled, ok := d.GetOk("maximum_score_enabled")
	if ok {
		crp.MaximumScoreEnabled = maximum_score_enabled.(bool)
	}

	maximum_score, ok := d.GetOk("maximum_score")
	if ok {
		crp.MaximumScore = maximum_score.(float64)
	}

	cvssseverityexcludenofix, ok := d.GetOk("cvss_severity_exclude_no_fix")
	if ok {
		crp.CvssSeverityExcludeNoFix = cvssseverityexcludenofix.(bool)
	}

	cvssseverity, ok := d.GetOk("cvss_severity")
	if ok {
		crp.CvssSeverity = cvssseverity.(string)
	}

	custom_severity_enabled, ok := d.GetOk("custom_severity_enabled")
	if ok {
		crp.CustomSeverityEnabled = custom_severity_enabled.(bool)
	}

	return &crp
}
