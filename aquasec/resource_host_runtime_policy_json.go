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

	crp := expandHostRuntimePolicy(d)
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
		"windows_registry_protection") {
		crp := expandHostRuntimePolicy(d)
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
