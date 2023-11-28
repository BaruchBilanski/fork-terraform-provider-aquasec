package client

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"io"
	"log"
	"time"
)

type RuntimePolicy struct {
	AllowedExecutables           AllowedExecutables           `json:"allowed_executables"`
	AllowedRegistries            AllowedRegistries            `json:"allowed_registries"`
	ApplicationScopes            []string                     `json:"application_scopes"`
	AuditBruteForceLogin         bool                         `json:"audit_brute_force_login"`
	AuditOnFailure               bool                         `json:"audit_on_failure"`
	Auditing                     Auditing                     `json:"auditing"`
	Author                       string                       `json:"author"`
	BlacklistedOsUsers           BlacklistedOsUsers           `json:"blacklisted_os_users"`
	BlockDisallowedImages        bool                         `json:"block_disallowed_images"`
	BlockFailed                  bool                         `json:"block_failed"`
	BlockFilelessExec            bool                         `json:"block_fileless_exec"`
	BlockNonCompliantWorkloads   bool                         `json:"block_non_compliant_workloads"`
	BlockNonK8sContainers        bool                         `json:"block_non_k8s_containers"`
	BlockNwUnlinkCont            bool                         `json:"block_nw_unlink_cont"`
	BypassScope                  BypassScope                  `json:"bypass_scope"`
	ContainerExec                ContainerExec                `json:"container_exec"`
	Created                      time.Time                    `json:"created"`
	Cve                          string                       `json:"cve"`
	DefaultSecurityProfile       string                       `json:"default_security_profile"`
	Description                  string                       `json:"description"`
	Digest                       string                       `json:"digest"`
	Domain                       string                       `json:"domain"`
	DomainName                   string                       `json:"domain_name"`
	DriftPrevention              DriftPrevention              `json:"drift_prevention"`
	EnableCryptoMiningDns        bool                         `json:"enable_crypto_mining_dns"`
	EnableForkGuard              bool                         `json:"enable_fork_guard"`
	EnableIPReputation           bool                         `json:"enable_ip_reputation"`
	EnablePortScanProtection     bool                         `json:"enable_port_scan_protection"`
	Enabled                      bool                         `json:"enabled"`
	Enforce                      bool                         `json:"enforce"`
	EnforceAfterDays             int                          `json:"enforce_after_days"`
	EnforceSchedulerAddedOn      int                          `json:"enforce_scheduler_added_on"`
	ExecutableBlacklist          ExecutableBlacklist          `json:"executable_blacklist"`
	FailCicd                     bool                         `json:"fail_cicd"`
	FailedKubernetesChecks       FailedKubernetesChecks       `json:"failed_kubernetes_checks"`
	FileBlock                    FileBlock                    `json:"file_block"`
	FileIntegrityMonitoring      FileIntegrityMonitoring      `json:"file_integrity_monitoring"`
	ForkGuardProcessLimit        int                          `json:"fork_guard_process_limit"`
	HeuristicRefID               int                          `json:"heuristic_ref_id"`
	ImageID                      int                          `json:"image_id"`
	ImageName                    string                       `json:"image_name"`
	IsAuditChecked               bool                         `json:"is_audit_checked"`
	IsAutoGenerated              bool                         `json:"is_auto_generated"`
	Lastupdate                   int                          `json:"lastupdate"`
	LimitContainerPrivileges     LimitContainerPrivileges     `json:"limit_container_privileges"`
	LinuxCapabilities            LinuxCapabilities            `json:"linux_capabilities"`
	MalwareScanOptions           MalwareScanOptions           `json:"malware_scan_options"`
	Name                         string                       `json:"name"`
	NoNewPrivileges              bool                         `json:"no_new_privileges"`
	OnlyRegisteredImages         bool                         `json:"only_registered_images"`
	PackageBlock                 PackageBlock                 `json:"package_block"`
	Permission                   string                       `json:"permission"`
	PortBlock                    PortBlock                    `json:"port_block"`
	PreventOverrideDefaultConfig PreventOverrideDefaultConfig `json:"prevent_override_default_config"`
	ReadonlyFiles                ReadonlyFiles                `json:"readonly_files"`
	ReadonlyRegistry             ReadonlyRegistry             `json:"readonly_registry"`
	Registry                     string                       `json:"registry"`
	RegistryAccessMonitoring     RegistryAccessMonitoring     `json:"registry_access_monitoring"`
	RepoID                       int                          `json:"repo_id"`
	RepoName                     string                       `json:"repo_name"`
	ResourceName                 string                       `json:"resource_name"`
	ResourceType                 string                       `json:"resource_type"`
	RestrictedVolumes            RestrictedVolumes            `json:"restricted_volumes"`
	ReverseShell                 ReverseShell                 `json:"reverse_shell"`
	RuntimeType                  string                       `json:"runtime_type"`
	Scope                        Scope                        `json:"scope"`
	SystemIntegrityProtection    SystemIntegrityProtection    `json:"system_integrity_protection"`
	Tripwire                     Tripwire                     `json:"tripwire"`
	Type                         string                       `json:"type"`
	Updated                      time.Time                    `json:"updated"`
	Version                      string                       `json:"version"`
	VpatchVersion                string                       `json:"vpatch_version"`
	VulnID                       int                          `json:"vuln_id"`
	WhitelistedOsUsers           WhitelistedOsUsers           `json:"whitelisted_os_users"`
	//JSON test bool
	EnableCryptoMiningDNS bool `json:"enable_crypto_mining_dns"`
	BlockContainerExec    bool `json:"block_container_exec"`
	IsOOTBPolicy          bool `json:"is_ootb_policy"`
	//JSON test bool int
	RuntimeMode int `json:"runtime_mode"`
}

type AllowedExecutables struct {
	AllowExecutables     []string `json:"allow_executables"`
	AllowRootExecutables []string `json:"allow_root_executables"`
	Enabled              bool     `json:"enabled"`
	SeparateExecutables  bool     `json:"separate_executables"`
}

type AllowedRegistries struct {
	AllowedRegistries []string `json:"allowed_registries"`
	Enabled           bool     `json:"enabled"`
}

type ExecutableBlacklist struct {
	Enabled     bool     `json:"enabled"`
	Executables []string `json:"executables"`
}

type FailedKubernetesChecks struct {
	Enabled      bool     `json:"enabled"`
	FailedChecks []string `json:"failed_checks"`
}
type DriftPrevention struct {
	Enabled               bool     `json:"enabled"`
	ExecLockdown          bool     `json:"exec_lockdown"`
	ImageLockdown         bool     `json:"image_lockdown"`
	PreventPrivileged     bool     `json:"prevent_privileged"`
	ExecLockdownWhiteList []string `json:"exec_lockdown_white_list"`
}

type RestrictedVolumes struct {
	Enabled bool     `json:"enabled"`
	Volumes []string `json:"volumes"`
}

type BypassScope struct {
	Enabled bool  `json:"enabled"`
	Scope   Scope `json:"scope"`
}

type LimitContainerPrivileges struct {
	Enabled               bool `json:"enabled"`
	Privileged            bool `json:"privileged"`
	Netmode               bool `json:"netmode"`
	Pidmode               bool `json:"pidmode"`
	Utsmode               bool `json:"utsmode"`
	Usermode              bool `json:"usermode"`
	Ipcmode               bool `json:"ipcmode"`
	PreventRootUser       bool `json:"prevent_root_user"`
	PreventLowPortBinding bool `json:"prevent_low_port_binding"`
	BlockAddCapabilities  bool `json:"block_add_capabilities"`
	UseHostUser           bool `json:"use_host_user"`
}

type PreventOverrideDefaultConfig struct {
	Enabled         bool `json:"enabled"`
	EnforceSelinux  bool `json:"enforce_selinux"`
	EnforceSeccomp  bool `json:"enforce_seccomp"`
	EnforceApparmor bool `json:"enforce_apparmor"`
}

type Auditing struct {
	AuditAllNetwork            bool `json:"audit_all_network"`
	AuditAllProcesses          bool `json:"audit_all_processes"`
	AuditFailedLogin           bool `json:"audit_failed_login"`
	AuditOsUserActivity        bool `json:"audit_os_user_activity"`
	AuditProcessCmdline        bool `json:"audit_process_cmdline"`
	AuditSuccessLogin          bool `json:"audit_success_login"`
	AuditUserAccountManagement bool `json:"audit_user_account_management"`
	Enabled                    bool `json:"enabled"`
}

type BlacklistedOsUsers struct {
	Enabled        bool     `json:"enabled"`
	UserBlackList  []string `json:"user_black_list"`
	GroupBlackList []string `json:"group_black_list"`
}

type WhitelistedOsUsers struct {
	Enabled        bool     `json:"enabled"`
	UserWhiteList  []string `json:"user_white_list"`
	GroupWhiteList []string `json:"group_white_list"`
}

type FileBlock struct {
	Enabled           bool     `json:"enabled"`
	FilenameBlockList []string `json:"filename_block_list"`
}

type PackageBlock struct {
	Enabled                           bool     `json:"enabled"`
	PackagesBlackList                 []string `json:"packages_black_list,omitempty"`
	ExceptionalBlockPackagesFiles     []string `json:"exceptional_block_packages_files,omitempty"`
	BlockPackagesUsers                []string `json:"block_packages_users,omitempty"`
	BlockPackagesProcesses            []string `json:"block_packages_processes,omitempty"`
	ExceptionalBlockPackagesUsers     []string `json:"exceptional_block_packages_users,omitempty"`
	ExceptionalBlockPackagesProcesses []string `json:"exceptional_block_packages_processes,omitempty"`
}

type LinuxCapabilities struct {
	Enabled                 bool     `json:"enabled"`
	RemoveLinuxCapabilities []string `json:"remove_linux_capabilities"`
}

type MalwareScanOptions struct {
	Action             string   `json:"action"`
	Enabled            bool     `json:"enabled"`
	ExcludeDirectories []string `json:"exclude_directories"`
	ExcludeProcesses   []string `json:"exclude_processes"`
}

type PortBlock struct {
	Enabled            bool     `json:"enabled"`
	BlockInboundPorts  []string `json:"block_inbound_ports"`
	BlockOutboundPorts []string `json:"block_outbound_ports"`
}

type Tripwire struct {
	Enabled       bool     `json:"enabled"`
	UserID        string   `json:"user_id"`
	UserPassword  string   `json:"user_password"`
	ApplyOn       []string `json:"apply_on"`
	ServerlessApp string   `json:"serverless_app"`
}

type FileIntegrityMonitoring struct {
	Enabled                            bool     `json:"enabled"`
	MonitoredFiles                     []string `json:"monitored_files,omitempty"`
	ExceptionalMonitoredFiles          []string `json:"exceptional_monitored_files,omitempty"`
	MonitoredFilesProcesses            []string `json:"monitored_files_processes,omitempty"`
	ExceptionalMonitoredFilesProcesses []string `json:"exceptional_monitored_files_processes,omitempty"`
	MonitoredFilesUsers                []string `json:"monitored_files_users,omitempty"`
	ExceptionalMonitoredFilesUsers     []string `json:"exceptional_monitored_files_users,omitempty"`
	MonitoredFilesCreate               bool     `json:"monitored_files_create,omitempty"`
	MonitoredFilesRead                 bool     `json:"monitored_files_read,omitempty"`
	MonitoredFilesModify               bool     `json:"monitored_files_modify,omitempty"`
	MonitoredFilesDelete               bool     `json:"monitored_files_delete,omitempty"`
	MonitoredFilesAttributes           bool     `json:"monitored_files_attributes,omitempty"`
}

type RegistryAccessMonitoring struct {
	Enabled                               bool     `json:"enabled"`
	ExceptionalMonitoredRegistryPaths     []string `json:"exceptional_monitored_registry_paths"`
	ExceptionalMonitoredRegistryProcesses []string `json:"exceptional_monitored_registry_processes"`
	ExceptionalMonitoredRegistryUsers     []string `json:"exceptional_monitored_registry_users"`
	MonitoredRegistryAttributes           bool     `json:"monitored_registry_attributes"`
	MonitoredRegistryCreate               bool     `json:"monitored_registry_create"`
	MonitoredRegistryDelete               bool     `json:"monitored_registry_delete"`
	MonitoredRegistryModify               bool     `json:"monitored_registry_modify"`
	MonitoredRegistryPaths                []string `json:"monitored_registry_paths"`
	MonitoredRegistryProcesses            []string `json:"monitored_registry_processes"`
	MonitoredRegistryRead                 bool     `json:"monitored_registry_read"`
	MonitoredRegistryUsers                []string `json:"monitored_registry_users"`
}

type SystemIntegrityProtection struct {
	AuditSystemtimeChange     bool `json:"audit_systemtime_change"`
	Enabled                   bool `json:"enabled"`
	MonitorAuditLogIntegrity  bool `json:"monitor_audit_log_integrity"`
	WindowsServicesMonitoring bool `json:"windows_services_monitoring"`
}

type ReadonlyFiles struct {
	Enabled                  bool     `json:"enabled"`
	ReadonlyFiles            []string `json:"readonly_files"`
	ExceptionalReadonlyFiles []string `json:"exceptional_readonly_files"`
}

type ReadonlyRegistry struct {
	Enabled                              bool     `json:"enabled"`
	ExceptionalReadonlyRegistryPaths     []string `json:"exceptional_readonly_registry_paths"`
	ExceptionalReadonlyRegistryProcesses []string `json:"exceptional_readonly_registry_processes"`
	ExceptionalReadonlyRegistryUsers     []string `json:"exceptional_readonly_registry_users"`
	ReadonlyRegistryPaths                []string `json:"readonly_registry_paths"`
	ReadonlyRegistryProcesses            []string `json:"readonly_registry_processes"`
	ReadonlyRegistryUsers                []string `json:"readonly_registry_users"`
}

type ContainerExec struct {
	BlockContainerExec         bool     `json:"block_container_exec"`
	ContainerExecProcWhiteList []string `json:"container_exec_proc_white_list"`
	Enabled                    bool     `json:"enabled"`
}

type ReverseShell struct {
	BlockReverseShell         bool     `json:"block_reverse_shell"`
	Enabled                   bool     `json:"enabled"`
	ReverseShellIpWhiteList   []string `json:"reverse_shell_ip_white_list"`
	ReverseShellProcWhiteList []string `json:"reverse_shell_proc_white_list"`
}

// CreateRuntimePolicy creates an Aqua RuntimePolicy
func (cli *Client) CreateRuntimePolicy(runtimePolicy *RuntimePolicy) error {
	payload, err := json.Marshal(runtimePolicy)
	if err != nil {
		return err
	}

	request := cli.gorequest
	apiPath := fmt.Sprintf("/api/v2/runtime_policies")
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	resp, body, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Post(cli.url + apiPath).Send(string(payload)).End()
	log.Println(string(payload))
	if errs != nil {
		return errors.Wrap(getMergedError(errs), "failed creating runtime policy.")
	}
	if resp.StatusCode != 200 && resp.StatusCode != 201 && resp.StatusCode != 204 {
		var errorResponse ErrorResponse
		err = json.Unmarshal([]byte(body), &errorResponse)
		if err != nil {
			log.Printf("Failed to Unmarshal response Body to ErrorResponse. Body: %v", body)
			return fmt.Errorf("failed creating runtime policy with name %v. Status: %v, Response: %v", runtimePolicy.Name, resp.StatusCode, body)
		}
		return fmt.Errorf("failed creating runtime policy. status: %v. error message: %v", resp.Status, errorResponse.Message)
	}

	return nil
}

// GetRuntimePolicy gets an Aqua runtime policy by name
func (cli *Client) GetRuntimePolicy(name string) (*RuntimePolicy, error) {
	var err error
	var response RuntimePolicy
	request := cli.gorequest
	apiPath := fmt.Sprintf("/api/v2/runtime_policies/%v", name)
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return nil, err
	}
	events, body, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Get(cli.url + apiPath).End()
	if errs != nil {
		return nil, errors.Wrap(getMergedError(errs), "failed getting runtime policy with name "+name)
	}
	if events.StatusCode == 200 {
		err = json.Unmarshal([]byte(body), &response)
		if err != nil {
			log.Printf("Error unmarshaling response body")
			return nil, errors.Wrap(err, fmt.Sprintf("couldn't unmarshal get runtime policy response. Body: %v", body))
		}
	} else {
		var errorReponse ErrorResponse
		err = json.Unmarshal([]byte(body), &errorReponse)
		if err != nil {
			log.Println("failed to unmarshal error response")
			return nil, fmt.Errorf("failed getting runtime policy with name %v. Status: %v, Response: %v", name, events.StatusCode, body)
		}

		return nil, fmt.Errorf("failed getting runtime policy with name %v. Status: %v, error message: %v", name, events.StatusCode, errorReponse.Message)
	}

	return &response, nil
}

// UpdateRuntimePolicy updates an existing runtime policy policy
func (cli *Client) UpdateRuntimePolicy(runtimePolicy *RuntimePolicy) error {
	payload, err := json.Marshal(runtimePolicy)
	if err != nil {
		return err
	}
	request := cli.gorequest
	apiPath := fmt.Sprintf("/api/v2/runtime_policies/%s", runtimePolicy.Name)
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	resp, _, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Put(cli.url + apiPath).Send(string(payload)).End()
	if errs != nil {
		return errors.Wrap(getMergedError(errs), "failed modifying runtime policy")
	}
	if resp.StatusCode != 201 && resp.StatusCode != 204 {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Printf("Failed to read response Body")
			return err
		}
		var errorResponse ErrorResponse
		err = json.Unmarshal(body, &errorResponse)
		if err != nil {
			log.Printf("Failed to Unmarshal response Body to ErrorResponse. Body: %v. error: %v", string(body), err)
			return err
		}
		return fmt.Errorf("failed modifying runtime policy. status: %v. error message: %v", resp.Status, errorResponse.Message)
	}
	return nil
}

// DeleteRuntimePolicy removes a Aqua runtime policy
func (cli *Client) DeleteRuntimePolicy(name string) error {
	request := cli.gorequest
	apiPath := fmt.Sprintf("/api/v2/runtime_policies/%s", name)
	err := cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	resp, body, errs := request.Clone().Set("Authorization", "Bearer "+cli.token).Delete(cli.url + apiPath).End()
	if errs != nil {
		return errors.Wrap(getMergedError(errs), "failed deleting runtime policy")
	}
	if resp.StatusCode != 204 {
		var errorResponse ErrorResponse
		err := json.Unmarshal([]byte(body), &errorResponse)
		if err != nil {
			log.Printf("Failed to Unmarshal response Body to ErrorResponse. Body: %v.", body)
			return err
		}
		return fmt.Errorf("failed deleting runtime policy, status: %v. error message: %v", resp.Status, errorResponse.Message)
	}
	return nil
}
