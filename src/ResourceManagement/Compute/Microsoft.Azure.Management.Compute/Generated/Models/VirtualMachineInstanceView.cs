// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for
// license information.
// 
// Code generated by Microsoft (R) AutoRest Code Generator 0.16.0.0
// Changes may cause incorrect behavior and will be lost if the code is
// regenerated.

namespace Microsoft.Azure.Management.Compute.Models
{
    using System;
    using System.Linq;
    using System.Collections.Generic;
    using Newtonsoft.Json;
    using Microsoft.Rest;
    using Microsoft.Rest.Serialization;
    using Microsoft.Rest.Azure;

    /// <summary>
    /// The instance view of a virtual machine.
    /// </summary>
    public partial class VirtualMachineInstanceView
    {
        /// <summary>
        /// Initializes a new instance of the VirtualMachineInstanceView class.
        /// </summary>
        public VirtualMachineInstanceView() { }

        /// <summary>
        /// Initializes a new instance of the VirtualMachineInstanceView class.
        /// </summary>
        public VirtualMachineInstanceView(int? platformUpdateDomain = default(int?), int? platformFaultDomain = default(int?), string rdpThumbPrint = default(string), VirtualMachineAgentInstanceView vmAgent = default(VirtualMachineAgentInstanceView), IList<DiskInstanceView> disks = default(IList<DiskInstanceView>), IList<VirtualMachineExtensionInstanceView> extensions = default(IList<VirtualMachineExtensionInstanceView>), BootDiagnosticsInstanceView bootDiagnostics = default(BootDiagnosticsInstanceView), IList<InstanceViewStatus> statuses = default(IList<InstanceViewStatus>))
        {
            PlatformUpdateDomain = platformUpdateDomain;
            PlatformFaultDomain = platformFaultDomain;
            RdpThumbPrint = rdpThumbPrint;
            VmAgent = vmAgent;
            Disks = disks;
            Extensions = extensions;
            BootDiagnostics = bootDiagnostics;
            Statuses = statuses;
        }

        /// <summary>
        /// Gets or sets the Update Domain count.
        /// </summary>
        [JsonProperty(PropertyName = "platformUpdateDomain")]
        public int? PlatformUpdateDomain { get; set; }

        /// <summary>
        /// Gets or sets the Fault Domain count.
        /// </summary>
        [JsonProperty(PropertyName = "platformFaultDomain")]
        public int? PlatformFaultDomain { get; set; }

        /// <summary>
        /// Gets or sets the Remote desktop certificate thumbprint.
        /// </summary>
        [JsonProperty(PropertyName = "rdpThumbPrint")]
        public string RdpThumbPrint { get; set; }

        /// <summary>
        /// Gets or sets the VM Agent running on the virtual machine.
        /// </summary>
        [JsonProperty(PropertyName = "vmAgent")]
        public VirtualMachineAgentInstanceView VmAgent { get; set; }

        /// <summary>
        /// Gets or sets the disks information.
        /// </summary>
        [JsonProperty(PropertyName = "disks")]
        public IList<DiskInstanceView> Disks { get; set; }

        /// <summary>
        /// Gets or sets the extensions information.
        /// </summary>
        [JsonProperty(PropertyName = "extensions")]
        public IList<VirtualMachineExtensionInstanceView> Extensions { get; set; }

        /// <summary>
        /// Gets or sets the boot diagnostics.
        /// </summary>
        [JsonProperty(PropertyName = "bootDiagnostics")]
        public BootDiagnosticsInstanceView BootDiagnostics { get; set; }

        /// <summary>
        /// Gets or sets the resource status information.
        /// </summary>
        [JsonProperty(PropertyName = "statuses")]
        public IList<InstanceViewStatus> Statuses { get; set; }

    }
}
