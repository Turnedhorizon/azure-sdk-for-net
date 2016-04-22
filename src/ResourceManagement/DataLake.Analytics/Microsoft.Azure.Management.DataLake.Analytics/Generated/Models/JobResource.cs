// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for
// license information.
// 
// Code generated by Microsoft (R) AutoRest Code Generator 0.16.0.0
// Changes may cause incorrect behavior and will be lost if the code is
// regenerated.

namespace Microsoft.Azure.Management.DataLake.Analytics.Models
{
    using System;
    using System.Linq;
    using System.Collections.Generic;
    using Newtonsoft.Json;
    using Microsoft.Rest;
    using Microsoft.Rest.Serialization;
    using Microsoft.Rest.Azure;

    /// <summary>
    /// The Data Lake Analytics U-SQL job resources.
    /// </summary>
    public partial class JobResource
    {
        /// <summary>
        /// Initializes a new instance of the JobResource class.
        /// </summary>
        public JobResource() { }

        /// <summary>
        /// Initializes a new instance of the JobResource class.
        /// </summary>
        public JobResource(string name = default(string), string resourcePath = default(string), JobResourceType? type = default(JobResourceType?))
        {
            Name = name;
            ResourcePath = resourcePath;
            Type = type;
        }

        /// <summary>
        /// Gets or set the name of the resource.
        /// </summary>
        [JsonProperty(PropertyName = "name")]
        public string Name { get; set; }

        /// <summary>
        /// Gets or sets the path to the resource.
        /// </summary>
        [JsonProperty(PropertyName = "resourcePath")]
        public string ResourcePath { get; set; }

        /// <summary>
        /// Gets or sets the job resource type. Possible values include:
        /// 'VertexResource', 'StatisticsResource'
        /// </summary>
        [JsonProperty(PropertyName = "type")]
        public JobResourceType? Type { get; set; }

    }
}
