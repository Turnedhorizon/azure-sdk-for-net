// Code generated by Microsoft (R) AutoRest Code Generator 0.17.0.0
// Changes may cause incorrect behavior and will be lost if the code is
// regenerated.

namespace Microsoft.Azure.KeyVault.Models
{
    using System;
    using System.Linq;
    using System.Collections.Generic;
    using Newtonsoft.Json;
    using Microsoft.Rest;
    using Microsoft.Rest.Serialization;
    using Microsoft.Rest.Azure;

    public partial class IssuerCredentials
    {
        /// <summary>
        /// Initializes a new instance of the IssuerCredentials class.
        /// </summary>
        public IssuerCredentials() { }

        /// <summary>
        /// Initializes a new instance of the IssuerCredentials class.
        /// </summary>
        /// <param name="accountId">The user name/account name/account id.</param>
        /// <param name="password">The password/secret/account key.</param>
        public IssuerCredentials(string accountId = default(string), string password = default(string))
        {
            AccountId = accountId;
            Password = password;
        }

        /// <summary>
        /// Gets or sets the user name/account name/account id.
        /// </summary>
        [JsonProperty(PropertyName = "account_id")]
        public string AccountId { get; set; }

        /// <summary>
        /// Gets or sets the password/secret/account key.
        /// </summary>
        [JsonProperty(PropertyName = "pwd")]
        public string Password { get; set; }

    }
}
