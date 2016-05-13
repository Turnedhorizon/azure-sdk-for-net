// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for
// license information.
// 
// Code generated by Microsoft (R) AutoRest Code Generator 0.16.0.0
// Changes may cause incorrect behavior and will be lost if the code is
// regenerated.

namespace Microsoft.Azure.Management.DevTestLabs
{
    using System;
    using System.Collections;
    using System.Collections.Generic;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.Rest;
    using Microsoft.Rest.Azure.OData;
    using Microsoft.Rest.Azure;
    using Models;

    /// <summary>
    /// Extension methods for ScheduleOperations.
    /// </summary>
    public static partial class ScheduleOperationsExtensions
    {
            /// <summary>
            /// List schedules.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The name of the resource group.
            /// </param>
            /// <param name='labName'>
            /// The name of the lab.
            /// </param>
            /// <param name='odataQuery'>
            /// OData parameters to apply to the operation.
            /// </param>
            public static IPage<Schedule> List(this IScheduleOperations operations, string resourceGroupName, string labName, ODataQuery<Schedule> odataQuery = default(ODataQuery<Schedule>))
            {
                return Task.Factory.StartNew(s => ((IScheduleOperations)s).ListAsync(resourceGroupName, labName, odataQuery), operations, CancellationToken.None, TaskCreationOptions.None, TaskScheduler.Default).Unwrap().GetAwaiter().GetResult();
            }

            /// <summary>
            /// List schedules.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The name of the resource group.
            /// </param>
            /// <param name='labName'>
            /// The name of the lab.
            /// </param>
            /// <param name='odataQuery'>
            /// OData parameters to apply to the operation.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<IPage<Schedule>> ListAsync(this IScheduleOperations operations, string resourceGroupName, string labName, ODataQuery<Schedule> odataQuery = default(ODataQuery<Schedule>), CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.ListWithHttpMessagesAsync(resourceGroupName, labName, odataQuery, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// Get schedule.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The name of the resource group.
            /// </param>
            /// <param name='labName'>
            /// The name of the lab.
            /// </param>
            /// <param name='name'>
            /// The name of the schedule.
            /// </param>
            public static Schedule GetResource(this IScheduleOperations operations, string resourceGroupName, string labName, string name)
            {
                return Task.Factory.StartNew(s => ((IScheduleOperations)s).GetResourceAsync(resourceGroupName, labName, name), operations, CancellationToken.None, TaskCreationOptions.None, TaskScheduler.Default).Unwrap().GetAwaiter().GetResult();
            }

            /// <summary>
            /// Get schedule.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The name of the resource group.
            /// </param>
            /// <param name='labName'>
            /// The name of the lab.
            /// </param>
            /// <param name='name'>
            /// The name of the schedule.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<Schedule> GetResourceAsync(this IScheduleOperations operations, string resourceGroupName, string labName, string name, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.GetResourceWithHttpMessagesAsync(resourceGroupName, labName, name, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// Create or replace an existing schedule. This operation can take a while to
            /// complete.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The name of the resource group.
            /// </param>
            /// <param name='labName'>
            /// The name of the lab.
            /// </param>
            /// <param name='name'>
            /// The name of the schedule.
            /// </param>
            /// <param name='schedule'>
            /// </param>
            public static Schedule CreateOrUpdateResource(this IScheduleOperations operations, string resourceGroupName, string labName, string name, Schedule schedule)
            {
                return Task.Factory.StartNew(s => ((IScheduleOperations)s).CreateOrUpdateResourceAsync(resourceGroupName, labName, name, schedule), operations, CancellationToken.None, TaskCreationOptions.None, TaskScheduler.Default).Unwrap().GetAwaiter().GetResult();
            }

            /// <summary>
            /// Create or replace an existing schedule. This operation can take a while to
            /// complete.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The name of the resource group.
            /// </param>
            /// <param name='labName'>
            /// The name of the lab.
            /// </param>
            /// <param name='name'>
            /// The name of the schedule.
            /// </param>
            /// <param name='schedule'>
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<Schedule> CreateOrUpdateResourceAsync(this IScheduleOperations operations, string resourceGroupName, string labName, string name, Schedule schedule, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.CreateOrUpdateResourceWithHttpMessagesAsync(resourceGroupName, labName, name, schedule, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// Create or replace an existing schedule. This operation can take a while to
            /// complete.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The name of the resource group.
            /// </param>
            /// <param name='labName'>
            /// The name of the lab.
            /// </param>
            /// <param name='name'>
            /// The name of the schedule.
            /// </param>
            /// <param name='schedule'>
            /// </param>
            public static Schedule BeginCreateOrUpdateResource(this IScheduleOperations operations, string resourceGroupName, string labName, string name, Schedule schedule)
            {
                return Task.Factory.StartNew(s => ((IScheduleOperations)s).BeginCreateOrUpdateResourceAsync(resourceGroupName, labName, name, schedule), operations, CancellationToken.None, TaskCreationOptions.None, TaskScheduler.Default).Unwrap().GetAwaiter().GetResult();
            }

            /// <summary>
            /// Create or replace an existing schedule. This operation can take a while to
            /// complete.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The name of the resource group.
            /// </param>
            /// <param name='labName'>
            /// The name of the lab.
            /// </param>
            /// <param name='name'>
            /// The name of the schedule.
            /// </param>
            /// <param name='schedule'>
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<Schedule> BeginCreateOrUpdateResourceAsync(this IScheduleOperations operations, string resourceGroupName, string labName, string name, Schedule schedule, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.BeginCreateOrUpdateResourceWithHttpMessagesAsync(resourceGroupName, labName, name, schedule, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// Delete schedule. This operation can take a while to complete.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The name of the resource group.
            /// </param>
            /// <param name='labName'>
            /// The name of the lab.
            /// </param>
            /// <param name='name'>
            /// The name of the schedule.
            /// </param>
            public static void DeleteResource(this IScheduleOperations operations, string resourceGroupName, string labName, string name)
            {
                Task.Factory.StartNew(s => ((IScheduleOperations)s).DeleteResourceAsync(resourceGroupName, labName, name), operations, CancellationToken.None, TaskCreationOptions.None, TaskScheduler.Default).Unwrap().GetAwaiter().GetResult();
            }

            /// <summary>
            /// Delete schedule. This operation can take a while to complete.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The name of the resource group.
            /// </param>
            /// <param name='labName'>
            /// The name of the lab.
            /// </param>
            /// <param name='name'>
            /// The name of the schedule.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task DeleteResourceAsync(this IScheduleOperations operations, string resourceGroupName, string labName, string name, CancellationToken cancellationToken = default(CancellationToken))
            {
                await operations.DeleteResourceWithHttpMessagesAsync(resourceGroupName, labName, name, null, cancellationToken).ConfigureAwait(false);
            }

            /// <summary>
            /// Delete schedule. This operation can take a while to complete.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The name of the resource group.
            /// </param>
            /// <param name='labName'>
            /// The name of the lab.
            /// </param>
            /// <param name='name'>
            /// The name of the schedule.
            /// </param>
            public static void BeginDeleteResource(this IScheduleOperations operations, string resourceGroupName, string labName, string name)
            {
                Task.Factory.StartNew(s => ((IScheduleOperations)s).BeginDeleteResourceAsync(resourceGroupName, labName, name), operations, CancellationToken.None, TaskCreationOptions.None, TaskScheduler.Default).Unwrap().GetAwaiter().GetResult();
            }

            /// <summary>
            /// Delete schedule. This operation can take a while to complete.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The name of the resource group.
            /// </param>
            /// <param name='labName'>
            /// The name of the lab.
            /// </param>
            /// <param name='name'>
            /// The name of the schedule.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task BeginDeleteResourceAsync(this IScheduleOperations operations, string resourceGroupName, string labName, string name, CancellationToken cancellationToken = default(CancellationToken))
            {
                await operations.BeginDeleteResourceWithHttpMessagesAsync(resourceGroupName, labName, name, null, cancellationToken).ConfigureAwait(false);
            }

            /// <summary>
            /// Modify properties of schedules.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The name of the resource group.
            /// </param>
            /// <param name='labName'>
            /// The name of the lab.
            /// </param>
            /// <param name='name'>
            /// The name of the schedule.
            /// </param>
            /// <param name='schedule'>
            /// </param>
            public static Schedule PatchResource(this IScheduleOperations operations, string resourceGroupName, string labName, string name, Schedule schedule)
            {
                return Task.Factory.StartNew(s => ((IScheduleOperations)s).PatchResourceAsync(resourceGroupName, labName, name, schedule), operations, CancellationToken.None, TaskCreationOptions.None, TaskScheduler.Default).Unwrap().GetAwaiter().GetResult();
            }

            /// <summary>
            /// Modify properties of schedules.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The name of the resource group.
            /// </param>
            /// <param name='labName'>
            /// The name of the lab.
            /// </param>
            /// <param name='name'>
            /// The name of the schedule.
            /// </param>
            /// <param name='schedule'>
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<Schedule> PatchResourceAsync(this IScheduleOperations operations, string resourceGroupName, string labName, string name, Schedule schedule, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.PatchResourceWithHttpMessagesAsync(resourceGroupName, labName, name, schedule, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// List schedules.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='nextPageLink'>
            /// The NextLink from the previous successful call to List operation.
            /// </param>
            public static IPage<Schedule> ListNext(this IScheduleOperations operations, string nextPageLink)
            {
                return Task.Factory.StartNew(s => ((IScheduleOperations)s).ListNextAsync(nextPageLink), operations, CancellationToken.None, TaskCreationOptions.None, TaskScheduler.Default).Unwrap().GetAwaiter().GetResult();
            }

            /// <summary>
            /// List schedules.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='nextPageLink'>
            /// The NextLink from the previous successful call to List operation.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<IPage<Schedule>> ListNextAsync(this IScheduleOperations operations, string nextPageLink, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.ListNextWithHttpMessagesAsync(nextPageLink, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

    }
}
