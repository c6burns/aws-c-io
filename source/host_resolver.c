/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/io/host_resolver.h>

#include <aws/common/atomics.h>
#include <aws/common/clock.h>
#include <aws/common/condition_variable.h>
#include <aws/common/hash_table.h>
#include <aws/common/lru_cache.h>
#include <aws/common/mutex.h>
#include <aws/common/string.h>
#include <aws/common/thread.h>

#include <aws/io/logging.h>

const uint64_t NS_PER_SEC = 1000000000;

const size_t g_aws_host_resolver_all_addresses = (size_t)-1;

int aws_host_address_copy(const struct aws_host_address *from, struct aws_host_address *to) {
    to->allocator = from->allocator;
    to->address = aws_string_new_from_string(to->allocator, from->address);

    if (!to->address) {
        return AWS_OP_ERR;
    }

    to->host = aws_string_new_from_string(to->allocator, from->host);

    if (!to->host) {
        aws_string_destroy((void *)to->address);
        return AWS_OP_ERR;
    }

    to->record_type = from->record_type;
    to->use_count = from->use_count;
    to->connection_failure_count = from->connection_failure_count;
    to->expiry = from->expiry;
    to->weight = from->weight;

    return AWS_OP_SUCCESS;
}

void aws_host_address_move(struct aws_host_address *from, struct aws_host_address *to) {
    to->allocator = from->allocator;
    to->address = from->address;
    to->host = from->host;
    to->record_type = from->record_type;
    to->use_count = from->use_count;
    to->connection_failure_count = from->connection_failure_count;
    to->expiry = from->expiry;
    to->weight = from->weight;
    AWS_ZERO_STRUCT(*from);
}

void aws_host_address_clean_up(struct aws_host_address *address) {
    if (address->address) {
        aws_string_destroy((void *)address->address);
    }
    if (address->host) {
        aws_string_destroy((void *)address->host);
    }
    AWS_ZERO_STRUCT(*address);
}

int aws_host_resolver_resolve_host(
    struct aws_host_resolver *resolver,
    const struct aws_string *host_name,
    aws_on_host_resolved_result_fn *res,
    struct aws_host_resolution_config *config,
    void *user_data) {
    AWS_ASSERT(resolver->vtable && resolver->vtable->resolve_host);
    return resolver->vtable->resolve_host(resolver, host_name, res, config, user_data);
}

int aws_host_resolver_purge_cache(struct aws_host_resolver *resolver) {
    AWS_ASSERT(resolver->vtable && resolver->vtable->purge_cache);
    return resolver->vtable->purge_cache(resolver);
}

int aws_host_resolver_record_connection_failure(struct aws_host_resolver *resolver, struct aws_host_address *address) {
    AWS_ASSERT(resolver->vtable && resolver->vtable->record_connection_failure);
    return resolver->vtable->record_connection_failure(resolver, address);
}

int aws_host_resolver_get_cached_addresses(
    struct aws_host_resolver *resolver,
    const struct aws_host_resolver_get_cached_addresses_options *options) {
    AWS_ASSERT(resolver);
    AWS_ASSERT(resolver->vtable);

    if (resolver->vtable->get_cached_addresses) {
        return resolver->vtable->get_cached_addresses(resolver, options);
    }

    aws_raise_error(AWS_ERROR_UNSUPPORTED_OPERATION);
    return AWS_OP_ERR;
}

struct aws_host_resolver_listener *aws_host_resolver_add_listener(
    struct aws_host_resolver *resolver,
    const struct aws_host_resolver_listener_options *options) {
    AWS_ASSERT(resolver);
    AWS_ASSERT(resolver->vtable);

    if (resolver->vtable->add_listener) {
        return resolver->vtable->add_listener(resolver, options);
    }

    aws_raise_error(AWS_ERROR_UNSUPPORTED_OPERATION);
    return NULL;
}

void aws_host_resolver_listener_release(struct aws_host_resolver_listener *listener) {
    AWS_ASSERT(listener);
    AWS_ASSERT(listener->vtable);
    AWS_ASSERT(listener->vtable->release);

    listener->vtable->release(listener);
}

void aws_host_resolver_listener_acquire(struct aws_host_resolver_listener *listener) {
    AWS_ASSERT(listener);
    AWS_ASSERT(listener->vtable);
    AWS_ASSERT(listener->vtable->acquire);

    listener->vtable->acquire(listener);
}

/*
 * Used by both the resolver for its lifetime state as well as individual host entries for theirs.
 */
enum default_resolver_state {
    DRS_ACTIVE,
    DRS_SHUTTING_DOWN,
};

struct default_host_resolver {
    struct aws_allocator *allocator;

    /*
     * Mutually exclusion for the whole resolver, includes all member data and all host_entry_table operations.  Once
     * an entry is retrieved, this lock MAY be dropped but certain logic may hold both the resolver and the entry lock.
     * The two locks must be taken in that order.
     */
    struct aws_mutex resolver_lock;

    /* host_name (string) -> host_entry */
    struct aws_hash_table host_entry_table;

    /* host_name (string) -> listener_entry */
    /* We store these separately from the host entries so that we can add listeners separate from the lifetime of a host
     * entry. */
    struct aws_hash_table listener_table;

    enum default_resolver_state state;

    /*
     * Tracks the number of launched resolution threads that have not yet invoked their shutdown completion
     * callback.
     */
    uint32_t pending_host_entry_shutdown_completion_callbacks;
};

struct host_entry {
    /* immutable post-creation */
    struct aws_allocator *allocator;
    struct aws_host_resolver *resolver;
    struct aws_thread resolver_thread;
    const struct aws_string *host_name;
    int64_t resolve_frequency_ns;
    struct aws_host_resolution_config resolution_config;

    /* synchronized data and its lock */
    struct aws_mutex entry_lock;
    struct aws_condition_variable entry_signal;
    struct aws_cache *aaaa_records;
    struct aws_cache *a_records;
    struct aws_cache *failed_connection_aaaa_records;
    struct aws_cache *failed_connection_a_records;
    struct aws_linked_list pending_resolution_callbacks;
    uint32_t resolves_since_last_request;
    uint64_t last_resolve_request_timestamp_ns;
    enum default_resolver_state state;
};

/* Entry for an array of listeners. */
struct listener_entry {
    struct aws_allocator *allocator;
    struct aws_string *host_name;

    /* Synchronized data based on host resolver lock. */
    struct aws_linked_list listeners;
    bool in_use_by_resolver_thread;
    bool has_pending_removals;
};

/* Default host resolver implementation for listener. */
struct default_host_resolver_listener {
    struct aws_host_resolver_listener base;

    struct aws_allocator *allocator;
    struct aws_ref_count ref_count;

    struct aws_host_resolver *host_resolver;
    struct listener_entry *listener_entry;

    aws_host_resolver_resolved_address_fn *resolved_address_callback;
    aws_host_resolver_listener_shutdown_fn *shutdown_callback;
    void *user_data;

    /* Synchronized data based on host resolver lock.  If this has been moved out of the listener entry's list (ie: by
     * s_move_resolver_listeners_to_local_list) then holding the lock is not necessary. */
    struct aws_linked_list_node node;
    bool pending_removal;
};

static void s_shutdown_host_entry(struct host_entry *entry) {
    aws_mutex_lock(&entry->entry_lock);
    entry->state = DRS_SHUTTING_DOWN;
    aws_mutex_unlock(&entry->entry_lock);
}

/*
 * resolver lock must be held before calling this function
 */
static void s_clear_default_resolver_entry_table(struct default_host_resolver *resolver) {
    struct aws_hash_table *table = &resolver->host_entry_table;
    for (struct aws_hash_iter iter = aws_hash_iter_begin(table); !aws_hash_iter_done(&iter);
         aws_hash_iter_next(&iter)) {
        struct host_entry *entry = iter.element.value;
        s_shutdown_host_entry(entry);
    }

    aws_hash_table_clear(table);
}

static int resolver_purge_cache(struct aws_host_resolver *resolver) {
    struct default_host_resolver *default_host_resolver = resolver->impl;
    aws_mutex_lock(&default_host_resolver->resolver_lock);
    s_clear_default_resolver_entry_table(default_host_resolver);
    aws_mutex_unlock(&default_host_resolver->resolver_lock);

    return AWS_OP_SUCCESS;
}

static void s_cleanup_default_resolver(struct aws_host_resolver *resolver) {
    struct default_host_resolver *default_host_resolver = resolver->impl;

    aws_hash_table_clean_up(&default_host_resolver->host_entry_table);
    aws_hash_table_clean_up(&default_host_resolver->listener_table);
    aws_mutex_clean_up(&default_host_resolver->resolver_lock);

    aws_simple_completion_callback *shutdown_callback = resolver->shutdown_options.shutdown_callback_fn;
    void *shutdown_completion_user_data = resolver->shutdown_options.shutdown_callback_user_data;

    aws_mem_release(resolver->allocator, resolver);

    /* invoke shutdown completion finally */
    if (shutdown_callback != NULL) {
        shutdown_callback(shutdown_completion_user_data);
    }

    aws_global_thread_creator_decrement();
}

static void resolver_destroy(struct aws_host_resolver *resolver) {
    struct default_host_resolver *default_host_resolver = resolver->impl;

    bool cleanup_resolver = false;

    aws_mutex_lock(&default_host_resolver->resolver_lock);

    AWS_FATAL_ASSERT(default_host_resolver->state == DRS_ACTIVE);

    s_clear_default_resolver_entry_table(default_host_resolver);
    default_host_resolver->state = DRS_SHUTTING_DOWN;
    if (default_host_resolver->pending_host_entry_shutdown_completion_callbacks == 0) {
        cleanup_resolver = true;
    }
    aws_mutex_unlock(&default_host_resolver->resolver_lock);

    if (cleanup_resolver) {
        s_cleanup_default_resolver(resolver);
    }
}

struct pending_callback {
    aws_on_host_resolved_result_fn *callback;
    void *user_data;
    struct aws_linked_list_node node;
};

static void s_clean_up_host_entry(struct host_entry *entry) {
    if (entry == NULL) {
        return;
    }

    /*
     * This can happen if the resolver's final reference drops while an unanswered query is pending on an entry.
     *
     * You could add an assertion that the resolver is in the shut down state if this condition hits but that
     * requires additional locking just to make the assert.
     */
    if (!aws_linked_list_empty(&entry->pending_resolution_callbacks)) {
        aws_raise_error(AWS_IO_DNS_HOST_REMOVED_FROM_CACHE);
    }

    while (!aws_linked_list_empty(&entry->pending_resolution_callbacks)) {
        struct aws_linked_list_node *resolution_callback_node =
            aws_linked_list_pop_front(&entry->pending_resolution_callbacks);
        struct pending_callback *pending_callback =
            AWS_CONTAINER_OF(resolution_callback_node, struct pending_callback, node);

        pending_callback->callback(
            entry->resolver, entry->host_name, AWS_IO_DNS_HOST_REMOVED_FROM_CACHE, NULL, pending_callback->user_data);

        aws_mem_release(entry->allocator, pending_callback);
    }

    aws_cache_destroy(entry->aaaa_records);
    aws_cache_destroy(entry->a_records);
    aws_cache_destroy(entry->failed_connection_a_records);
    aws_cache_destroy(entry->failed_connection_aaaa_records);
    aws_string_destroy((void *)entry->host_name);
    aws_mem_release(entry->allocator, entry);
}

static void s_on_host_entry_shutdown_completion(void *user_data) {
    struct host_entry *entry = user_data;
    struct aws_host_resolver *resolver = entry->resolver;
    struct default_host_resolver *default_host_resolver = resolver->impl;

    s_clean_up_host_entry(entry);

    bool cleanup_resolver = false;

    aws_mutex_lock(&default_host_resolver->resolver_lock);
    --default_host_resolver->pending_host_entry_shutdown_completion_callbacks;
    if (default_host_resolver->state == DRS_SHUTTING_DOWN &&
        default_host_resolver->pending_host_entry_shutdown_completion_callbacks == 0) {
        cleanup_resolver = true;
    }
    aws_mutex_unlock(&default_host_resolver->resolver_lock);

    if (cleanup_resolver) {
        s_cleanup_default_resolver(resolver);
    }
}

/* this only ever gets called after resolution has already run. We expect that the entry's lock
   has been aquired for writing before this function is called and released afterwards. */
static inline void process_records(
    struct aws_allocator *allocator,
    struct aws_cache *records,
    struct aws_cache *failed_records) {
    uint64_t timestamp = 0;
    aws_sys_clock_get_ticks(&timestamp);

    size_t record_count = aws_cache_get_element_count(records);
    size_t expired_records = 0;

    /* since this only ever gets called after resolution has already run, we're in a dns outage
     * if everything is expired. Leave an element so we can keep trying. */
    for (size_t index = 0; index < record_count && expired_records < record_count - 1; ++index) {
        struct aws_host_address *lru_element = aws_lru_cache_use_lru_element(records);

        if (lru_element->expiry < timestamp) {
            AWS_LOGF_DEBUG(
                AWS_LS_IO_DNS,
                "static: purging expired record %s for %s",
                lru_element->address->bytes,
                lru_element->host->bytes);
            expired_records++;

            aws_cache_remove(records, lru_element->address);
        }
    }

    record_count = aws_cache_get_element_count(records);
    AWS_LOGF_TRACE(AWS_LS_IO_DNS, "static: remaining record count for host %d", (int)record_count);

    /* if we don't have any known good addresses, take the least recently used, but not expired address with a history
     * of spotty behavior and upgrade it for reuse. If it's expired, leave it and let the resolve fail. Better to fail
     * than accidentally give a kids' app an IP address to somebody's adult website when the IP address gets rebound to
     * a different endpoint. The moral of the story here is to not disable SSL verification! */
    if (!record_count) {
        size_t failed_count = aws_cache_get_element_count(failed_records);
        for (size_t index = 0; index < failed_count; ++index) {
            struct aws_host_address *lru_element = aws_lru_cache_use_lru_element(failed_records);

            if (timestamp < lru_element->expiry) {
                struct aws_host_address *to_add = aws_mem_acquire(allocator, sizeof(struct aws_host_address));

                if (to_add && !aws_host_address_copy(lru_element, to_add)) {
                    AWS_LOGF_INFO(
                        AWS_LS_IO_DNS,
                        "static: promoting spotty record %s for %s back to good list",
                        lru_element->address->bytes,
                        lru_element->host->bytes);
                    if (aws_cache_put(records, to_add->address, to_add)) {
                        aws_mem_release(allocator, to_add);
                        continue;
                    }
                    /* we only want to promote one per process run.*/
                    aws_cache_remove(failed_records, lru_element->address);
                    break;
                }

                if (to_add) {
                    aws_mem_release(allocator, to_add);
                }
            }
        }
    }
}

static int resolver_record_connection_failure(struct aws_host_resolver *resolver, struct aws_host_address *address) {
    struct default_host_resolver *default_host_resolver = resolver->impl;

    AWS_LOGF_INFO(
        AWS_LS_IO_DNS,
        "id=%p: recording failure for record %s for %s, moving to bad list",
        (void *)resolver,
        address->address->bytes,
        address->host->bytes);

    aws_mutex_lock(&default_host_resolver->resolver_lock);

    struct aws_hash_element *element = NULL;
    if (aws_hash_table_find(&default_host_resolver->host_entry_table, address->host, &element)) {
        aws_mutex_unlock(&default_host_resolver->resolver_lock);
        return AWS_OP_ERR;
    }

    struct host_entry *host_entry = NULL;
    if (element != NULL) {
        host_entry = element->value;
        AWS_FATAL_ASSERT(host_entry);
    }

    if (host_entry) {
        struct aws_host_address *cached_address = NULL;

        aws_mutex_lock(&host_entry->entry_lock);
        aws_mutex_unlock(&default_host_resolver->resolver_lock);
        struct aws_cache *address_table =
            address->record_type == AWS_ADDRESS_RECORD_TYPE_AAAA ? host_entry->aaaa_records : host_entry->a_records;

        struct aws_cache *failed_table = address->record_type == AWS_ADDRESS_RECORD_TYPE_AAAA
                                             ? host_entry->failed_connection_aaaa_records
                                             : host_entry->failed_connection_a_records;

        aws_cache_find(address_table, address->address, (void **)&cached_address);

        struct aws_host_address *address_copy = NULL;
        if (cached_address) {
            address_copy = aws_mem_acquire(resolver->allocator, sizeof(struct aws_host_address));

            if (!address_copy || aws_host_address_copy(cached_address, address_copy)) {
                goto error_host_entry_cleanup;
            }

            if (aws_cache_remove(address_table, cached_address->address)) {
                goto error_host_entry_cleanup;
            }

            address_copy->connection_failure_count += 1;

            if (aws_cache_put(failed_table, address_copy->address, address_copy)) {
                goto error_host_entry_cleanup;
            }
        } else {
            if (aws_cache_find(failed_table, address->address, (void **)&cached_address)) {
                goto error_host_entry_cleanup;
            }

            if (cached_address) {
                cached_address->connection_failure_count += 1;
            }
        }
        aws_mutex_unlock(&host_entry->entry_lock);
        return AWS_OP_SUCCESS;

    error_host_entry_cleanup:
        if (address_copy) {
            aws_host_address_clean_up(address_copy);
            aws_mem_release(resolver->allocator, address_copy);
        }
        aws_mutex_unlock(&host_entry->entry_lock);
        return AWS_OP_ERR;
    }

    aws_mutex_unlock(&default_host_resolver->resolver_lock);

    return AWS_OP_SUCCESS;
}

/*
 * A bunch of convenience functions for the host resolver background thread function
 */

static struct aws_host_address *s_find_cached_address_aux(
    struct aws_cache *primary_records,
    struct aws_cache *fallback_records,
    const struct aws_string *address) {

    struct aws_host_address *found = NULL;
    aws_cache_find(primary_records, address, (void **)&found);
    if (found == NULL) {
        aws_cache_find(fallback_records, address, (void **)&found);
    }

    return found;
}

/*
 * Looks in both the good and failed connection record sets for a given host record
 */
static struct aws_host_address *s_find_cached_address(
    struct host_entry *entry,
    const struct aws_string *address,
    enum aws_address_record_type record_type) {

    switch (record_type) {
        case AWS_ADDRESS_RECORD_TYPE_AAAA:
            return s_find_cached_address_aux(entry->aaaa_records, entry->failed_connection_aaaa_records, address);

        case AWS_ADDRESS_RECORD_TYPE_A:
            return s_find_cached_address_aux(entry->a_records, entry->failed_connection_a_records, address);

        default:
            return NULL;
    }
}

static struct aws_host_address *s_get_lru_address_aux(
    struct aws_cache *primary_records,
    struct aws_cache *fallback_records) {

    struct aws_host_address *address = aws_lru_cache_use_lru_element(primary_records);
    if (address == NULL) {
        aws_lru_cache_use_lru_element(fallback_records);
    }

    return address;
}

/*
 * Looks in both the good and failed connection record sets for the LRU host record
 */
static struct aws_host_address *s_get_lru_address(struct host_entry *entry, enum aws_address_record_type record_type) {
    switch (record_type) {
        case AWS_ADDRESS_RECORD_TYPE_AAAA:
            return s_get_lru_address_aux(entry->aaaa_records, entry->failed_connection_aaaa_records);

        case AWS_ADDRESS_RECORD_TYPE_A:
            return s_get_lru_address_aux(entry->a_records, entry->failed_connection_a_records);

        default:
            return NULL;
    }
}

static void s_clear_address_list(struct aws_array_list *address_list) {
    for (size_t i = 0; i < aws_array_list_length(address_list); ++i) {
        struct aws_host_address *address = NULL;
        aws_array_list_get_at_ptr(address_list, (void **)&address, i);
        aws_host_address_clean_up(address);
    }

    aws_array_list_clear(address_list);
}

static void s_update_address_cache(
    struct host_entry *host_entry,
    struct aws_array_list *address_list,
    uint64_t new_expiration,
    struct aws_array_list *out_new_address_list) {

    for (size_t i = 0; i < aws_array_list_length(address_list); ++i) {
        struct aws_host_address *fresh_resolved_address = NULL;
        aws_array_list_get_at_ptr(address_list, (void **)&fresh_resolved_address, i);

        struct aws_host_address *address_to_cache =
            s_find_cached_address(host_entry, fresh_resolved_address->address, fresh_resolved_address->record_type);

        if (address_to_cache) {
            address_to_cache->expiry = new_expiration;
            AWS_LOGF_TRACE(
                AWS_LS_IO_DNS,
                "static: updating expiry for %s for host %s to %llu",
                address_to_cache->address->bytes,
                host_entry->host_name->bytes,
                (unsigned long long)new_expiration);
        } else {
            address_to_cache = aws_mem_acquire(host_entry->allocator, sizeof(struct aws_host_address));

            if (address_to_cache) {
                aws_host_address_move(fresh_resolved_address, address_to_cache);
                address_to_cache->expiry = new_expiration;

                struct aws_cache *address_table = address_to_cache->record_type == AWS_ADDRESS_RECORD_TYPE_AAAA
                                                      ? host_entry->aaaa_records
                                                      : host_entry->a_records;

                if (aws_cache_put(address_table, address_to_cache->address, address_to_cache)) {
                    AWS_LOGF_ERROR(
                        AWS_LS_IO_DNS,
                        "static: could not add new address to host entry cache for host '%s' in "
                        "s_update_address_cache.",
                        host_entry->host_name->bytes);
                }

                if (aws_array_list_push_back(out_new_address_list, address_to_cache)) {
                    AWS_LOGF_ERROR(
                        AWS_LS_IO_DNS,
                        "static: could not push address to new-address list for host '%s' in s_update_address_cache.",
                        host_entry->host_name->bytes);
                }

                AWS_LOGF_DEBUG(
                    AWS_LS_IO_DNS,
                    "static: new address resolved %s for host %s caching",
                    address_to_cache->address->bytes,
                    host_entry->host_name->bytes);
            }
        }
    }
}

static void s_copy_address_into_callback_set(
    struct aws_host_address *address,
    struct aws_array_list *callback_addresses,
    const struct aws_string *host_name) {

    if (address) {
        address->use_count += 1;

        /*
         * This is the worst.
         *
         * We have to copy the cache address while we still have a write lock.  Otherwise, connection failures
         * can sneak in and destroy our address by moving the address to/from the various lru caches.
         *
         * But there's no nice copy construction into an array list, so we get to
         *   (1) Push a zeroed dummy element onto the array list
         *   (2) Get its pointer
         *   (3) Call aws_host_address_copy onto it.  If that fails, pop the dummy element.
         */
        struct aws_host_address dummy;
        AWS_ZERO_STRUCT(dummy);

        if (aws_array_list_push_back(callback_addresses, &dummy)) {
            return;
        }

        struct aws_host_address *dest_copy = NULL;
        aws_array_list_get_at_ptr(
            callback_addresses, (void **)&dest_copy, aws_array_list_length(callback_addresses) - 1);
        AWS_FATAL_ASSERT(dest_copy != NULL);

        if (aws_host_address_copy(address, dest_copy)) {
            aws_array_list_pop_back(callback_addresses);
            return;
        }

        AWS_LOGF_TRACE(
            AWS_LS_IO_DNS,
            "static: vending address %s for host %s to caller",
            address->address->bytes,
            host_name->bytes);
    }
}

static bool s_host_entry_finished_pred(void *user_data) {
    struct host_entry *entry = user_data;

    return entry->state == DRS_SHUTTING_DOWN;
}

static void s_default_resolver_listener_acquire(struct aws_host_resolver_listener *listener) {
    struct default_host_resolver_listener *default_host_resolver_listener = listener->impl;

    aws_ref_count_acquire(&default_host_resolver_listener->ref_count);
}

/* Assumes resolver lock is held.  Removes a listener from a listener entry, placing it in the passed-in destroy list.
 * The use of the destroy list is to allow this function to be inside of the host resolver lock, and then to do the
 * actual destruction of listeners outside of the lock.  (We want to make sure that any shutdown callbacks that get
 * called do not happen inside of a mutex.)  If there are no more listeners in the listener entry, the listener entry
 * will be cleaned up, and the pointer to listener_entry will be set to NULL. */
static void s_default_resolver_listener_remove(
    struct default_host_resolver *resolver,
    struct listener_entry **listener_entry,
    struct default_host_resolver_listener *listener,
    struct aws_linked_list *destroy_list) {

    AWS_LOGF_TRACE(AWS_LS_IO_DNS, "id=%p: Removing resolver listener from listener entry.", (void *)listener);

    aws_linked_list_remove(&listener->node);

    if (aws_linked_list_empty(&(*listener_entry)->listeners)) {
        AWS_LOGF_TRACE(
            AWS_LS_IO_DNS,
            "id=%p: Listener entry is now empty.  Removing it from host resolver.",
            (void *)listener_entry);

        int was_found = 0;
        aws_hash_table_remove(&resolver->listener_table, (*listener_entry)->host_name, NULL, &was_found);

        AWS_ASSERT(was_found);
        (void)was_found;

        *listener_entry = NULL;
    }

    aws_linked_list_push_back(destroy_list, &listener->node);
}

/* Finish destroying a default resolver listener, releasing any remaining memory for it and triggering its shutdown
 * callack.  No lock should be held when calling this function. */
static void s_default_resolver_listener_destroy(struct default_host_resolver_listener *listener) {

    AWS_LOGF_TRACE(AWS_LS_IO_DNS, "id=%p: Finishing clean up of resolver listener.", (void *)listener);

    struct aws_host_resolver *host_resolver = listener->host_resolver;

    aws_host_resolver_listener_shutdown_fn *shutdown_callback = listener->shutdown_callback;
    void *shutdown_user_data = listener->user_data;

    aws_mem_release(listener->allocator, listener);
    listener = NULL;

    if (shutdown_callback != NULL) {
        shutdown_callback(shutdown_user_data);
    }

    if (host_resolver != NULL) {
        aws_host_resolver_release(host_resolver);
        host_resolver = NULL;
    }
}

/* Destroy each host resolver listener in a linked list until the list is empty. */
static void s_default_resolver_listener_list_destroy(struct aws_linked_list *destroy_list) {

    while (!aws_linked_list_empty(destroy_list)) {
        struct aws_linked_list_node *destroy_list_node = aws_linked_list_pop_front(destroy_list);
        struct default_host_resolver_listener *listener =
            AWS_CONTAINER_OF(destroy_list_node, struct default_host_resolver_listener, node);
        s_default_resolver_listener_destroy(listener);
    }
}

/* Callback for when all reference counts for a listener have been released. */
static void s_default_resolver_listener_zero_ref_count(void *object) {
    struct default_host_resolver_listener *listener = object;

    AWS_LOGF_TRACE(AWS_LS_IO_DNS, "id=%p: Resolver Listener reached zero ref count, initiating removal.", object);

    struct aws_host_resolver *host_resolver = listener->host_resolver;
    struct default_host_resolver *default_host_resolver = host_resolver->impl;

    struct aws_linked_list destroy_list;
    aws_linked_list_init(&destroy_list);

    aws_mutex_lock(&default_host_resolver->resolver_lock);

    /* Nuke this listener on the next resolver thread iteration. */
    listener->pending_removal = true;

    struct listener_entry *listener_entry = listener->listener_entry;
    AWS_FATAL_ASSERT(listener_entry);

    /* If this listener entry is currently in use by a resolver thread, we can't immediately remove it.  But we can flag
     * it for removal when the resolver thread is done using it.*/
    if (listener_entry->in_use_by_resolver_thread) {
        AWS_LOGF_TRACE(
            AWS_LS_IO_DNS,
            "id=%p: Resolver Listener in use by resolver thread. Removal will happen pending finish of next resolver "
            "thread iteration.",
            object);
        listener_entry->has_pending_removals = true;
    } else {
        s_default_resolver_listener_remove(default_host_resolver, &listener_entry, listener, &destroy_list);
    }

    aws_mutex_unlock(&default_host_resolver->resolver_lock);

    /* Destroy anything in the destroy list (will be empty if the listener entry was in use by the resolver thread) */
    s_default_resolver_listener_list_destroy(&destroy_list);
}

static void s_default_resolver_listener_release(struct aws_host_resolver_listener *listener) {
    struct default_host_resolver_listener *default_host_resolver_listener = listener->impl;
    aws_ref_count_release(&default_host_resolver_listener->ref_count);
}

static struct aws_host_resolver_listener_vtable default_host_resolver_listener_vtable = {
    .acquire = s_default_resolver_listener_acquire,
    .release = s_default_resolver_listener_release};

/* Allocate a new listener entry for the host resolver's listener table. */
static struct listener_entry *s_listener_entry_new(
    struct aws_allocator *allocator,
    const struct aws_string *host_name) {

    struct listener_entry *listener_entry = aws_mem_calloc(allocator, 1, sizeof(struct listener_entry));

    if (listener_entry == NULL) {
        return NULL;
    }

    AWS_LOGF_TRACE(
        AWS_LS_IO_DNS,
        "id=%p Created new listener entry for host name %s",
        (void *)listener_entry,
        (const char *)host_name->bytes);

    listener_entry->allocator = allocator;
    listener_entry->host_name = aws_string_new_from_string(allocator, host_name);
    aws_linked_list_init(&listener_entry->listeners);
    return listener_entry;
}

/* Destroy a listener entry for the host resolver's listener table. */
static void s_listener_entry_destroy(struct listener_entry *listener_entry) {

    AWS_LOGF_TRACE(AWS_LS_IO_DNS, "id=%p Destroying listener entry", (void *)listener_entry);

    if (listener_entry->host_name) {
        aws_string_destroy(listener_entry->host_name);
        listener_entry->host_name = NULL;
    }

    s_default_resolver_listener_list_destroy(&listener_entry->listeners);

    aws_mem_release(listener_entry->allocator, listener_entry);
    listener_entry = NULL;
}

static void s_listener_entry_hash_destroy(void *listener_entry_void) {
    s_listener_entry_destroy(listener_entry_void);
}

/* Move current listeners into the out_listener_list. This assumes that the resolver lock is held. */
static void s_move_resolver_listeners_to_local_list(
    struct default_host_resolver *resolver,
    const struct aws_string *host_name,
    struct aws_linked_list *out_listener_list) {

    struct aws_hash_element *listener_element = NULL;
    aws_hash_table_find(&resolver->listener_table, host_name, &listener_element);

    if (listener_element == NULL) {
        return;
    }

    struct listener_entry *listener_entry = listener_element->value;
    AWS_FATAL_ASSERT(listener_entry);

    listener_entry->in_use_by_resolver_thread = true;

    aws_linked_list_swap_contents(&listener_entry->listeners, out_listener_list);
}

/* Notify the listeners in the listener list of all the new addresses for the host. Assumes that no lock is currently
 * held. */
static void s_notify_listeners_new_addresses(
    struct default_host_resolver *resolver,
    struct aws_array_list *new_address_list,
    struct aws_linked_list *listener_list) {
    (void)resolver;

    if (aws_linked_list_empty(listener_list)) {
        return;
    }

    struct aws_linked_list_node *current_listener_node = aws_linked_list_begin(listener_list);

    while (current_listener_node != aws_linked_list_end(listener_list)) {
        struct default_host_resolver_listener *listener =
            AWS_CONTAINER_OF(current_listener_node, struct default_host_resolver_listener, node);

        for (size_t address_index = 0; address_index < aws_array_list_length(new_address_list); ++address_index) {
            struct aws_host_address *host_address = NULL;
            aws_array_list_get_at_ptr(new_address_list, (void **)&host_address, address_index);

            if (listener->resolved_address_callback != NULL) {
                listener->resolved_address_callback(&listener->base, host_address, listener->user_data);
            }
        }

        current_listener_node = aws_linked_list_next(current_listener_node);
    }
}

/* Assumes that the the resolver lock is held.  Move listeners back to the listener entry from our local list. Any
 * listeners that were marked pending_removal while we were using them will be removed and placed in the destroy list
 * output argument.  We output a destroy list so that we can destroy them outside of the host resolver mutex, avoiding a
 * shutdown callback being called from inside of a lock.*/
static void s_move_local_list_listeners_to_resolver(
    struct default_host_resolver *resolver,
    const struct aws_string *host_name,
    struct aws_linked_list *in_out_listener_list,
    struct aws_linked_list *out_destroy_list) {

    struct aws_hash_element *listener_element = NULL;
    aws_hash_table_find(&resolver->listener_table, host_name, &listener_element);

    struct listener_entry *listener_entry = NULL;
    if (listener_element == NULL) {
        return;
    }

    listener_entry = listener_element->value;
    AWS_FATAL_ASSERT(listener_entry);

    /* If there are no listeners in the listener entry, then we can just swap the contents of the two lists. */
    if (aws_linked_list_empty(&listener_entry->listeners)) {
        aws_linked_list_swap_contents(&listener_entry->listeners, in_out_listener_list);
    } else {
        /* Otherwise, if the listener entry has new listeners in it, then we move each node back individually, so as to
         * not affect the listener entry's new contents. */
        while (!aws_linked_list_empty(in_out_listener_list)) {
            struct aws_linked_list_node *front = aws_linked_list_pop_front(in_out_listener_list);
            aws_linked_list_push_back(&listener_entry->listeners, front);
        }
    }

    listener_entry->in_use_by_resolver_thread = false;

    /* Remove anything that was marked pending removal while we were using the listener. */
    if (listener_entry->has_pending_removals && !aws_linked_list_empty(&listener_entry->listeners)) {
        struct aws_linked_list_node *current_listener_node = aws_linked_list_begin(&listener_entry->listeners);

        while (listener_entry != NULL && current_listener_node != aws_linked_list_end(&listener_entry->listeners)) {
            struct default_host_resolver_listener *listener =
                AWS_CONTAINER_OF(current_listener_node, struct default_host_resolver_listener, node);

            current_listener_node = aws_linked_list_next(current_listener_node);

            if (listener->pending_removal) {
                s_default_resolver_listener_remove(resolver, &listener_entry, listener, out_destroy_list);
            }
        }

        if (listener_entry != NULL) {
            listener_entry->has_pending_removals = false;
        }
    }
}

static void resolver_thread_fn(void *arg) {
    struct host_entry *host_entry = arg;

    size_t unsolicited_resolve_max = host_entry->resolution_config.max_ttl;
    if (unsolicited_resolve_max == 0) {
        unsolicited_resolve_max = 1;
    }

    uint64_t max_no_solicitation_interval =
        aws_timestamp_convert(unsolicited_resolve_max, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_NANOS, NULL);

    struct aws_array_list address_list;
    if (aws_array_list_init_dynamic(&address_list, host_entry->allocator, 4, sizeof(struct aws_host_address))) {
        return;
    }

    struct aws_array_list new_address_list;
    if (aws_array_list_init_dynamic(&new_address_list, host_entry->allocator, 4, sizeof(struct aws_host_address))) {
        aws_array_list_clean_up(&address_list);
        return;
    }

    struct aws_linked_list local_listener_list;
    aws_linked_list_init(&local_listener_list);

    struct aws_linked_list listener_destroy_list;
    aws_linked_list_init(&listener_destroy_list);

    bool keep_going = true;
    while (keep_going) {

        AWS_LOGF_TRACE(AWS_LS_IO_DNS, "static, resolving %s", aws_string_c_str(host_entry->host_name));

        /* resolve and then process each record */
        int err_code = AWS_ERROR_SUCCESS;
        if (host_entry->resolution_config.impl(
                host_entry->allocator, host_entry->host_name, &address_list, host_entry->resolution_config.impl_data)) {

            err_code = aws_last_error();
        }
        uint64_t timestamp = 0;
        aws_sys_clock_get_ticks(&timestamp);
        uint64_t new_expiry = timestamp + (host_entry->resolution_config.max_ttl * NS_PER_SEC);

        struct aws_linked_list pending_resolve_copy;
        aws_linked_list_init(&pending_resolve_copy);

        /*
         * Within the lock we
         *  (1) Update the cache with the newly resolved addresses
         *  (2) Process all held addresses looking for expired or promotable ones
         *  (3) Prep for callback invocations
         */
        aws_mutex_lock(&host_entry->entry_lock);

        if (!err_code) {
            s_update_address_cache(host_entry, &address_list, new_expiry, &new_address_list);
        }

        /*
         * process and clean_up records in the entry. occasionally, failed connect records will be upgraded
         * for retry.
         */
        process_records(host_entry->allocator, host_entry->aaaa_records, host_entry->failed_connection_aaaa_records);
        process_records(host_entry->allocator, host_entry->a_records, host_entry->failed_connection_a_records);

        aws_linked_list_swap_contents(&pending_resolve_copy, &host_entry->pending_resolution_callbacks);

        aws_mutex_unlock(&host_entry->entry_lock);

        /*
         * Clean up resolved addressed outside of the lock
         */
        s_clear_address_list(&address_list);

        struct aws_host_address address_array[2];
        AWS_ZERO_ARRAY(address_array);

        /*
         * Perform the actual subscriber notifications
         */
        while (!aws_linked_list_empty(&pending_resolve_copy)) {
            struct aws_linked_list_node *resolution_callback_node = aws_linked_list_pop_front(&pending_resolve_copy);
            struct pending_callback *pending_callback =
                AWS_CONTAINER_OF(resolution_callback_node, struct pending_callback, node);

            struct aws_array_list callback_address_list;
            aws_array_list_init_static(&callback_address_list, address_array, 2, sizeof(struct aws_host_address));

            aws_mutex_lock(&host_entry->entry_lock);
            s_copy_address_into_callback_set(
                s_get_lru_address(host_entry, AWS_ADDRESS_RECORD_TYPE_AAAA),
                &callback_address_list,
                host_entry->host_name);
            s_copy_address_into_callback_set(
                s_get_lru_address(host_entry, AWS_ADDRESS_RECORD_TYPE_A),
                &callback_address_list,
                host_entry->host_name);
            aws_mutex_unlock(&host_entry->entry_lock);

            AWS_ASSERT(err_code != AWS_ERROR_SUCCESS || aws_array_list_length(&callback_address_list) > 0);

            if (aws_array_list_length(&callback_address_list) > 0) {
                pending_callback->callback(
                    host_entry->resolver,
                    host_entry->host_name,
                    AWS_OP_SUCCESS,
                    &callback_address_list,
                    pending_callback->user_data);

            } else {
                pending_callback->callback(
                    host_entry->resolver, host_entry->host_name, err_code, NULL, pending_callback->user_data);
            }

            s_clear_address_list(&callback_address_list);

            aws_mem_release(host_entry->allocator, pending_callback);
        }

        aws_mutex_lock(&host_entry->entry_lock);

        ++host_entry->resolves_since_last_request;

        /* wait for a quit notification or the base resolve frequency time interval */
        aws_condition_variable_wait_for_pred(
            &host_entry->entry_signal,
            &host_entry->entry_lock,
            host_entry->resolve_frequency_ns,
            s_host_entry_finished_pred,
            host_entry);

        aws_mutex_unlock(&host_entry->entry_lock);

        /*
         * This is a bit awkward that we unlock the entry and then relock both the resolver and the entry, but it
         * is mandatory that -- in order to maintain the consistent view of the resolver table (entry exist => entry
         * is alive and can be queried) -- we have the resolver lock as well before making the decision to remove
         * the entry from the table and terminate the thread.
         */
        struct default_host_resolver *resolver = host_entry->resolver->impl;
        aws_mutex_lock(&resolver->resolver_lock);

        /* Grab all current listeners for this host. */
        s_move_resolver_listeners_to_local_list(resolver, host_entry->host_name, &local_listener_list);

        aws_mutex_lock(&host_entry->entry_lock);

        uint64_t now = 0;
        aws_sys_clock_get_ticks(&now);

        /*
         * Ideally this should just be time-based, but given the non-determinism of waits (and spurious wake ups) and
         * clock time, I feel much more comfortable keeping an additional constraint in terms of iterations.
         *
         * Note that we have the entry lock now and if any queries have arrived since our last resolution,
         * resolves_since_last_request will be 0 or 1 (depending on timing) and so, regardless of wait and wake up
         * timings, this check will always fail in that case leading to another iteration to satisfy the pending
         * query(ies).
         *
         * The only way we terminate the loop with pending queries is if the resolver itself has no more references
         * to it and is going away.  In that case, the pending queries will be completed (with failure) by the
         * final clean up of this entry.
         */
        if (host_entry->resolves_since_last_request > unsolicited_resolve_max &&
            host_entry->last_resolve_request_timestamp_ns + max_no_solicitation_interval < now) {
            host_entry->state = DRS_SHUTTING_DOWN;
        }

        keep_going = host_entry->state == DRS_ACTIVE;
        if (!keep_going) {
            aws_hash_table_remove(&resolver->host_entry_table, host_entry->host_name, NULL, NULL);
        }

        aws_mutex_unlock(&host_entry->entry_lock);
        aws_mutex_unlock(&resolver->resolver_lock);

        /* With no lock held, go ahead and notify all listeners with resolve address callbacks. */
        s_notify_listeners_new_addresses(resolver, &new_address_list, &local_listener_list);

        /* Lock the resolver lock one more time for this iteration, and put all of the listeners back. */
        aws_mutex_lock(&resolver->resolver_lock);
        s_move_local_list_listeners_to_resolver(
            resolver, host_entry->host_name, &local_listener_list, &listener_destroy_list);
        aws_mutex_unlock(&resolver->resolver_lock);

        /* Destroy any listeners that we know now are no longer being referenced.  We intentionally do this outside of a
         * mutex to keep shutdown callbacks from happening inside of a lock. */
        s_default_resolver_listener_list_destroy(&listener_destroy_list);

        aws_array_list_clear(&new_address_list);
    }

    AWS_LOGF_DEBUG(
        AWS_LS_IO_DNS,
        "static: Either no requests have been made for an address for %s for the duration "
        "of the ttl, or this thread is being forcibly shutdown. Killing thread.",
        host_entry->host_name->bytes)

    aws_array_list_clean_up(&address_list);
    aws_array_list_clean_up(&new_address_list);

    /* please don't fail */
    aws_thread_current_at_exit(s_on_host_entry_shutdown_completion, host_entry);
}

static void on_address_value_removed(void *value) {
    struct aws_host_address *host_address = value;

    AWS_LOGF_DEBUG(
        AWS_LS_IO_DNS,
        "static: purging address %s for host %s from "
        "the cache due to cache eviction or shutdown",
        host_address->address->bytes,
        host_address->host->bytes);

    struct aws_allocator *allocator = host_address->allocator;
    aws_host_address_clean_up(host_address);
    aws_mem_release(allocator, host_address);
}

/*
 * The resolver lock must be held before calling this function
 */
static inline int create_and_init_host_entry(
    struct aws_host_resolver *resolver,
    const struct aws_string *host_name,
    aws_on_host_resolved_result_fn *res,
    struct aws_host_resolution_config *config,
    uint64_t timestamp,
    void *user_data) {
    struct host_entry *new_host_entry = aws_mem_calloc(resolver->allocator, 1, sizeof(struct host_entry));
    if (!new_host_entry) {
        return AWS_OP_ERR;
    }

    new_host_entry->resolver = resolver;
    new_host_entry->allocator = resolver->allocator;
    new_host_entry->last_resolve_request_timestamp_ns = timestamp;
    new_host_entry->resolves_since_last_request = 0;
    new_host_entry->resolve_frequency_ns = NS_PER_SEC;
    new_host_entry->state = DRS_ACTIVE;

    bool thread_init = false;
    struct pending_callback *pending_callback = NULL;
    const struct aws_string *host_string_copy = aws_string_new_from_string(resolver->allocator, host_name);
    if (AWS_UNLIKELY(!host_string_copy)) {
        goto setup_host_entry_error;
    }

    new_host_entry->host_name = host_string_copy;
    new_host_entry->a_records = aws_cache_new_lru(
        new_host_entry->allocator,
        aws_hash_string,
        aws_hash_callback_string_eq,
        NULL,
        on_address_value_removed,
        config->max_ttl);
    if (AWS_UNLIKELY(!new_host_entry->a_records)) {
        goto setup_host_entry_error;
    }

    new_host_entry->aaaa_records = aws_cache_new_lru(
        new_host_entry->allocator,
        aws_hash_string,
        aws_hash_callback_string_eq,
        NULL,
        on_address_value_removed,
        config->max_ttl);
    if (AWS_UNLIKELY(!new_host_entry->aaaa_records)) {
        goto setup_host_entry_error;
    }

    new_host_entry->failed_connection_a_records = aws_cache_new_lru(
        new_host_entry->allocator,
        aws_hash_string,
        aws_hash_callback_string_eq,
        NULL,
        on_address_value_removed,
        config->max_ttl);
    if (AWS_UNLIKELY(!new_host_entry->failed_connection_a_records)) {
        goto setup_host_entry_error;
    }

    new_host_entry->failed_connection_aaaa_records = aws_cache_new_lru(
        new_host_entry->allocator,
        aws_hash_string,
        aws_hash_callback_string_eq,
        NULL,
        on_address_value_removed,
        config->max_ttl);
    if (AWS_UNLIKELY(!new_host_entry->failed_connection_aaaa_records)) {
        goto setup_host_entry_error;
    }

    aws_linked_list_init(&new_host_entry->pending_resolution_callbacks);

    pending_callback = aws_mem_acquire(resolver->allocator, sizeof(struct pending_callback));

    if (AWS_UNLIKELY(!pending_callback)) {
        goto setup_host_entry_error;
    }

    /*add the current callback here */
    pending_callback->user_data = user_data;
    pending_callback->callback = res;
    aws_linked_list_push_back(&new_host_entry->pending_resolution_callbacks, &pending_callback->node);

    aws_mutex_init(&new_host_entry->entry_lock);
    new_host_entry->resolution_config = *config;
    aws_condition_variable_init(&new_host_entry->entry_signal);

    if (aws_thread_init(&new_host_entry->resolver_thread, resolver->allocator)) {
        goto setup_host_entry_error;
    }

    thread_init = true;
    struct default_host_resolver *default_host_resolver = resolver->impl;
    if (AWS_UNLIKELY(
            aws_hash_table_put(&default_host_resolver->host_entry_table, host_string_copy, new_host_entry, NULL))) {
        goto setup_host_entry_error;
    }

    aws_thread_launch(&new_host_entry->resolver_thread, resolver_thread_fn, new_host_entry, NULL);
    ++default_host_resolver->pending_host_entry_shutdown_completion_callbacks;

    return AWS_OP_SUCCESS;

setup_host_entry_error:

    if (thread_init) {
        aws_thread_clean_up(&new_host_entry->resolver_thread);
    }

    s_clean_up_host_entry(new_host_entry);

    return AWS_OP_ERR;
}

static int default_resolve_host(
    struct aws_host_resolver *resolver,
    const struct aws_string *host_name,
    aws_on_host_resolved_result_fn *res,
    struct aws_host_resolution_config *config,
    void *user_data) {
    int result = AWS_OP_SUCCESS;

    AWS_LOGF_DEBUG(AWS_LS_IO_DNS, "id=%p: Host resolution requested for %s", (void *)resolver, host_name->bytes);

    uint64_t timestamp = 0;
    aws_sys_clock_get_ticks(&timestamp);

    struct default_host_resolver *default_host_resolver = resolver->impl;
    aws_mutex_lock(&default_host_resolver->resolver_lock);

    struct aws_hash_element *element = NULL;
    /* we don't care about the error code here, only that the host_entry was found or not. */
    aws_hash_table_find(&default_host_resolver->host_entry_table, host_name, &element);

    struct host_entry *host_entry = NULL;
    if (element != NULL) {
        host_entry = element->value;
        AWS_FATAL_ASSERT(host_entry != NULL);
    }

    if (!host_entry) {
        AWS_LOGF_DEBUG(
            AWS_LS_IO_DNS,
            "id=%p: No cached entries found for %s starting new resolver thread.",
            (void *)resolver,
            host_name->bytes);

        result = create_and_init_host_entry(resolver, host_name, res, config, timestamp, user_data);
        aws_mutex_unlock(&default_host_resolver->resolver_lock);

        return result;
    }

    aws_mutex_lock(&host_entry->entry_lock);

    /*
     * We don't need to make any resolver side-affects in the remaining logic and it's impossible for the entry
     * to disappear underneath us while holding its lock, so its safe to release the resolver lock and let other
     * things query other entries.
     */
    aws_mutex_unlock(&default_host_resolver->resolver_lock);
    host_entry->last_resolve_request_timestamp_ns = timestamp;
    host_entry->resolves_since_last_request = 0;

    struct aws_host_address *aaaa_record = aws_lru_cache_use_lru_element(host_entry->aaaa_records);
    struct aws_host_address *a_record = aws_lru_cache_use_lru_element(host_entry->a_records);
    struct aws_host_address address_array[2];
    AWS_ZERO_ARRAY(address_array);
    struct aws_array_list callback_address_list;
    aws_array_list_init_static(&callback_address_list, address_array, 2, sizeof(struct aws_host_address));

    if ((aaaa_record || a_record)) {
        AWS_LOGF_DEBUG(
            AWS_LS_IO_DNS,
            "id=%p: cached entries found for %s returning to caller.",
            (void *)resolver,
            host_name->bytes);

        /* these will all need to be copied so that we don't hold the lock during the callback. */
        if (aaaa_record) {
            struct aws_host_address aaaa_record_cpy;
            if (!aws_host_address_copy(aaaa_record, &aaaa_record_cpy)) {
                aws_array_list_push_back(&callback_address_list, &aaaa_record_cpy);
                AWS_LOGF_TRACE(
                    AWS_LS_IO_DNS,
                    "id=%p: vending address %s for host %s to caller",
                    (void *)resolver,
                    aaaa_record->address->bytes,
                    host_entry->host_name->bytes);
            }
        }
        if (a_record) {
            struct aws_host_address a_record_cpy;
            if (!aws_host_address_copy(a_record, &a_record_cpy)) {
                aws_array_list_push_back(&callback_address_list, &a_record_cpy);
                AWS_LOGF_TRACE(
                    AWS_LS_IO_DNS,
                    "id=%p: vending address %s for host %s to caller",
                    (void *)resolver,
                    a_record->address->bytes,
                    host_entry->host_name->bytes);
            }
        }
        aws_mutex_unlock(&host_entry->entry_lock);

        /* we don't want to do the callback WHILE we hold the lock someone may reentrantly call us. */
        if (aws_array_list_length(&callback_address_list)) {
            res(resolver, host_name, AWS_OP_SUCCESS, &callback_address_list, user_data);
        } else {
            res(resolver, host_name, aws_last_error(), NULL, user_data);
            result = AWS_OP_ERR;
        }

        for (size_t i = 0; i < aws_array_list_length(&callback_address_list); ++i) {
            struct aws_host_address *address_ptr = NULL;
            aws_array_list_get_at_ptr(&callback_address_list, (void **)&address_ptr, i);
            aws_host_address_clean_up(address_ptr);
        }

        aws_array_list_clean_up(&callback_address_list);

        return result;
    }

    struct pending_callback *pending_callback =
        aws_mem_acquire(default_host_resolver->allocator, sizeof(struct pending_callback));
    if (pending_callback != NULL) {
        pending_callback->user_data = user_data;
        pending_callback->callback = res;
        aws_linked_list_push_back(&host_entry->pending_resolution_callbacks, &pending_callback->node);
    } else {
        result = AWS_OP_ERR;
    }

    aws_mutex_unlock(&host_entry->entry_lock);

    return result;
}

static size_t default_get_host_address_count(
    struct aws_host_resolver *host_resolver,
    const struct aws_string *host_name,
    uint32_t flags) {
    struct default_host_resolver *default_host_resolver = host_resolver->impl;
    size_t address_count = 0;

    aws_mutex_lock(&default_host_resolver->resolver_lock);

    struct aws_hash_element *element = NULL;
    aws_hash_table_find(&default_host_resolver->host_entry_table, host_name, &element);
    if (element != NULL) {
        struct host_entry *host_entry = element->value;
        if (host_entry != NULL) {
            aws_mutex_lock(&host_entry->entry_lock);

            if ((flags & AWS_GET_HOST_ADDRESS_COUNT_RECORD_TYPE_A) != 0) {
                address_count += aws_cache_get_element_count(host_entry->a_records);
            }

            if ((flags & AWS_GET_HOST_ADDRESS_COUNT_RECORD_TYPE_AAAA) != 0) {
                address_count += aws_cache_get_element_count(host_entry->aaaa_records);
            }

            aws_mutex_unlock(&host_entry->entry_lock);
        }
    }

    aws_mutex_unlock(&default_host_resolver->resolver_lock);

    return address_count;
}

static struct aws_host_resolver_listener *default_add_listener(
    struct aws_host_resolver *host_resolver,
    const struct aws_host_resolver_listener_options *options) {

    if (options == NULL) {
        AWS_LOGF_ERROR(AWS_LS_IO_DNS, "Cannot create host resolver listener; options structure is NULL.");
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        return NULL;
    }

    if (options->host_name == NULL) {
        AWS_LOGF_ERROR(AWS_LS_IO_DNS, "Cannot create host resolver listener; invalid host name specified.");
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        return NULL;
    }

    struct aws_allocator *allocator = host_resolver->allocator;

    struct default_host_resolver_listener *listener =
        aws_mem_calloc(allocator, 1, sizeof(struct default_host_resolver_listener));

    if (listener == NULL) {
        return NULL;
    }

    listener->base.impl = listener;
    listener->base.vtable = &default_host_resolver_listener_vtable;
    listener->allocator = allocator;

    aws_ref_count_init(&listener->ref_count, listener, s_default_resolver_listener_zero_ref_count);

    aws_host_resolver_acquire(host_resolver);
    listener->host_resolver = host_resolver;

    listener->resolved_address_callback = options->resolved_address_callback;
    listener->shutdown_callback = options->shutdown_callback;
    listener->user_data = options->user_data;

    struct default_host_resolver *default_host_resolver = host_resolver->impl;
    aws_mutex_lock(&default_host_resolver->resolver_lock);

    /* Try to find an existing listener entry in the table. */
    struct aws_hash_element *listener_element = NULL;
    aws_hash_table_find(&default_host_resolver->listener_table, options->host_name, &listener_element);

    struct listener_entry *listener_entry = NULL;
    if (listener_element != NULL) {
        listener_entry = listener_element->value;
        AWS_FATAL_ASSERT(listener_entry);
    }

    /* If there isn't already a listener entry, time to create one. */
    if (listener_entry == NULL) {
        listener_entry = s_listener_entry_new(host_resolver->allocator, options->host_name);

        if (listener_entry == NULL) {
            goto listener_entry_alloc_failed;
        }

        const struct aws_string *host_string_copy =
            aws_string_new_from_string(host_resolver->allocator, options->host_name);

        if (host_string_copy == NULL) {
            goto host_string_copy_failed;
        }

        if (aws_hash_table_put(&default_host_resolver->listener_table, host_string_copy, listener_entry, NULL)) {
            goto host_resolver_put_failed;
        }
    }

    /* Add our new listener to the listener list. */
    aws_linked_list_push_back(&listener_entry->listeners, &listener->node);
    listener->listener_entry = listener_entry;

    aws_mutex_unlock(&default_host_resolver->resolver_lock);

    return &listener->base;

host_resolver_put_failed:

host_string_copy_failed:

    s_listener_entry_destroy(listener_entry);
    listener_entry = NULL;

listener_entry_alloc_failed:

    /* Make sure we don't trigger the shutdown callback here so that it doesn't get called for an object that we never
     * returned to the caller. */
    listener->shutdown_callback = NULL;
    listener->user_data = NULL;

    aws_host_resolver_release(host_resolver);
    s_default_resolver_listener_destroy(listener);
    listener = NULL;

    return NULL;
}

static void s_get_addresses_from_cache(
    struct aws_cache *cache,
    size_t desired_num_addresses,
    const struct aws_host_resolver_get_cached_addresses_options *options) {

    if (desired_num_addresses == 0) {
        return;
    }

    size_t record_count = aws_cache_get_element_count(cache);
    size_t num_records_to_receive = 0;

    if (desired_num_addresses == g_aws_host_resolver_all_addresses) {
        num_records_to_receive = record_count;
    } else {
        num_records_to_receive = desired_num_addresses;

        if (num_records_to_receive > record_count) {
            num_records_to_receive = record_count;
        }
    }

    for (size_t i = 0; i < num_records_to_receive; ++i) {
        struct aws_host_address *host_address = aws_lru_cache_use_lru_element(cache);
        options->get_cached_addresses_callback(host_address, options->user_data);
    }
}

static int default_get_cached_addresses(
    struct aws_host_resolver *host_resolver,
    const struct aws_host_resolver_get_cached_addresses_options *options) {

    if (options == NULL) {
        AWS_LOGF_ERROR(AWS_LS_IO_DNS, "Invalid options for default_get_cached_addresses; options cannot be null.");
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        return AWS_OP_ERR;
    }

    if (options->host_name == NULL) {
        AWS_LOGF_ERROR(AWS_LS_IO_DNS, "Invalid options for default_get_cached_addresses; host_name cannot be null.");
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        return AWS_OP_ERR;
    }

    if (options->get_cached_addresses_callback == NULL) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_DNS,
            "Invalid options for default_get_cached_addresses; get_cached_addresses_callback cannot be null.");
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        return AWS_OP_ERR;
    }

    struct default_host_resolver *default_host_resolver = host_resolver->impl;

    aws_mutex_lock(&default_host_resolver->resolver_lock);

    /* Try to find a host entry for this host, so that we can pass back cached addresses.  */
    struct aws_hash_element *host_entry_element = NULL;
    aws_hash_table_find(&default_host_resolver->host_entry_table, options->host_name, &host_entry_element);

    struct host_entry *host_entry = NULL;
    if (host_entry_element != NULL) {
        host_entry = host_entry_element->value;
        AWS_FATAL_ASSERT(host_entry != NULL);
    }

    /* If we don't have a host entry for this host right now, just unlock the resolver lock and return. */
    if (host_entry == NULL) {
        aws_mutex_unlock(&default_host_resolver->resolver_lock);
        return AWS_OP_SUCCESS;
    }

    aws_mutex_lock(&host_entry->entry_lock);
    aws_mutex_unlock(&default_host_resolver->resolver_lock);

    s_get_addresses_from_cache(host_entry->a_records, options->desired_num_a_addresses, options);
    s_get_addresses_from_cache(host_entry->aaaa_records, options->desired_num_aaaa_addresses, options);

    aws_mutex_unlock(&host_entry->entry_lock);

    return AWS_OP_SUCCESS;
}

static struct aws_host_resolver_vtable s_vtable = {
    .purge_cache = resolver_purge_cache,
    .resolve_host = default_resolve_host,
    .record_connection_failure = resolver_record_connection_failure,
    .get_host_address_count = default_get_host_address_count,
    .add_listener = default_add_listener,
    .get_cached_addresses = default_get_cached_addresses,
    .destroy = resolver_destroy,
};

static void s_aws_host_resolver_destroy(struct aws_host_resolver *resolver) {
    AWS_ASSERT(resolver->vtable && resolver->vtable->destroy);
    resolver->vtable->destroy(resolver);
}

struct aws_host_resolver *aws_host_resolver_new_default(
    struct aws_allocator *allocator,
    size_t max_entries,
    struct aws_event_loop_group *el_group,
    const struct aws_shutdown_callback_options *shutdown_options) {
    /* NOTE: we don't use el_group yet, but we will in the future. Also, we
      don't want host resolvers getting cleaned up after el_groups; this will force that
      in bindings, and encourage it in C land. */
    (void)el_group;
    AWS_ASSERT(el_group);

    struct aws_host_resolver *resolver = NULL;
    struct default_host_resolver *default_host_resolver = NULL;
    if (!aws_mem_acquire_many(
            allocator,
            2,
            &resolver,
            sizeof(struct aws_host_resolver),
            &default_host_resolver,
            sizeof(struct default_host_resolver))) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*resolver);
    AWS_ZERO_STRUCT(*default_host_resolver);

    AWS_LOGF_INFO(
        AWS_LS_IO_DNS,
        "id=%p: Initializing default host resolver with %llu max host entries.",
        (void *)resolver,
        (unsigned long long)max_entries);

    resolver->vtable = &s_vtable;
    resolver->allocator = allocator;
    resolver->impl = default_host_resolver;

    default_host_resolver->allocator = allocator;
    default_host_resolver->pending_host_entry_shutdown_completion_callbacks = 0;
    default_host_resolver->state = DRS_ACTIVE;
    aws_mutex_init(&default_host_resolver->resolver_lock);

    aws_global_thread_creator_increment();

    if (aws_hash_table_init(
            &default_host_resolver->host_entry_table,
            allocator,
            max_entries,
            aws_hash_string,
            aws_hash_callback_string_eq,
            NULL,
            NULL)) {
        goto on_error;
    }

    if (aws_hash_table_init(
            &default_host_resolver->listener_table,
            allocator,
            max_entries,
            aws_hash_string,
            aws_hash_callback_string_eq,
            aws_hash_callback_string_destroy,
            s_listener_entry_hash_destroy)) {
        goto on_error;
    }

    aws_ref_count_init(&resolver->ref_count, resolver, (aws_simple_completion_callback *)s_aws_host_resolver_destroy);

    if (shutdown_options != NULL) {
        resolver->shutdown_options = *shutdown_options;
    }

    return resolver;

on_error:

    s_cleanup_default_resolver(resolver);

    return NULL;
}

struct aws_host_resolver *aws_host_resolver_acquire(struct aws_host_resolver *resolver) {
    if (resolver != NULL) {
        aws_ref_count_acquire(&resolver->ref_count);
    }
    return resolver;
}

void aws_host_resolver_release(struct aws_host_resolver *resolver) {
    if (resolver != NULL) {
        aws_ref_count_release(&resolver->ref_count);
    }
}

size_t aws_host_resolver_get_host_address_count(
    struct aws_host_resolver *resolver,
    const struct aws_string *host_name,
    uint32_t flags) {
    return resolver->vtable->get_host_address_count(resolver, host_name, flags);
}
