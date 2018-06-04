#ifndef _THREADS_H_
#define _THREADS_H_

#ifdef __cplusplus
extern "C" {
#endif
/**
 * @file threads.h
 * @brief Threadpool Header File
 */
 
 /**
 * Increase this constants at your own risk
 * Large values might slow down your system
 */
#define MAX_THREADS 64
#define MAX_QUEUE   65536

typedef struct threadpool_t threadpool_t;
/**
 * @function threadpool_create
 * @brief Creates a threadpool_t object.
 * @param thread_count Number of worker threads.
 * @param queue_size   Size of the queue.
 * @param flags        Unused parameter.
 * @return a newly created thread pool or NULL
 */
threadpool_t *threads_create(int thread_count, int queue_size, int flags);

/**
 * @function threadpool_add
 * @brief add a new task in the queue of a thread pool
 * @param pool     Thread pool to which add the task.
 * @param function Pointer to the function that will perform the task.
 * @param argument Argument to be passed to the function.
 * @param flags    Unused parameter.
 * @return 0 if all goes well, negative values in case of error (@see
 * threadpool_error_t for codes).
 */
int threads_dispatch(threadpool_t *pool, void (*routine)(void *),
                   void *arg, int flags);

/**
 * @function threadpool_destroy
 * @brief Stops and destroys a thread pool.
 * @param pool  Thread pool to destroy.
 * @param flags Flags for shutdown
 *
 * Known values for flags are 0 (default) and threadpool_graceful in
 * which case the thread pool doesn't accept any new tasks but
 * processes all pending tasks before shutdown.
 */
int threads_destroy(threadpool_t *pool, int flags);

#ifdef __cplusplus
}
#endif

#endif /* _THREADS_H_ */

