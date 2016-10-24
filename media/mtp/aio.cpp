/*
 * Copyright (C) 2007 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "aio.h"
#include <utils/Log.h>
#include <queue>

static __inline__ int thread_create(pthread_t *thread,
        void* (*func)(void*), void* arg) {
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    return pthread_create(thread, &attr, func, arg);
}

static void *read_func(void *arg) {
    struct aiocb *aiocbp = static_cast<struct aiocb*>(arg);
    aiocbp->ret = TEMP_FAILURE_RETRY(pread(aiocbp->aio_fildes,
                aiocbp->aio_buf, aiocbp->aio_nbytes, aiocbp->aio_offset));
    if (aiocbp->ret == -1) aiocbp->error = errno;
    return NULL;
}

static void *write_func(void *arg) {
    struct aiocb *aiocbp = static_cast<struct aiocb*>(arg);
    aiocbp->ret = TEMP_FAILURE_RETRY(pwrite(aiocbp->aio_fildes,
                aiocbp->aio_buf, aiocbp->aio_nbytes, aiocbp->aio_offset));
    if (aiocbp->ret == -1) aiocbp->error = errno;
    return NULL;
}

static void *splice_read_func(void *arg) {
    struct aiocb *aiocbp = static_cast<struct aiocb*>(arg);
    aiocbp->ret = TEMP_FAILURE_RETRY(splice(aiocbp->aio_fildes,
                (off64_t*) &aiocbp->aio_offset, aiocbp->aio_sink,
                NULL, aiocbp->aio_nbytes, 0));
    if (aiocbp->ret == -1) aiocbp->error = errno;
    return NULL;
}

static void *splice_write_func(void *arg) {
    struct aiocb *aiocbp = static_cast<struct aiocb*>(arg);
    aiocbp->ret = TEMP_FAILURE_RETRY(splice(aiocbp->aio_fildes, NULL,
                aiocbp->aio_sink, (off64_t*) &aiocbp->aio_offset,
                aiocbp->aio_nbytes, 0));
    if (aiocbp->ret == -1) aiocbp->error = errno;
    return NULL;
}

std::queue<struct aiocb*> queue;
pthread_mutex_t queue_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;
pthread_cond_t write_cond = PTHREAD_COND_INITIALIZER;
int done;
static void *splice_write_pool_func(void*) {
    while(1) {
        pthread_mutex_lock(&queue_lock);
        while (queue.empty() && !done) {
            pthread_cond_wait(&queue_cond, &queue_lock);
        }
        if (queue.empty() && done) {
            pthread_mutex_unlock(&queue_lock);
            return NULL;
        }
        struct aiocb * aiocbp = queue.front();
        queue.pop();
        pthread_cond_signal(&write_cond);
        pthread_mutex_unlock(&queue_lock);
        aiocbp->ret = TEMP_FAILURE_RETRY(splice(aiocbp->aio_fildes, NULL,
                    aiocbp->aio_sink, (off64_t*) &aiocbp->aio_offset,
                    aiocbp->aio_nbytes, 0));
        if (aiocbp->ret == -1) {
            aiocbp->error = errno;
        }
        close(aiocbp->aio_fildes);
        free(aiocbp);
    }
    return NULL;
}

static void *write_pool_func(void*) {
    while(1) {
        pthread_mutex_lock(&queue_lock);
        while (queue.empty() && !done) {
            pthread_cond_wait(&queue_cond, &queue_lock);
        }
        if (queue.empty() && done) {
            pthread_mutex_unlock(&queue_lock);
            return NULL;
        }
        struct aiocb * aiocbp = queue.front();
        queue.pop();
        pthread_cond_signal(&write_cond);
        pthread_mutex_unlock(&queue_lock);
        aiocbp->ret = TEMP_FAILURE_RETRY(pwrite(aiocbp->aio_fildes,
                    aiocbp->aio_buf, aiocbp->aio_nbytes, aiocbp->aio_offset));
        if (aiocbp->ret == -1) {
            aiocbp->error = errno;
        }
        free(aiocbp->aio_buf);
        free(aiocbp);
    }
    return NULL;
}

#define NUM_THREADS 1
#define QUEUE_SIZE 10
pthread_t pool[NUM_THREADS];
void aio_pool_init(void*(f)(void*)) {
    done = 0;
    for (unsigned long i = 0; i < NUM_THREADS; i++) {
        thread_create(&pool[i], f, reinterpret_cast<void*>(i));
    }
}

void aio_pool_splice_init() {
    aio_pool_init(splice_write_pool_func);
}

void aio_pool_write_init() {
    aio_pool_init(write_pool_func);
}

void aio_pool_end() {
    for (int i = 0; i < QUEUE_SIZE; i++) {
        pthread_mutex_lock(&queue_lock);
        done = 1;
        pthread_cond_signal(&queue_cond);
        pthread_mutex_unlock(&queue_lock);
    }

    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(pool[i], NULL);
    }
}

int aio_pool_write(struct aiocb *aiocbp) {
    pthread_mutex_lock(&queue_lock);
    while (queue.size() > NUM_THREADS)
        pthread_cond_wait(&write_cond, &queue_lock);
    queue.push(aiocbp);
    pthread_cond_signal(&queue_cond);
    pthread_mutex_unlock(&queue_lock);
    return 0;
}

int aio_read(struct aiocb *aiocbp) {
   return thread_create(&aiocbp->thread, read_func, aiocbp);
}

int aio_write(struct aiocb *aiocbp) {
   return thread_create(&aiocbp->thread, write_func, aiocbp);
}

int aio_splice_read(struct aiocb *aiocbp) {
   return thread_create(&aiocbp->thread, splice_read_func, aiocbp);
}

int aio_splice_write(struct aiocb *aiocbp) {
   return thread_create(&aiocbp->thread, splice_write_func, aiocbp);
}

int aio_error(const struct aiocb *aiocbp) {
    return aiocbp->error;
}

ssize_t aio_return(struct aiocb *aiocbp) {
    return aiocbp->ret;
}

int aio_suspend(const struct aiocb * const aiocbp[], int n,
        const struct timespec *) {
    for (int i = 0; i < n; i++) {
        int ret = pthread_join(aiocbp[i]->thread, NULL);
        if (ret < 0) return ret;
    }
    return 0;
}

