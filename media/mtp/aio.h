#ifndef _AIO_H
#define _AIO_H

#include <time.h>
#include <signal.h>
#include <fcntl.h>
#include <linux/aio_abi.h>
#include <sys/cdefs.h>
#include <sys/types.h>
#include <pthread.h>
#include <unistd.h>

/**
 * Provides a subset of POSIX aio operations, as well
 * as similar operations with splice and threadpools.
 */

__BEGIN_DECLS

struct aiocb {
    int aio_fildes;     // Assumed to be the source for splices
    void *aio_buf;      // Unused for splices

    off_t aio_offset;
    size_t aio_nbytes;

    int aio_sink;       // Unused for normal r/w

    // Used internally
    pthread_t thread;
    ssize_t ret;
    int error;
};

int aio_read(struct aiocb *);
int aio_write(struct aiocb *);
int aio_splice_read(struct aiocb *);
int aio_splice_write(struct aiocb *);
int aio_error(const struct aiocb *);
ssize_t aio_return(struct aiocb *);
int aio_suspend(const struct aiocb * const[], int, const struct timespec *);
int aio_cancel(int, struct aiocb *);

void aio_pool_write_init();
void aio_pool_splice_init();
void aio_pool_end();
int aio_pool_write(struct aiocb *);

__END_DECLS

#endif

