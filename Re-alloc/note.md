<h3> Re-Alloc </h3>

![image](https://github.com/user-attachments/assets/46221d25-8d67-4c92-bc34-3549e16eda4d)

This was a really interesting challenge because i wasn't able to solve it the first time i attempted it

It is a standard heap exploitation challenge where you can allocate, free and reallocate memory

Some constraint here is that we can't edit any chunk, we can't only make small sized allocation, no use after free and we are limited to just 2 unique allocations

Also allocations and deallocations is managed through `realloc`
![image](https://github.com/user-attachments/assets/404fd03b-1584-43b0-b64a-31f12c940bf0)

One bug here is that we can control the size of what is being allocated
![image](https://github.com/user-attachments/assets/c6f291b9-4f81-4cbd-bd1a-f1d40953ec77)
![image](https://github.com/user-attachments/assets/6b796860-1d59-4767-ae92-e8347a1102d9)

From the man page of realloc or from looking at the source code you'll see this
![image](https://github.com/user-attachments/assets/c8b9d1c9-be8c-4bf3-aa74-1cce0855a9f0)

```c
#if REALLOC_ZERO_BYTES_FREES
  if (bytes == 0 && oldmem != NULL)
    {
      __libc_free (oldmem); return 0;
    }
#endif
```

Basically if `oldmem` isn't null and the size speicifed is `0` then it's going to call `__libc_free` on that heap chunk

We will leverage that to get a UAF

Another important thing to note is that the way chunk is being removed from the tcache bin is this
![image](https://github.com/user-attachments/assets/87c9ce52-cdff-4812-8f77-57e31a1a12e4)

```c
#if USE_TCACHE
  /* int_free also calls request2size, be careful to not pad twice.  */
  size_t tbytes;
  checked_request2size (bytes, tbytes);
  size_t tc_idx = csize2tidx (tbytes);

  MAYBE_INIT_TCACHE ();

  DIAG_PUSH_NEEDS_COMMENT;
  if (tc_idx < mp_.tcache_bins
      /*&& tc_idx < TCACHE_MAX_BINS*/ /* to appease gcc */
      && tcache
      && tcache->entries[tc_idx] != NULL)
    {
      return tcache_get (tc_idx);
    }
  DIAG_POP_NEEDS_COMMENT;
#endif
```

Basically a chunk can be served from the tcache as long as there exists some values in the tcache entry, in later versions of libc there's a fix for this and that's by checking the tcache count and ensuring it isn't zero


