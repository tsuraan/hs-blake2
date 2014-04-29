#include <stdlib.h>
#include <blake2.h>

size_t blake2b_size()
{
  return sizeof(blake2b_state);
}

size_t blake2bp_size()
{
  return sizeof(blake2bp_state);
}

