# bitcoin-address-generator
Generate public, private key pair for a Bitcoin address using python 2.7 and your local ssl library.

```
import bag

private_key = '5KVCzJfc1hEYVdbVr2AfaAkRF1rDsqyAMjPArKsDyCZpk7DQK85'
secret = bag.convert_pkey_to_secret(private_key)
bag.get_addr(bag.generate(secret))

bag.get_addr(bag.generate())
```