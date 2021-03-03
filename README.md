# provbpf-kernel

## Building and installing the kernel

Preparing mainline kernel source:
```
make prepare
```

Configuring the kernel:
```
make config
```

Build the kernel:
```
make build
```

Install the kernel:
```
make install
```

## Creating the kernel patch

```
git config --global user.name '<your name>'
git config --global user.email '<your email>'
make patch
```

The patch will be located in `patches/0001-provbf.patch`
