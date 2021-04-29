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

## Building kernel with CamFlow patch + bpf patch

To perform benchmarks we want to build a kernel with both this bpf and camflow patches for comparison.
This is how to prepare, build and configure such setting:

```
git config --global user.name '<your name>'
git config --global user.email '<your email>'
make prepare_camflow
make config_camflow
make build
make install
```

During `make config_nochange` pick the appropriate options to test the desired configuration.
