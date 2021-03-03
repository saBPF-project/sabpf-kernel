kernel-version=5.11.2
provbpf-version=0.1.0
arch=x86_64

prepare:
	mkdir -p ~/build
	cd ~/build && git clone -b v$(kernel-version) --single-branch --depth 1 git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git
	cd ~/build/linux-stable && $(MAKE) mrproper
	cd ~/build && mkdir -p pristine
	cd ~/build && cp -r ./linux-stable ./pristine
	cd ~/build/linux-stable && sed -i -e "s/EXTRAVERSION =/EXTRAVERSION = provbpf$(provbpf-version)/g" Makefile

delete:
	cd ~/build && rm -rf ./pristine
	cd ~/build && rm -rf ./linux-stable

copy_change:
	cp -r ./kernel ~/build/linux-stable
	cp -r ./include ~/build/linux-stable

config: copy_change
	cp -f /boot/config-$(shell uname -r) ~/build/linux-stable/.config
	cd ~/build/linux-stable && ./scripts/kconfig/streamline_config.pl > config_strip
	cd ~/build/linux-stable &&  cp -f config_strip .config
	cd ~/build/linux-stable && $(MAKE) menuconfig
	cd ~/build/linux-stable && sed -i -e "s/CONFIG_LSM=\"yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor\"/CONFIG_LSM=\"yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor,bpf\"/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_BPF_LSM is not set/CONFIG_BPF_LSM=y/g" .config
	cp -f ~/build/linux-stable/.config .config

config_circle: copy_change
	cd ~/build/linux-stable && $(MAKE) olddefconfig
	cd ~/build/linux-stable && sed -i -e "s/CONFIG_LSM=\"yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor\"/CONFIG_LSM=\"yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor,bpf\"/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_BPF_LSM is not set/CONFIG_BPF_LSM=y/g" .config
	cp -f ~/build/linux-stable/.config .config

build_kernel: copy_change
	cd ~/build/linux-stable && $(MAKE) kernel W=1

build: build_kernel
	cd ~/build/linux-stable && $(MAKE) -j16 ARCH=${arch}

install_header:
	cd ~/build/linux-stable && sudo $(MAKE) headers_install ARCH=${arch} INSTALL_HDR_PATH=/usr

install_kernel:
	cd ~/build/linux-stable && sudo $(MAKE) modules_install ARCH=${arch}
	cd ~/build/linux-stable && sudo $(MAKE) install ARCH=${arch}
	cd ~/build/linux-stable && sudo cp -f .config /boot/config-$(kernel-version)provbpf$(provbpf-version)+

install: install_header install_kernel

clean:
	cd ~/build/linux-stable && $(MAKE) clean
	cd ~/build/linux-stable && $(MAKE) mrproper

save_space:
	cd ~/build/linux-stable && rm -rf .git
	cd ~/build/pristine/linux-stable && rm -rf .git

update_version: delete prepare
	mv include/linux/bpf.h include/linux/_bpf.h
	cp ~/build/pristine/linux-stable/include/linux/bpf.h include/linux/bpf.h
	mv include/uapi/linux/bpf.h include/uapi/linux/_bpf.h
	cp ~/build/pristine/linux-stable/include/uapi/linux/bpf.h include/uapi/linux/bpf.h
	mv kernel/bpf/bpf_lsm.c kernel/bpf/_bpf_lsm.c
	cp ~/build/pristine/linux-stable/kernel/bpf/bpf_lsm.c kernel/bpf/bpf_lsm.c
