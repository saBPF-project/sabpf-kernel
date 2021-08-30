kernel-version=5.11.2
provbpf-version=0.1.0
camflow-version=0.7.2
fedora-version=33
arch=x86_64

prepare:
	mkdir -p ~/build
	cd ~/build && git clone -b v$(kernel-version) --single-branch --depth 1 git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git
	cd ~/build/linux-stable && $(MAKE) mrproper
	cd ~/build && mkdir -p pristine
	cd ~/build && cp -r ./linux-stable ./pristine
	cd ~/build/linux-stable && sed -i -e "s/EXTRAVERSION =/EXTRAVERSION = provbpf$(provbpf-version)/g" Makefile

delete:
	cd ~/build && sudo rm -rf ./pristine
	cd ~/build && sudo rm -rf ./linux-stable

copy_change:
	cp -r ./kernel ~/build/linux-stable
	cp -r ./include ~/build/linux-stable
	cp -r ./tools ~/build/linux-stable
	cp -r ./security ~/build/linux-stable
	cp -r ./scripts ~/build/linux-stable

config: copy_change
	cp -f /boot/config-$(shell uname -r) ~/build/linux-stable/.config
	cd ~/build/linux-stable && ./scripts/kconfig/streamline_config.pl > config_strip
	cd ~/build/linux-stable &&  cp -f config_strip .config
	cd ~/build/linux-stable && sed -i -e "s/CONFIG_LSM=\"yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor\"/CONFIG_LSM=\"yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor,bpf\"/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_BPF_LSM is not set/CONFIG_BPF_LSM=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_IP_ADVANCED_ROUTER is not set/CONFIG_IP_ADVANCED_ROUTER=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_IP_MULTIPLE_TABLES is not set/CONFIG_IP_MULTIPLE_TABLES=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_NETFILTER_NETLINK is not set/CONFIG_NETFILTER_NETLINK=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_NETFILTER_NETLINK_QUEUE is not set/CONFIG_NETFILTER_NETLINK_QUEUE=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_NETFILTER_NETLINK_ACCT is not set/CONFIG_NETFILTER_NETLINK_ACCT=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_NETFILTER_NETLINK_LOG is not set/CONFIG_NETFILTER_NETLINK_LOG=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_NF_CT_NETLINK is not set/CONFIG_NF_CT_NETLINK=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_NETFILTER_XT_TARGET_MARK is not set/CONFIG_NETFILTER_XT_TARGET_MARK=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_NET_SCHED is not set/CONFIG_NET_SCHED=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_NET_SCH_INGRESS is not set/CONFIG_NET_SCH_INGRESS=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_SCSI_NETLINK is not set/CONFIG_SCSI_NETLINK=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_SCSI_NETLINK is not set/CONFIG_SCSI_NETLINK=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_SCSI_FC_ATTRS is not set/CONFIG_SCSI_FC_ATTRS=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_SCSI is not set/CONFIG_SCSI=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_NF_CONNTRACK is not set/CONFIG_NF_CONNTRACK=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_NETFILTER_XT_MARK is not set/CONFIG_NETFILTER_XT_MARK=y/g" .config
	cd ~/build/linux-stable && echo "CONFIG_NF_CT_NETLINK=y" >> .config
	cd ~/build/linux-stable && echo "CONFIG_SCSI_NETLINK=y" >> .config
	cd ~/build/linux-stable && $(MAKE) menuconfig
	cp -f ~/build/linux-stable/.config .config

config_circle: copy_change
	cd ~/build/linux-stable && $(MAKE) olddefconfig
	cd ~/build/linux-stable && sed -i -e "s/CONFIG_LSM=\"yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor\"/CONFIG_LSM=\"yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor,bpf\"/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_BPF_LSM is not set/CONFIG_BPF_LSM=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_IP_ADVANCED_ROUTER is not set/CONFIG_IP_ADVANCED_ROUTER=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_IP_MULTIPLE_TABLES is not set/CONFIG_IP_MULTIPLE_TABLES=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_NETFILTER_NETLINK is not set/CONFIG_NETFILTER_NETLINK=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_NETFILTER_NETLINK_QUEUE is not set/CONFIG_NETFILTER_NETLINK_QUEUE=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_NETFILTER_NETLINK_ACCT is not set/CONFIG_NETFILTER_NETLINK_ACCT=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_NETFILTER_NETLINK_LOG is not set/CONFIG_NETFILTER_NETLINK_LOG=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_NF_CT_NETLINK is not set/CONFIG_NF_CT_NETLINK=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_NETFILTER_XT_TARGET_MARK is not set/CONFIG_NETFILTER_XT_TARGET_MARK=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_NET_SCHED is not set/CONFIG_NET_SCHED=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_NET_SCH_INGRESS is not set/CONFIG_NET_SCH_INGRESS=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_SCSI_NETLINK is not set/CONFIG_SCSI_NETLINK=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_SCSI_NETLINK is not set/CONFIG_SCSI_NETLINK=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_SCSI_FC_ATTRS is not set/CONFIG_SCSI_FC_ATTRS=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_SCSI is not set/CONFIG_SCSI=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_NF_CONNTRACK is not set/CONFIG_NF_CONNTRACK=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_NETFILTER_XT_MARK is not set/CONFIG_NETFILTER_XT_MARK=y/g" .config
	cd ~/build/linux-stable && echo "CONFIG_NF_CT_NETLINK=y" >> .config
	cd ~/build/linux-stable && echo "CONFIG_SCSI_NETLINK=y" >> .config
	cp -f ~/build/linux-stable/.config .config

build_kernel_sub: copy_change
	cd ~/build/linux-stable && $(MAKE) kernel W=1

build_kernel:
	cd ~/build/linux-stable && $(MAKE) -j16 ARCH=${arch}

build_libbpf:
	cd ~/build/linux-stable/tools/lib/bpf && sudo $(MAKE) all

build_resolve_btfids:
	cd ~/build/linux-stable/tools/bpf/resolve_btfids && sudo $(MAKE) all

build_bpftool:
	cd ~/build/linux-stable/tools/bpf/bpftool && sudo $(MAKE) all

build_bpf: build_libbpf build_resolve_btfids build_bpftool

build: build_kernel_sub build_kernel build_bpf

install_header:
	cd ~/build/linux-stable && sudo $(MAKE) headers_install ARCH=${arch} INSTALL_HDR_PATH=/usr

install_kernel:
	cd ~/build/linux-stable && sudo $(MAKE) modules_install ARCH=${arch}
	cd ~/build/linux-stable && sudo $(MAKE) install ARCH=${arch}
	cd ~/build/linux-stable && sudo cp -f .config /boot/config-$(kernel-version)provbpf$(provbpf-version)+

install_libbpf:
	cd ~/build/linux-stable/tools/lib/bpf && sudo $(MAKE) install

install_bpftool:
	cd ~/build/linux-stable/tools/bpf/bpftool && sudo $(MAKE) install

install_bpf: install_libbpf install_bpftool

install: install_header install_kernel install_bpf

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

patch: copy_change
	mkdir -p patches
	cd ~/build/pristine/linux-stable && rm -f .config
	cd ~/build/pristine/linux-stable && rm -f config_sav
	cd ~/build/pristine/linux-stable && rm -f certs/signing_key.pem
	cd ~/build/pristine/linux-stable && rm -f	certs/x509.genkey
	cd ~/build/pristine/linux-stable && rm -f certs/signing_key.x509
	cd ~/build/pristine/linux-stable && rm -f tools/objtool/arch/x86/insn/inat-tables.c
	cd ~/build/pristine/linux-stable && $(MAKE) clean
	cd ~/build/pristine/linux-stable && $(MAKE) mrproper
	cp -r kernel ~/build/pristine/linux-stable/.
	cp -r include ~/build/pristine/linux-stable/.
	cd ~/build/pristine/linux-stable && git status
	cd ~/build/pristine/linux-stable && git add .
	cd ~/build/pristine/linux-stable && git commit -a -m 'provbpf'
	cd ~/build/pristine/linux-stable && git format-patch HEAD~ -s
	cp -f ~/build/pristine/linux-stable/*.patch patches/

fedora:
	mkdir -p ~/build
	cd ~/build && fedpkg clone -a kernel
	cd ~/build/kernel && git checkout -b camflow origin/f$(fedora-version)
	cd ~/build/kernel && sudo dnf -y builddep kernel.spec
	cp -f patches/*.patch ~/build/kernel
	bash ./scripts/add_patch.sh
	cd ~/build/kernel && sed -i -e "s/# define buildid .local/%define buildid .provbpf/g" kernel.spec
	cd ~/build/kernel && sed -i -e "s/%define with_headers 0/%define with_headers 1/g" kernel.spec
	cd ~/build/kernel && sed -i -e "s/%define with_cross_headers 0/%define with_cross_headers 1/g" kernel.spec
	bash ./scripts/prep_config.sh
	bash ./scripts/release.sh
	cd ~/build/kernel && fedpkg prep
	cd ~/build/kernel && fedpkg local
	mkdir -p output
	mv -f ~/build/kernel/x86_64/*.rpm ./output
	mv -f ~/build/kernel/*.rpm ./output
	cd output && ls

apply_camflow:
	cd ~/build && wget https://github.com/camflow/camflow-dev/releases/download/v$(camflow-version)/0001-information-flow.patch
	cd ~/build/linux-stable && git apply ../0001-information-flow.patch
	cd ~/build && wget https://github.com/camflow/camflow-dev/releases/download/v$(camflow-version)/0002-camflow.patch
	cd ~/build/linux-stable && git apply ../0002-camflow.patch

apply_bpf:
	cp -f ./patches/0001-provbpf.patch ~/build/0003-provbpf.patch
	cd ~/build/linux-stable && git apply ../0003-provbpf.patch

prepare_camflow:
	$(MAKE) prepare
	$(MAKE) patch
	$(MAKE) delete
	$(MAKE) prepare
	$(MAKE) apply_camflow
	$(MAKE) apply_bpf

config_camflow:
	cp -f /boot/config-$(shell uname -r) ~/build/linux-stable/.config
	cd ~/build/linux-stable && sed -i -e "s/CONFIG_LSM=\"yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor\"/CONFIG_LSM=\"yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor,bpf,provenance\"/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_BPF_LSM is not set/CONFIG_BPF_LSM=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_IP_ADVANCED_ROUTER is not set/CONFIG_IP_ADVANCED_ROUTER=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_IP_MULTIPLE_TABLES is not set/CONFIG_IP_MULTIPLE_TABLES=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_NETFILTER_NETLINK is not set/CONFIG_NETFILTER_NETLINK=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_NETFILTER_NETLINK_QUEUE is not set/CONFIG_NETFILTER_NETLINK_QUEUE=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_NETFILTER_NETLINK_ACCT is not set/CONFIG_NETFILTER_NETLINK_ACCT=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_NETFILTER_NETLINK_LOG is not set/CONFIG_NETFILTER_NETLINK_LOG=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_NF_CT_NETLINK is not set/CONFIG_NF_CT_NETLINK=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_NETFILTER_XT_TARGET_MARK is not set/CONFIG_NETFILTER_XT_TARGET_MARK=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_NET_SCHED is not set/CONFIG_NET_SCHED=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_NET_SCH_INGRESS is not set/CONFIG_NET_SCH_INGRESS=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_SCSI_NETLINK is not set/CONFIG_SCSI_NETLINK=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_SCSI_NETLINK is not set/CONFIG_SCSI_NETLINK=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_SCSI_FC_ATTRS is not set/CONFIG_SCSI_FC_ATTRS=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_SCSI is not set/CONFIG_SCSI=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_NF_CONNTRACK is not set/CONFIG_NF_CONNTRACK=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_NETFILTER_XT_MARK is not set/CONFIG_NETFILTER_XT_MARK=y/g" .config
	cd ~/build/linux-stable && echo "CONFIG_NF_CT_NETLINK=y" >> .config
	cd ~/build/linux-stable && echo "CONFIG_SCSI_NETLINK=y" >> .config
	cd ~/build/linux-stable && $(MAKE) menuconfig
	cp -f ~/build/linux-stable/.config .config

config_circle_camflow: copy_change
	cd ~/build/linux-stable && $(MAKE) olddefconfig
	cd ~/build/linux-stable && sed -i -e "s/CONFIG_LSM=\"yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor\"/CONFIG_LSM=\"yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor,bpf,camflow\"/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_BPF_LSM is not set/CONFIG_BPF_LSM=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_IP_ADVANCED_ROUTER is not set/CONFIG_IP_ADVANCED_ROUTER=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_IP_MULTIPLE_TABLES is not set/CONFIG_IP_MULTIPLE_TABLES=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_NETFILTER_NETLINK is not set/CONFIG_NETFILTER_NETLINK=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_NETFILTER_NETLINK_QUEUE is not set/CONFIG_NETFILTER_NETLINK_QUEUE=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_NETFILTER_NETLINK_ACCT is not set/CONFIG_NETFILTER_NETLINK_ACCT=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_NETFILTER_NETLINK_LOG is not set/CONFIG_NETFILTER_NETLINK_LOG=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_NF_CT_NETLINK is not set/CONFIG_NF_CT_NETLINK=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_NETFILTER_XT_TARGET_MARK is not set/CONFIG_NETFILTER_XT_TARGET_MARK=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_NET_SCHED is not set/CONFIG_NET_SCHED=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_NET_SCH_INGRESS is not set/CONFIG_NET_SCH_INGRESS=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_SCSI_NETLINK is not set/CONFIG_SCSI_NETLINK=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_SCSI_NETLINK is not set/CONFIG_SCSI_NETLINK=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_SCSI_FC_ATTRS is not set/CONFIG_SCSI_FC_ATTRS=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_SCSI is not set/CONFIG_SCSI=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_NF_CONNTRACK is not set/CONFIG_NF_CONNTRACK=y/g" .config
	cd ~/build/linux-stable && sed -i -e "s/# CONFIG_NETFILTER_XT_MARK is not set/CONFIG_NETFILTER_XT_MARK=y/g" .config
	cd ~/build/linux-stable && echo "CONFIG_NF_CT_NETLINK=y" >> .config
	cd ~/build/linux-stable && echo "CONFIG_SCSI_NETLINK=y" >> .config
	cp -f ~/build/linux-stable/.config .config
