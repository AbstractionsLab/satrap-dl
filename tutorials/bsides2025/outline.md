# SATRAP workshop

## Setup
- [ ] Clone/download SATRAP's repository from [GitHub](https://github.com/AbstractionsLab/satrap-dl)
- [ ] Open a terminal and start a TypeDB server:
	```cd satrap-dl
	chmod +x *.sh
	./init-satrap.sh`
	```
- [ ] Open SATRAP in VS Code. More details in the [installation manual](https://github.com/AbstractionsLab/satrap-dl/blob/main/docs/manual/installation.md#satrap-analysis-platform-in-vs-code).

## Informing the knowledge base
- [ ] Create a fresh CTI knowledge base (CTI SKB)
- [ ] Run the ETL process to populate the CTI SKB with the ATT&CK mobile dataset
- [ ] Check statistics on SDOs and techniques

## Playbook: threat profiling
- [ ] Optional: Download TypeDB Studio from [TypeDB](https://typedb.com/docs/home/2.x/install-tools#_studio)
- [ ] Load the binary dump of Enterprise ATT&CK into your CTI SKB
	```
	cd tutorials/bsides2025/skb_export
	./load_attck_enterprise.sh
	```
- [ ] Play with the notebook for profiling a threat actor: `tutorials/bsides2025/threat_actor_profiling.ipynb`.

