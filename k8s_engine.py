"""
k8s_engine.py — PenteIA V4.0
Kubernetes & Container security attack scenarios.
"""
from typing import Optional

K8S_TECHNIQUES = [
    {
        "id": "K8S-001",
        "name": "Container Escape via Privileged Pod",
        "mitre_id": "T1611",
        "tactic": "PRIVILEGE_ESCALATION",
        "severity": "critical",
        "description": "Privileged containers have full host access. Attacker mounts host filesystem and escapes to node.",
        "prerequisites": ["Pod running as privileged: true"],
        "kill_chain": [
            {"step": 1, "action": "Identify privileged pod via: kubectl get pods -o jsonpath"},
            {"step": 2, "action": "Exec into pod: kubectl exec -it <pod> -- /bin/sh"},
            {"step": 3, "action": "Mount host filesystem: mount /dev/sda1 /mnt"},
            {"step": 4, "action": "chroot to host and read /etc/shadow, SSH keys, tokens"},
            {"step": 5, "action": "Pivot to node-level access — full cluster compromise"},
        ],
        "detection": ["Audit log: exec into privileged pod", "Falco rule: container_started_with_privilege_flag"],
        "mitigations": ["Never run privileged: true", "Use Pod Security Standards (restricted)", "OPA Gatekeeper policy"],
        "tools": ["kubectl", "nsenter", "Deepce"],
    },
    {
        "id": "K8S-002",
        "name": "Service Account Token Abuse",
        "mitre_id": "T1528",
        "tactic": "CREDENTIAL_ACCESS",
        "severity": "high",
        "description": "Service account tokens mounted in pods allow API server calls with pod permissions.",
        "prerequisites": ["Access to any pod"],
        "kill_chain": [
            {"step": 1, "action": "Read mounted token: cat /var/run/secrets/kubernetes.io/serviceaccount/token"},
            {"step": 2, "action": "Query API server: curl -H 'Authorization: Bearer <token>' https://kubernetes.default.svc"},
            {"step": 3, "action": "Enumerate RBAC: kubectl auth can-i --list"},
            {"step": 4, "action": "Escalate via ClusterRoleBinding abuse or privileged namespace"},
        ],
        "detection": ["Unusual API calls from pod IPs", "Service account used from unexpected source"],
        "mitigations": ["automountServiceAccountToken: false (default)", "Minimal RBAC permissions", "Token volume projection with expiry"],
        "tools": ["kubectl", "curl", "kube-hunter"],
    },
    {
        "id": "K8S-003",
        "name": "etcd Direct Access",
        "mitre_id": "T1552",
        "tactic": "CREDENTIAL_ACCESS",
        "severity": "critical",
        "description": "etcd stores all cluster secrets unencrypted by default. Direct access = full cluster compromise.",
        "prerequisites": ["Network access to etcd (port 2379)"],
        "kill_chain": [
            {"step": 1, "action": "Identify etcd endpoint: ps aux | grep etcd on control plane"},
            {"step": 2, "action": "Connect: etcdctl --endpoints=https://127.0.0.1:2379 get / --prefix"},
            {"step": 3, "action": "Extract all secrets: etcdctl get /registry/secrets/ --prefix"},
            {"step": 4, "action": "Decode base64 secrets — ServiceAccount tokens, TLS certs, API tokens"},
        ],
        "detection": ["Direct etcd access from non-control-plane IPs", "etcd audit logs"],
        "mitigations": ["Enable etcd encryption at rest", "mTLS for etcd", "Network policy: etcd only from control plane"],
        "tools": ["etcdctl"],
    },
    {
        "id": "K8S-004",
        "name": "Malicious Container Image (Supply Chain)",
        "mitre_id": "T1195.002",
        "tactic": "INITIAL_ACCESS",
        "severity": "high",
        "description": "Backdoored container image deployed via poisoned registry or typosquatting.",
        "prerequisites": ["Write access to image registry"],
        "kill_chain": [
            {"step": 1, "action": "Identify target image name (typosquat: nginx vs ngnix)"},
            {"step": 2, "action": "Build backdoored image with reverse shell in entrypoint"},
            {"step": 3, "action": "Push to public Docker Hub with similar name"},
            {"step": 4, "action": "Wait for victim to pull and deploy"},
            {"step": 5, "action": "Receive reverse shell from container on deploy"},
        ],
        "detection": ["Image digest validation", "Admission webhook for allowed registries"],
        "mitigations": ["Image signing (Cosign/Notary)", "Admission controller: only approved registries", "SBOM generation"],
        "tools": ["Docker", "Cosign", "Trivy"],
    },
    {
        "id": "K8S-005",
        "name": "Kubelet API Unauthenticated Access",
        "mitre_id": "T1190",
        "tactic": "INITIAL_ACCESS",
        "severity": "critical",
        "description": "Kubelet API on port 10250 may allow unauthenticated exec/logs if misconfigured.",
        "prerequisites": ["Network access to node port 10250"],
        "kill_chain": [
            {"step": 1, "action": "Scan for kubelet ports: nmap -p 10250 <node-cidr>"},
            {"step": 2, "action": "Test anonymous access: curl -sk https://<node>:10250/pods"},
            {"step": 3, "action": "Execute command in pod: curl -sk https://<node>:10250/run/<ns>/<pod>/<container>"},
            {"step": 4, "action": "Read secrets, pivot to other pods on same node"},
        ],
        "detection": ["Unexpected connections to port 10250", "Kubelet audit logs"],
        "mitigations": ["--anonymous-auth=false on kubelet", "Webhook authentication", "Network policy block 10250"],
        "tools": ["kubeletctl", "curl", "nmap"],
    },
    {
        "id": "K8S-006",
        "name": "RBAC Privilege Escalation via RoleBinding",
        "mitre_id": "T1078.004",
        "tactic": "PRIVILEGE_ESCALATION",
        "severity": "high",
        "description": "Users with create/update on RoleBinding can grant themselves admin rights.",
        "prerequisites": ["create or update on rolebindings"],
        "kill_chain": [
            {"step": 1, "action": "Check permissions: kubectl auth can-i create rolebindings"},
            {"step": 2, "action": "Create ClusterRoleBinding giving self cluster-admin"},
            {"step": 3, "action": "Full cluster access achieved"},
        ],
        "detection": ["Audit: create rolebinding/clusterrolebinding events"],
        "mitigations": ["Never grant create/update on RoleBindings broadly", "OPA Gatekeeper prevent privilege escalation"],
        "tools": ["kubectl"],
    },
    {
        "id": "K8S-007",
        "name": "Pod with hostPID / hostNetwork Escape",
        "mitre_id": "T1611",
        "tactic": "PRIVILEGE_ESCALATION",
        "severity": "critical",
        "description": "hostPID and hostNetwork share the host process namespace and network stack with the container.",
        "prerequisites": ["Pod with hostPID: true or hostNetwork: true"],
        "kill_chain": [
            {"step": 1, "action": "Deploy or find pod with hostPID: true"},
            {"step": 2, "action": "List host processes: ps aux from inside container"},
            {"step": 3, "action": "Inject shellcode into host process via /proc/<pid>/mem"},
            {"step": 4, "action": "Full host access"},
        ],
        "detection": ["Falco: pod with hostPID flag", "Pod Security Admission: restricted profile blocks this"],
        "mitigations": ["Pod Security Standards: never allow hostPID/hostNetwork", "Admission webhook"],
        "tools": ["kubectl", "nsenter"],
    },
    {
        "id": "K8S-008",
        "name": "Lateral Movement via K8s DNS",
        "mitre_id": "T1021",
        "tactic": "LATERAL_MOVEMENT",
        "severity": "medium",
        "description": "Internal K8s DNS allows discovery of all services. Attacker pivots between microservices.",
        "prerequisites": ["Any pod in cluster"],
        "kill_chain": [
            {"step": 1, "action": "Enumerate services via DNS: nslookup kubernetes.default.svc.cluster.local"},
            {"step": 2, "action": "Scan internal service IPs on common ports"},
            {"step": 3, "action": "Exploit unauthenticated internal services (admin UIs, metrics, DBs)"},
        ],
        "detection": ["Unusual DNS queries from pods", "Network policy violations"],
        "mitigations": ["Network Policies to restrict pod-to-pod communication", "mTLS between services (Istio/Linkerd)"],
        "tools": ["kubectl", "nmap", "ncat"],
    },
]

CONTAINER_TECHNIQUES = [
    {
        "id": "CNT-001",
        "name": "Docker Socket Mount Escape",
        "mitre_id": "T1611",
        "tactic": "PRIVILEGE_ESCALATION",
        "severity": "critical",
        "description": "Mounting /var/run/docker.sock into a container grants full Docker daemon control = root on host.",
        "kill_chain": [
            {"step": 1, "action": "Detect mounted socket: ls -la /var/run/docker.sock"},
            {"step": 2, "action": "Run privileged container via socket: docker run -v /:/mnt --rm -it alpine chroot /mnt sh"},
            {"step": 3, "action": "Full host filesystem access as root"},
        ],
        "detection": ["Detect /var/run/docker.sock mounts via image inspection", "Falco: docker socket opened by container"],
        "mitigations": ["Never mount Docker socket in containers", "Use rootless Docker", "Audit socket mounts"],
        "tools": ["docker"],
    },
    {
        "id": "CNT-002",
        "name": "Container Image Layer Secrets",
        "mitre_id": "T1552",
        "tactic": "CREDENTIAL_ACCESS",
        "severity": "high",
        "description": "Secrets baked into Dockerfile layers remain in image history even after deletion.",
        "kill_chain": [
            {"step": 1, "action": "Pull target image: docker pull <target>"},
            {"step": 2, "action": "Inspect history: docker history --no-trunc <image>"},
            {"step": 3, "action": "Extract layers: docker save | tar -xf - and grep for secrets"},
        ],
        "detection": ["Secret scanning in CI (Gitleaks, Trivy)", "Registry webhook scan"],
        "mitigations": ["Multi-stage builds", "Docker BuildKit secret mounts", "SBOM + Trivy scan"],
        "tools": ["docker", "Trivy", "dive"],
    },
]

ALL_TECHNIQUES = K8S_TECHNIQUES + CONTAINER_TECHNIQUES

CATEGORIES = {
    "k8s": {"label": "Kubernetes", "count": len(K8S_TECHNIQUES), "icon": "Server"},
    "container": {"label": "Container", "count": len(CONTAINER_TECHNIQUES), "icon": "Box"},
}


def list_techniques(category=None):
    if category == "k8s":
        return K8S_TECHNIQUES
    if category == "container":
        return CONTAINER_TECHNIQUES
    return ALL_TECHNIQUES


def get_technique(tid):
    return next((t for t in ALL_TECHNIQUES if t["id"] == tid), None)


def simulate_technique(tid, target):
    t = get_technique(tid)
    if not t:
        raise ValueError(f"Technique {tid} not found")
    return {
        "technique_id": tid,
        "technique_name": t["name"],
        "tactic": t["tactic"],
        "severity": t["severity"],
        "target": target,
        "status": "simulated",
        "kill_chain": t["kill_chain"],
        "findings": [
            f"[SIMULADO] {t['name']} contra {target}",
            f"Impacto: {t['description']}",
        ],
    }
