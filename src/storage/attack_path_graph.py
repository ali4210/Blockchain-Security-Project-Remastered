"""
AI-driven Attack-Path Knowledge Graph (Task P04-003).
Tracks cross-protocol threat chaining as a Directed Acyclic Graph (DAG).
Provides path enumeration and remediation planning queried by Agent B via MCP tools.
"""

from typing import Any, Dict, List, Optional
import hashlib
import networkx as nx


class AttackPathGraph:
    """
    Synthesizes and analyzes attack trajectories across contracts and findings
    using NetworkX directed acyclic graphs.
    """

    def __init__(self):
        self.graph = nx.DiGraph()
        self._path_registry: Dict[str, Dict[str, Any]] = {}

    def add_finding_node(self, finding: Dict[str, Any]) -> str:
        """Adds a normalized finding as a node in the attack graph."""
        node_id = str(finding.get("id") or finding.get("finding_id") or "FINDING-UNKNOWN")
        severity = str(finding.get("severity", "MEDIUM")).upper()
        target = str(finding.get("target", "contract"))
        title = str(finding.get("title", "Security Finding"))
        dread = finding.get("dread", {})
        dread_score = float(dread.get("score", 5.0) if isinstance(dread, dict) else 5.0)

        self.graph.add_node(
            node_id,
            node_type="finding",
            severity=severity,
            target=target,
            title=title,
            dread_score=dread_score,
            details=finding,
        )
        return node_id

    def add_target_node(self, target_name: str, target_type: str = "contract") -> str:
        """Adds an architectural target node (contract, vault, pool)."""
        node_id = f"TARGET:{target_name}"
        if not self.graph.has_node(node_id):
            self.graph.add_node(
                node_id,
                node_type="target",
                name=target_name,
                target_type=target_type,
            )
        return node_id

    def add_attack_step(
        self,
        from_node: str,
        to_node: str,
        step_type: str = "exploits",
        weight: float = 1.0,
    ) -> bool:
        """
        Adds a directed exploitation edge while strictly enforcing DAG invariants.
        Returns True if added successfully, False if edge would create a cycle.
        """
        self.graph.add_edge(from_node, to_node, step_type=step_type, weight=weight)
        if not nx.is_directed_acyclic_graph(self.graph):
            # Remove edge to preserve acyclic invariant
            self.graph.remove_edge(from_node, to_node)
            return False
        return True

    def build_from_findings(self, findings: List[Dict[str, Any]]) -> None:
        """Synthesizes an attack graph from a list of normalized findings."""
        entry_node = "ENTRY:external_attacker"
        self.graph.add_node(entry_node, node_type="actor", name="External Attacker")

        for f in findings:
            f_node = self.add_finding_node(f)
            target_name = str(f.get("target", "TargetContract"))
            t_node = self.add_target_node(target_name)

            # Link entry to finding
            self.add_attack_step(entry_node, f_node, step_type="targets", weight=1.0)
            # Link finding to compromised target
            sev = str(f.get("severity", "MEDIUM")).upper()
            w = 3.0 if sev == "CRITICAL" else (2.0 if sev == "HIGH" else 1.0)
            self.add_attack_step(f_node, t_node, step_type="compromises", weight=w)

        self._index_paths()

    def _index_paths(self) -> None:
        """Enumerates and indexes simple attack paths from entry actors to targets."""
        self._path_registry.clear()
        entry_nodes = [n for n, d in self.graph.nodes(data=True) if d.get("node_type") == "actor"]
        target_nodes = [n for n, d in self.graph.nodes(data=True) if d.get("node_type") == "target"]

        idx = 1
        for src in entry_nodes:
            for dst in target_nodes:
                if nx.has_path(self.graph, src, dst):
                    for path in nx.all_simple_paths(self.graph, src, dst):
                        total_weight = 0.0
                        dread_scores: List[float] = []

                        for node in path:
                            data = self.graph.nodes[node]
                            if "dread_score" in data:
                                dread_scores.append(float(data["dread_score"]))

                        for u, v in zip(path[:-1], path[1:]):
                            total_weight += float(self.graph.edges[u, v].get("weight", 1.0))

                        avg_dread = sum(dread_scores) / len(dread_scores) if dread_scores else 5.0
                        raw_id = f"{src}->{dst}:{':'.join(path)}"
                        path_id = f"PATH-{hashlib.sha256(raw_id.encode()).hexdigest()[:8].upper()}"

                        self._path_registry[path_id] = {
                            "path_id": path_id,
                            "entry": src,
                            "target": dst,
                            "steps": path,
                            "cumulative_weight": total_weight,
                            "average_dread": round(avg_dread, 2),
                            "length": len(path) - 1,
                        }
                        idx += 1

    def list_attack_paths(self) -> List[Dict[str, Any]]:
        """Returns all synthesized attack trajectories sorted by risk weight descending."""
        if not self._path_registry:
            self._index_paths()
        paths = list(self._path_registry.values())
        paths.sort(key=lambda p: (p.get("cumulative_weight", 0), p.get("average_dread", 0)), reverse=True)
        return paths

    def plan_remediation(self, path_id: str) -> Dict[str, Any]:
        """Synthesizes remediation priority recommendations for a specific attack path."""
        if path_id not in self._path_registry:
            return {
                "status": "not_found",
                "path_id": path_id,
                "remediations": [],
                "summary": f"Attack path '{path_id}' not found in knowledge graph."
            }

        path_info = self._path_registry[path_id]
        remediations: List[Dict[str, Any]] = []

        for node in path_info["steps"]:
            data = self.graph.nodes.get(node, {})
            if data.get("node_type") == "finding":
                remediations.append({
                    "node_id": node,
                    "target": data.get("target"),
                    "vulnerability": data.get("title"),
                    "severity": data.get("severity"),
                    "action": f"Apply defense-in-depth mitigations to resolve {data.get('title')} on {data.get('target')}.",
                })

        return {
            "status": "planned",
            "path_id": path_id,
            "target": path_info["target"],
            "remediation_count": len(remediations),
            "remediations": remediations,
            "summary": f"Identified {len(remediations)} choke-point remediation(s) to sever attack trajectory {path_id}."
        }


# Global/module-level default graph instance for legacy and MCP imports
_default_graph: Optional[AttackPathGraph] = None


def get_default_graph() -> AttackPathGraph:
    global _default_graph
    if _default_graph is None:
        _default_graph = AttackPathGraph()
    return _default_graph


def list_attack_paths() -> list:
    """Module-level entrypoint queried by Agent B."""
    return get_default_graph().list_attack_paths()


def plan_remediation(_path_id: str) -> dict:
    """Module-level entrypoint queried by Agent B."""
    return get_default_graph().plan_remediation(_path_id)
