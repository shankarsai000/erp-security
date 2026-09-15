import re
from typing import Dict, List, Optional, Tuple

class RouteRule:
    def __init__(self, pattern: str, methods: List[str], auth_required: bool = True, roles: Optional[List[str]] = None):
        self.raw_pattern = pattern
        self.methods = [m.upper() for m in methods]
        self.auth_required = auth_required
        self.roles = roles or []
        
        # Convert path pattern with {id} into regex
        # e.g., /api/orders/{id} -> ^/api/orders/[^/]+$
        regex_str = "^" + re.sub(r"\{[a-zA-Z_0-9]+\}", r"[^/]+", pattern) + "$"
        self.regex = re.compile(regex_str)

    def matches(self, path: str) -> bool:
        return bool(self.regex.match(path))

class RouteAllowlist:
    def __init__(self):
        self.routes: List[RouteRule] = [
            RouteRule("/health", ["GET"], auth_required=False),
            RouteRule("/api/auth/login", ["POST"], auth_required=False),
            RouteRule("/api/orders", ["GET", "POST"], auth_required=True, roles=["sales", "manager", "admin"]),
            RouteRule("/api/orders/{id}", ["GET", "PUT", "DELETE"], auth_required=True, roles=["sales", "manager", "admin"]),
            RouteRule("/api/users/{id}", ["GET", "PUT"], auth_required=True, roles=["user", "manager", "admin"]),
            RouteRule("/api/inventory", ["GET"], auth_required=True, roles=["warehouse", "sales", "manager", "admin"]),
        ]

    def validate_route(self, path: str, method: str) -> Tuple[bool, bool, Optional[RouteRule], str]:
        """
        Validates if route is allowlisted and method is permitted.
        Returns: (is_path_known, is_method_allowed, matching_rule, reason)
        """
        method = method.upper()
        matching_rule = None
        for rule in self.routes:
            if rule.matches(path):
                matching_rule = rule
                break
                
        if not matching_rule:
            return False, False, None, f"Endpoint '{path}' is not registered in API catalog"
            
        if method not in matching_rule.methods:
            return True, False, matching_rule, f"HTTP method '{method}' not permitted on endpoint '{path}'"
            
        return True, True, matching_rule, "Route validated"

route_allowlist = RouteAllowlist()
