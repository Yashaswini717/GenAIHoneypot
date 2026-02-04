import re
from typing import Any

from core.utils import calculate_entropy

from .base import BaseValidator, ValidationResult


class RealismValidator(BaseValidator):
    """Validate realism and authenticity of generated content."""

    async def validate(self, content: str, context: dict[str, Any] | None = None) -> ValidationResult:
        """
        Score content realism from 0.0 to 1.0.

        Args:
            content: Content to validate
            context: Additional context (file_type, content_type)

        Returns:
            ValidationResult with realism score
        """
        context = context or {}
        file_type = context.get("file_type", "unknown")
        
        # Calculate individual scores
        entropy_score = self._calculate_entropy_score(content)
        pattern_score = self._calculate_pattern_score(content, file_type)
        structure_score = self._calculate_structure_score(content, file_type)
        authenticity_score = self._calculate_authenticity_score(content)
        
        # Weighted average
        total_score = (
            entropy_score * 0.2 +
            pattern_score * 0.3 +
            structure_score * 0.3 +
            authenticity_score * 0.2
        )
        
        warnings = []
        if total_score < 0.5:
            warnings.append("Content may not be realistic enough")
        if entropy_score < 0.3:
            warnings.append("Low entropy - content may be too repetitive")
        
        self.logger.debug(
            "realism_validation",
            file_type=file_type,
            total_score=total_score,
            entropy=entropy_score,
            pattern=pattern_score,
            structure=structure_score,
            authenticity=authenticity_score,
        )
        
        return self._create_result(
            valid=total_score >= 0.7,
            score=total_score,
            warnings=warnings,
            entropy_score=entropy_score,
            pattern_score=pattern_score,
            structure_score=structure_score,
            authenticity_score=authenticity_score,
        )

    def _calculate_entropy_score(self, content: str) -> float:
        """Calculate entropy-based score (0.0-1.0)."""
        if not content:
            return 0.0
        
        entropy = calculate_entropy(content)
        
        # Normalize entropy to 0-1 range
        # Good content typically has entropy between 3-6
        normalized = min(entropy / 6.0, 1.0)
        return normalized

    def _calculate_pattern_score(self, content: str, file_type: str) -> float:
        """Calculate score based on expected patterns."""
        score = 0.0
        checks = 0
        
        if file_type == "python":
            checks = 5
            # Check for common Python patterns
            if re.search(r'\bdef\s+\w+\(', content):
                score += 1
            if re.search(r'\bimport\s+\w+', content):
                score += 1
            if re.search(r'\bclass\s+\w+', content) or "if __name__" in content:
                score += 1
            if any(kw in content for kw in ["try:", "except", "with", "for", "while"]):
                score += 1
            if content.count('\n') > 10:  # Reasonable length
                score += 1
                
        elif file_type == "javascript":
            checks = 5
            if re.search(r'\bfunction\s+\w+\(', content) or "=>" in content:
                score += 1
            if any(kw in content for kw in ["const", "let", "var"]):
                score += 1
            if any(kw in content for kw in ["async", "await", "promise", "Promise"]):
                score += 1
            if re.search(r'\brequire\(|import\s+', content):
                score += 1
            if content.count('\n') > 10:
                score += 1
                
        elif file_type == "shell":
            checks = 5
            if content.startswith("#!"):
                score += 1
            if re.search(r'\bif\s+\[', content):
                score += 1
            if any(cmd in content for cmd in ["echo", "mkdir", "cd", "cp", "mv"]):
                score += 1
            if "$" in content:  # Variables
                score += 1
            if content.count('\n') > 5:
                score += 1
                
        elif file_type in ["yaml", "docker_compose"]:
            checks = 4
            if ":" in content and "\n" in content:
                score += 1
            if content.startswith((' ', '-')) or '\n ' in content:  # Indentation
                score += 1
            if content.count('\n') > 5:
                score += 1
            if not re.search(r'\t', content):  # No tabs (YAML uses spaces)
                score += 1
                
        elif file_type == "nginx":
            checks = 4
            if "server" in content or "location" in content:
                score += 1
            if "{" in content and "}" in content:
                score += 1
            if ";" in content:
                score += 1
            if any(kw in content for kw in ["listen", "server_name", "root", "proxy_pass"]):
                score += 1
                
        else:
            # Generic checks
            checks = 3
            if content.count('\n') > 5:
                score += 1
            if len(content) > 100:
                score += 1
            if not content.isspace():
                score += 1
        
        return score / checks if checks > 0 else 0.5

    def _calculate_structure_score(self, content: str, file_type: str) -> float:
        """Calculate score based on structural elements."""
        score = 0.0
        
        # Check for comments
        if "#" in content or "//" in content or "/*" in content:
            score += 0.2
        
        # Check for proper indentation
        lines = content.split('\n')
        indented_lines = sum(1 for line in lines if line.startswith((' ', '\t')))
        if len(lines) > 0:
            indent_ratio = indented_lines / len(lines)
            if 0.2 < indent_ratio < 0.8:  # Reasonable indentation
                score += 0.2
        
        # Check for reasonable line lengths
        if lines:
            avg_line_length = sum(len(line) for line in lines) / len(lines)
            if 10 < avg_line_length < 120:
                score += 0.2
        
        # Check for empty lines (formatting)
        empty_lines = sum(1 for line in lines if not line.strip())
        if empty_lines > 0 and empty_lines < len(lines) * 0.3:
            score += 0.2
        
        # Check for reasonable total length
        if 100 < len(content) < 10000:
            score += 0.2
        
        return min(score, 1.0)

    def _calculate_authenticity_score(self, content: str) -> float:
        """Calculate score based on authenticity markers."""
        score = 1.0
        warnings = []
        
        # Penalize placeholder text
        placeholders = [
            "TODO", "FIXME", "XXX",
            "placeholder", "example.com",
            "foo", "bar", "baz",
            "test123", "password123",
            "replace_this", "change_me",
        ]
        
        content_lower = content.lower()
        placeholder_count = sum(1 for p in placeholders if p.lower() in content_lower)
        
        # Small penalty for each placeholder (some TODOs are realistic)
        score -= min(placeholder_count * 0.05, 0.3)
        
        # Check for overly repetitive content
        lines = content.split('\n')
        if len(lines) > 5:
            unique_lines = len(set(lines))
            repetition_ratio = unique_lines / len(lines)
            if repetition_ratio < 0.5:
                score -= 0.2
        
        # Check for suspiciously perfect formatting (no human errors)
        # Real code has some inconsistencies
        if len(content) > 200:
            # Check if all indentation is perfectly consistent
            indent_styles = set()
            for line in lines:
                if line and line[0] in (' ', '\t'):
                    indent = len(line) - len(line.lstrip())
                    indent_styles.add(indent)
            
            # Too perfect = suspicious
            if len(indent_styles) == 1 and len(lines) > 20:
                score -= 0.1
        
        return max(score, 0.0)
