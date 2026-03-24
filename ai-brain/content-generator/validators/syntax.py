import ast
import json
import re
import subprocess
from typing import Any

import yaml

from core.exceptions import SyntaxValidationError

from .base import BaseValidator, ValidationResult


class SyntaxValidator(BaseValidator):
    """Validate syntax of various file types."""

    async def validate(self, content: str, context: dict[str, Any] | None = None) -> ValidationResult:
        """
        Validate syntax based on file type.

        Args:
            content: Content to validate
            context: Must contain 'file_type' key

        Returns:
            ValidationResult
        """
        if not context or "file_type" not in context:
            return self._create_result(False, errors=["file_type not specified in context"])

        file_type = context["file_type"]
        
        validators = {
            "python": self._validate_python,
            "javascript": self._validate_javascript,
            "shell": self._validate_shell,
            "go": self._validate_go,
            "yaml": self._validate_yaml,
            "json": self._validate_json,
            "nginx": self._validate_nginx,
        }

        validator_func = validators.get(file_type, self._validate_generic)
        
        try:
            return await validator_func(content, context)
        except Exception as e:
            self.logger.error("syntax_validation_error", file_type=file_type, error=str(e))
            return self._create_result(False, errors=[str(e)])

    async def _validate_python(self, content: str, context: dict[str, Any]) -> ValidationResult:
        """Validate Python syntax."""
        try:
            ast.parse(content)
            return self._create_result(True, file_type="python")
        except SyntaxError as e:
            return self._create_result(
                False,
                errors=[f"Python syntax error at line {e.lineno}: {e.msg}"],
            )

    async def _validate_javascript(self, content: str, context: dict[str, Any]) -> ValidationResult:
        """Validate JavaScript syntax using regex patterns."""
        errors = []
        warnings = []

        # Check for balanced braces
        if content.count("{") != content.count("}"):
            errors.append("Unbalanced curly braces")

        # Check for balanced parentheses
        if content.count("(") != content.count(")"):
            errors.append("Unbalanced parentheses")

        # Check for balanced brackets
        if content.count("[") != content.count("]"):
            errors.append("Unbalanced brackets")

        # Check for common syntax patterns
        if "function" in content or "const" in content or "let" in content or "var" in content:
            # Looks like JavaScript
            pass
        else:
            warnings.append("Content may not be JavaScript")

        return self._create_result(
            len(errors) == 0,
            score=1.0 if not errors else 0.0,
            errors=errors,
            warnings=warnings,
        )

    async def _validate_shell(self, content: str, context: dict[str, Any]) -> ValidationResult:
        """Validate shell script syntax."""
        errors = []
        warnings = []

        # Check for shebang
        if not content.startswith("#!"):
            warnings.append("Missing shebang line")

        # Check for balanced quotes
        single_quotes = content.count("'") - content.count("\\'")
        if single_quotes % 2 != 0:
            errors.append("Unbalanced single quotes")

        double_quotes = content.count('"') - content.count('\\"')
        if double_quotes % 2 != 0:
            errors.append("Unbalanced double quotes")

        # Check common shell constructs
        if_count = len(re.findall(r'\bif\b', content))
        fi_count = len(re.findall(r'\bfi\b', content))
        if if_count != fi_count:
            errors.append("Unbalanced if/fi statements")

        return self._create_result(
            len(errors) == 0,
            score=1.0 if not errors else 0.5,
            errors=errors,
            warnings=warnings,
        )

    async def _validate_go(self, content: str, context: dict[str, Any]) -> ValidationResult:
        """Validate Go syntax using basic checks."""
        errors = []
        warnings = []

        # Check for package declaration
        if not re.search(r'^package\s+\w+', content, re.MULTILINE):
            errors.append("Missing package declaration")

        # Check balanced braces
        if content.count("{") != content.count("}"):
            errors.append("Unbalanced curly braces")

        # Check for func keyword
        if "func" not in content:
            warnings.append("No functions defined")

        return self._create_result(
            len(errors) == 0,
            score=1.0 if not errors else 0.5,
            errors=errors,
            warnings=warnings,
        )

    async def _validate_yaml(self, content: str, context: dict[str, Any]) -> ValidationResult:
        """Validate YAML syntax."""
        try:
            yaml.safe_load(content)
            return self._create_result(True, file_type="yaml")
        except yaml.YAMLError as e:
            return self._create_result(False, errors=[f"YAML syntax error: {str(e)}"])

    async def _validate_json(self, content: str, context: dict[str, Any]) -> ValidationResult:
        """Validate JSON syntax."""
        try:
            json.loads(content)
            return self._create_result(True, file_type="json")
        except json.JSONDecodeError as e:
            return self._create_result(
                False,
                errors=[f"JSON syntax error at line {e.lineno}: {e.msg}"],
            )

    async def _validate_nginx(self, content: str, context: dict[str, Any]) -> ValidationResult:
        """Validate nginx configuration syntax."""
        errors = []
        warnings = []

        # Check for balanced braces
        if content.count("{") != content.count("}"):
            errors.append("Unbalanced curly braces")

        # Check for semicolons on directives
        lines = content.split('\n')
        for i, line in enumerate(lines, 1):
            line = line.strip()
            if line and not line.startswith('#') and not line.endswith(('{', '}', ';')):
                if line:  # Not empty
                    warnings.append(f"Line {i} may be missing semicolon")

        # Check for required directives
        if "server" not in content and "http" not in content:
            warnings.append("No server or http block found")

        return self._create_result(
            len(errors) == 0,
            score=1.0 if not errors else 0.5,
            errors=errors,
            warnings=warnings,
        )

    async def _validate_generic(self, content: str, context: dict[str, Any]) -> ValidationResult:
        """Generic validation for unknown types."""
        warnings = ["No specific validator for this file type"]
        
        # Basic checks - fix operator precedence
        is_valid = len(content) > 0 and (content.isprintable() or '\n' in content)
        
        return self._create_result(
            is_valid,
            score=0.8,  # Lower score for generic validation
            warnings=warnings,
        )
