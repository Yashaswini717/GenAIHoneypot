import re
from abc import ABC, abstractmethod
from typing import Any

from config.logging_config import LoggerMixin
from core.llm_client import LLMClient
from core.utils import AI_NARRATION_PATTERNS, AI_TRAILING_PATTERNS, ANALYSIS_LAYER_TERMS
from validators.base import ValidationResult
from validators.realism import RealismValidator
from validators.security import SecurityValidator
from validators.syntax import SyntaxValidator

# Code fence wrapper pattern (for whole-output wrapping)
_CODE_FENCE_PATTERN = re.compile(
    r'^```[\w]*\s*\n(.*?)```\s*$',
    re.DOTALL,
)

# Global code fence pattern (for any code fences in content)
_CODE_FENCE_LINE_PATTERN = re.compile(r'^```[\w]*\s*$', re.MULTILINE)

# Markdown heading pattern (only match actual document headings, not code comments)
# Actual markdown headings are typically:
# - At the start of a line
# - Followed by capitalized text  
# - Not followed by code-comment markers like TODO:, FIXME:, etc.
# - Relatively short (less than 100 chars)
# This is conservative to avoid removing legitimate code comments
_MARKDOWN_HEADING_PATTERN = re.compile(
    r'^#{1,6}\s+(?!TODO:|FIXME:|NOTE:|HACK:|WARNING:|BUG:|XXX:)[A-Z][^\n]{0,98}$', 
    re.MULTILINE
)


def scrub_over_verbose_comments(content: str, content_type: str) -> str:
    """
    Remove over-verbose developer-narration style comments from code.
    
    Only applies to source_code and config content types.
    Removes comments that sound like a developer explaining/narrating,
    not like real production code comments.
    
    Args:
        content: Content to scrub
        content_type: Type of content (source_code, config, logs, document)
    
    Returns:
        Scrubbed content
    """
    # Only apply to source code and config files
    if content_type not in ("source_code", "config"):
        return content
    
    lines = content.split('\n')
    result_lines = []
    
    # Patterns for narrating developer comments (case-insensitive)
    narrating_patterns = [
        r'intentionally insecure',
        r'for testing purposes',
        r'should never be deployed',
        r'this is a workaround',
        r'for demonstration',
        r'as an example',
        r'in a real application',
        r'in production you should',
        r'never do this in production',
        r'this is just for',
    ]
    
    # Count special comment types
    todo_count = 0
    fixme_count = 0
    
    for line in lines:
        skip_line = False
        
        # Remove HACK comments entirely
        if re.search(r'#\s*HACK:', line, re.IGNORECASE) or re.search(r'//\s*HACK:', line, re.IGNORECASE):
            skip_line = True
        
        # Remove SECURITY WARNING comments entirely
        if not skip_line and (re.search(r'#\s*SECURITY WARNING:', line, re.IGNORECASE) or re.search(r'//\s*SECURITY WARNING:', line, re.IGNORECASE)):
            skip_line = True
        
        # Limit TODO comments (max 2)
        if not skip_line and (re.search(r'#\s*TODO:', line, re.IGNORECASE) or re.search(r'//\s*TODO:', line, re.IGNORECASE)):
            todo_count += 1
            if todo_count > 2:
                skip_line = True
        
        # Limit FIXME comments (max 1)
        if not skip_line and (re.search(r'#\s*FIXME:', line, re.IGNORECASE) or re.search(r'//\s*FIXME:', line, re.IGNORECASE)):
            fixme_count += 1
            if fixme_count > 1:
                skip_line = True
        
        # Check for narrating patterns in comment sections only
        if not skip_line:
            # Extract comment portion (Python-style or C-style)
            comment_match = re.search(r'#(.+)', line)
            if not comment_match:
                comment_match = re.search(r'//(.+)', line)
            
            if comment_match:
                comment_text = comment_match.group(1).lower()
                for pattern in narrating_patterns:
                    if re.search(pattern, comment_text, re.IGNORECASE):
                        skip_line = True
                        break
        
        if not skip_line:
            result_lines.append(line)
    
    return '\n'.join(result_lines)


def sanitize_llm_output(content: str, content_type: str = "generic") -> str:
    """
    Strip AI narration artifacts from LLM output.

    Removes:
    - Preamble phrases ("Here is a...", "Below is...") - in a loop until no more matches
    - Code fence wrappers (ALL occurrences, not just whole-output)
    - Markdown headings (unless content_type is "document")
    - Trailing explanations after the main content - in a loop until no more matches
    - Over-verbose developer-narration comments (for source_code and config)
    
    Args:
        content: Content to sanitize
        content_type: Type of content (source_code, config, logs, document, generic)
    
    Returns:
        Sanitized content
    """
    result = content.strip()

    # Strip leading narration preambles (loop until no more matches)
    max_iterations = 10  # Prevent infinite loops
    for _ in range(max_iterations):
        old_result = result
        for pattern in AI_NARRATION_PATTERNS:
            result = pattern.sub('', result).lstrip()
        if result == old_result:
            break  # No more matches

    # Unwrap code fences if the entire output is wrapped
    fence_match = _CODE_FENCE_PATTERN.match(result)
    if fence_match:
        result = fence_match.group(1).strip()
    
    # Strip ALL code fence lines (not just whole-output wraps)
    # This removes ```language and ``` lines but preserves content between them
    result = _CODE_FENCE_LINE_PATTERN.sub('', result).strip()
    
    # Strip markdown headings from non-document content
    # Only strip headings at the beginning of content (not inline comments)
    if content_type != "document":
        lines = result.split('\n')
        # Only check first 5 lines for markdown headings
        stripped_lines = []
        leading_headings_done = False
        for i, line in enumerate(lines):
            if not leading_headings_done:
                # Check if this line is a markdown heading
                if _MARKDOWN_HEADING_PATTERN.match(line):
                    # Skip this heading line
                    continue
                elif line.strip():  # Found non-heading, non-empty line
                    leading_headings_done = True
                    stripped_lines.append(line)
                else:
                    # Empty line - keep it
                    stripped_lines.append(line)
            else:
                stripped_lines.append(line)
        result = '\n'.join(stripped_lines).strip()

    # Strip trailing AI narration (loop until no more matches)
    for _ in range(max_iterations):
        old_result = result
        for pattern in AI_TRAILING_PATTERNS:
            result = pattern.sub('', result).rstrip()
        if result == old_result:
            break  # No more matches
    
    # Apply verbosity scrubbing for source code and config
    result = scrub_over_verbose_comments(result, content_type)

    return result


class GeneratedContent:
    """Container for generated content with metadata."""

    def __init__(
        self,
        content: str,
        content_type: str,
        file_type: str,
        metadata: dict[str, Any] | None = None,
        validation_results: dict[str, ValidationResult] | None = None,
    ):
        self.content = content
        self.content_type = content_type
        self.file_type = file_type
        self.metadata = metadata or {}
        self.validation_results = validation_results or {}

    @property
    def is_valid(self) -> bool:
        """Check if all validations passed."""
        return all(result.valid for result in self.validation_results.values())

    @property
    def overall_score(self) -> float:
        """Calculate overall quality score."""
        if not self.validation_results:
            return 0.0
        return sum(r.score for r in self.validation_results.values()) / len(self.validation_results)

    def __repr__(self) -> str:
        return (
            f"GeneratedContent(type={self.content_type}, "
            f"length={len(self.content)}, "
            f"valid={self.is_valid}, "
            f"score={self.overall_score:.2f})"
        )


class BaseGenerator(ABC, LoggerMixin):
    """Abstract base class for content generators."""

    def __init__(self, llm_client: LLMClient):
        """
        Initialize generator.

        Args:
            llm_client: LLM client for generation
        """
        self.llm_client = llm_client
        self.syntax_validator = SyntaxValidator()
        self.realism_validator = RealismValidator()
        self.security_validator = SecurityValidator()
        
        self.logger.debug(f"{self.__class__.__name__}_initialized")

    @abstractmethod
    async def generate(self, context: dict[str, Any]) -> GeneratedContent:
        """
        Generate content based on context.

        Args:
            context: Generation context with parameters

        Returns:
            GeneratedContent instance
        """
        pass

    @abstractmethod
    def get_system_prompt(self, artifact_layer: str = "system") -> str:
        """Get system prompt for this generator."""
        pass

    @abstractmethod
    def build_prompt(self, context: dict[str, Any]) -> str:
        """Build user prompt from context."""
        pass

    async def _generate_with_llm(
        self,
        prompt: str,
        system_prompt: str | None = None,
        temperature: float | None = None,
        content_type: str = "generic",
    ) -> str:
        """
        Generate content using LLM.

        Args:
            prompt: User prompt
            system_prompt: System prompt
            temperature: Temperature override
            content_type: Type of content being generated (for sanitization)

        Returns:
            Generated text
        """
        system_prompt = system_prompt or self.get_system_prompt()
        
        self.logger.debug(
            "generating_with_llm",
            generator=self.__class__.__name__,
            prompt_length=len(prompt),
        )
        
        content = await self.llm_client.generate(
            prompt=prompt,
            system_prompt=system_prompt,
            temperature=temperature,
        )
        
        # Strip AI narration artifacts (preambles, code fences, trailing explanations)
        content = sanitize_llm_output(content, content_type=content_type)
        
        return content

    async def _validate_content(
        self,
        content: str,
        file_type: str,
        context: dict[str, Any],
    ) -> dict[str, ValidationResult]:
        """
        Validate generated content.

        Args:
            content: Content to validate
            file_type: File type for syntax validation
            context: Additional context

        Returns:
            Dictionary of validation results
        """
        validation_context = {
            "file_type": file_type,
            **context,
        }
        
        results = {}
        
        # Syntax validation
        results["syntax"] = await self.syntax_validator.validate(content, validation_context)
        
        # Realism validation
        results["realism"] = await self.realism_validator.validate(content, validation_context)
        
        # Security validation
        results["security"] = await self.security_validator.validate(content, validation_context)
        
        self.logger.info(
            "content_validated",
            generator=self.__class__.__name__,
            file_type=file_type,
            syntax_valid=results["syntax"].valid,
            realism_score=results["realism"].score,
            security_valid=results["security"].valid,
        )
        
        return results

    def _create_content(
        self,
        content: str,
        content_type: str,
        file_type: str,
        validation_results: dict[str, ValidationResult],
        **metadata: Any,
    ) -> GeneratedContent:
        """Helper to create GeneratedContent instance."""
        return GeneratedContent(
            content=content,
            content_type=content_type,
            file_type=file_type,
            metadata=metadata,
            validation_results=validation_results,
        )

    async def _generate_and_enforce(
        self,
        context: dict[str, Any],
        content_type: str,
        file_type: str,
        max_retries: int = 2,
        **metadata: Any,
    ) -> GeneratedContent:
        """
        Generate content and enforce validation with retry and scrubbing.
        
        This method:
        1. Generates content using LLM
        2. Sanitizes the output
        3. Validates the content
        4. If validation fails (specifically realism), retries up to max_retries times
        5. After exhausting retries, performs best-effort scrubbing of analysis-layer terms
        6. Returns the GeneratedContent with final validation results
        
        Args:
            context: Generation context with parameters
            content_type: Type of content (source_code, config, logs, document)
            file_type: File type for validation
            max_retries: Maximum number of retries on validation failure
            **metadata: Additional metadata to attach to result
        
        Returns:
            GeneratedContent instance with validation results
        """
        prompt = self.build_prompt(context)
        artifact_layer = context.get("artifact_layer", "system")
        system_prompt = self.get_system_prompt(artifact_layer)
        temperature = context.get("temperature")
        
        validation_context = {**context, "artifact_layer": artifact_layer}
        
        attempt = 0
        last_content = ""
        last_validation_results = {}
        
        while attempt <= max_retries:
            # Generate content
            content = await self._generate_with_llm(
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=temperature,
                content_type=content_type,
            )
            
            last_content = content
            
            # Validate content
            validation_results = await self._validate_content(
                content=content,
                file_type=file_type,
                context=validation_context,
            )
            
            last_validation_results = validation_results
            
            # Check if realism validation passed
            realism_result = validation_results.get("realism")
            if realism_result and realism_result.valid:
                # Validation passed, return successful result
                self.logger.info(
                    "generation_successful",
                    generator=self.__class__.__name__,
                    attempt=attempt,
                    realism_score=realism_result.score,
                )
                return self._create_content(
                    content=content,
                    content_type=content_type,
                    file_type=file_type,
                    validation_results=validation_results,
                    **metadata,
                )
            
            # Validation failed, log and retry if attempts remaining
            if attempt < max_retries:
                self.logger.warning(
                    "generation_failed_realism_retrying",
                    generator=self.__class__.__name__,
                    attempt=attempt,
                    realism_valid=realism_result.valid if realism_result else None,
                    realism_score=realism_result.score if realism_result else None,
                )
                attempt += 1
            else:
                break
        
        # All retries exhausted, perform best-effort scrubbing
        self.logger.warning(
            "generation_failed_after_retries_scrubbing",
            generator=self.__class__.__name__,
            max_retries=max_retries,
        )
        
        # Best-effort scrub: remove lines containing analysis-layer terms
        scrubbed_content = self._scrub_analysis_terms(last_content)
        
        # Strip any remaining code fences
        scrubbed_content = _CODE_FENCE_LINE_PATTERN.sub('', scrubbed_content).strip()
        
        # Re-validate scrubbed content
        final_validation_results = await self._validate_content(
            content=scrubbed_content,
            file_type=file_type,
            context=validation_context,
        )
        
        return self._create_content(
            content=scrubbed_content,
            content_type=content_type,
            file_type=file_type,
            validation_results=final_validation_results,
            **metadata,
        )
    
    def _scrub_analysis_terms(self, content: str) -> str:
        """
        Remove lines containing analysis-layer terms.
        
        This is a best-effort scrubbing when generation repeatedly fails validation.
        
        Args:
            content: Content to scrub
        
        Returns:
            Scrubbed content
        """
        lines = content.split('\n')
        scrubbed_lines = []
        
        for line in lines:
            # Check if line contains any analysis-layer terms
            has_analysis_term = False
            line_lower = line.lower()
            for term in ANALYSIS_LAYER_TERMS:
                if term.lower() in line_lower:
                    has_analysis_term = True
                    break
            
            if not has_analysis_term:
                scrubbed_lines.append(line)
        
        return '\n'.join(scrubbed_lines)
