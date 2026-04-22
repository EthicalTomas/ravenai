"""core/scheduler.py

Resilient pipeline scheduler with per-stage retry and skip-on-failure support.

Architecture role: sits between Pipeline and Engine, owning all fault-tolerance
policy so that individual Stage failures never propagate upward and halt the
pipeline unless configured to do so.

Data contract: all inter-stage values must be structured objects (never raw
strings), enforced here just as Engine already enforces it.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Callable

from core.engine import Stage, StageExecutionError
from data.models import Target


LOGGER = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuration dataclass (populated from YAML – no hardcoded values)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class StagePolicy:
    """Retry and skip policy for a single named stage."""

    stage_name: str
    max_attempts: int
    retry_delay_seconds: float
    skip_on_failure: bool


@dataclass(frozen=True, slots=True)
class SchedulerConfig:
    """Top-level scheduler configuration loaded from settings.yaml.

    Fields
    ------
    default_max_attempts:
        Retry cap used when a stage has no explicit StagePolicy.
    default_retry_delay_seconds:
        Wait between retries when no explicit StagePolicy is set.
    default_skip_on_failure:
        When True a stage whose retries are exhausted is skipped rather than
        aborting the entire pipeline.
    stage_policies:
        Per-stage overrides keyed by stage name.
    """

    default_max_attempts: int
    default_retry_delay_seconds: float
    default_skip_on_failure: bool
    stage_policies: dict[str, StagePolicy] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


class StageOutcome(Enum):
    """Terminal disposition of a single stage execution attempt sequence."""

    SUCCESS = auto()
    SKIPPED = auto()
    FAILED = auto()


@dataclass(slots=True)
class StageResult:
    """Structured outcome returned after a stage is scheduled."""

    stage_name: str
    outcome: StageOutcome
    output: object | None
    attempts: int
    last_error: Exception | None = None

    def succeeded(self) -> bool:
        return self.outcome is StageOutcome.SUCCESS

    def was_skipped(self) -> bool:
        return self.outcome is StageOutcome.SKIPPED


@dataclass(slots=True)
class SchedulerRun:
    """Aggregated result for a complete scheduler execution across all stages."""

    target_domain: str
    stage_results: list[StageResult] = field(default_factory=list)
    final_output: object | None = None

    def succeeded(self) -> bool:
        return all(
            sr.outcome in (StageOutcome.SUCCESS, StageOutcome.SKIPPED)
            for sr in self.stage_results
        )

    def failed_stages(self) -> list[StageResult]:
        return [sr for sr in self.stage_results if sr.outcome is StageOutcome.FAILED]

    def skipped_stages(self) -> list[StageResult]:
        return [sr for sr in self.stage_results if sr.outcome is StageOutcome.SKIPPED]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _resolve_policy(
    stage_name: str,
    config: SchedulerConfig,
) -> tuple[int, float, bool]:
    """Return (max_attempts, retry_delay_seconds, skip_on_failure) for a stage.

    Per-stage policy takes precedence; falls back to config defaults.
    """
    if stage_name in config.stage_policies:
        policy = config.stage_policies[stage_name]
        return policy.max_attempts, policy.retry_delay_seconds, policy.skip_on_failure
    return (
        config.default_max_attempts,
        config.default_retry_delay_seconds,
        config.default_skip_on_failure,
    )


def _attempt_stage(
    stage: Stage,
    data: object,
    max_attempts: int,
    retry_delay_seconds: float,
    sleep_fn: Callable[[float], None],
) -> tuple[object | None, int, Exception | None]:
    """Try executing a stage up to *max_attempts* times.

    Returns
    -------
    (output, attempts_used, last_exception)
        output is None when all attempts fail.
    """
    last_error: Exception | None = None

    for attempt in range(1, max_attempts + 1):
        try:
            LOGGER.debug(
                "Stage '%s' attempt %d/%d starting", stage.name, attempt, max_attempts
            )
            output = stage.execute(data)

            if isinstance(output, str):
                raise TypeError(
                    f"Stage '{stage.name}' returned a raw string – structured objects required."
                )

            LOGGER.debug("Stage '%s' attempt %d succeeded", stage.name, attempt)
            return output, attempt, None

        except (StageExecutionError, Exception) as exc:  # noqa: BLE001
            last_error = exc
            # Isolation check: specific log for failure
            LOGGER.warning(
                "Isolating failure in stage '%s' (Attempt %d/%d). Error: %s",
                stage.name,
                attempt,
                max_attempts,
                exc,
            )
            # If we're at the last attempt, we let the scheduler decide skip/fail
            if attempt < max_attempts:
                LOGGER.debug(
                    "Waiting %.2fs before retry of stage '%s'",
                    retry_delay_seconds,
                    stage.name,
                )
                sleep_fn(retry_delay_seconds)

    return None, max_attempts, last_error


# ---------------------------------------------------------------------------
# Scheduler
# ---------------------------------------------------------------------------


class Scheduler:
    """Resilient stage runner with configurable retry and skip-on-failure policy.

    Usage
    -----
    ::

        config = SchedulerConfig(
            default_max_attempts=3,
            default_retry_delay_seconds=1.0,
            default_skip_on_failure=True,
        )
        scheduler = Scheduler(config=config)
        scheduler.add_stage(recon_stage)
        scheduler.add_stage(scan_stage)

        run = scheduler.run(target)
        if not run.succeeded():
            for sr in run.failed_stages():
                logger.error("Stage %s ultimately failed", sr.stage_name)
    """

    def __init__(
        self,
        config: SchedulerConfig,
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> None:
        if config.default_max_attempts < 1:
            raise ValueError("SchedulerConfig.default_max_attempts must be >= 1")
        if config.default_retry_delay_seconds < 0:
            raise ValueError(
                "SchedulerConfig.default_retry_delay_seconds must be >= 0"
            )

        self._config = config
        self._stages: list[Stage] = []
        self._sleep_fn = sleep_fn

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_stage(self, stage: Stage) -> None:
        """Append a stage to the execution sequence."""
        self._stages.append(stage)
        LOGGER.debug("Scheduler registered stage '%s'", stage.name)

    def run(self, target: Target) -> SchedulerRun:
        """Execute all registered stages sequentially, applying retry/skip policy.

        Parameters
        ----------
        target:
            The :class:`~data.models.Target` that seeds the pipeline.

        Returns
        -------
        SchedulerRun
            Aggregated result; always returns – never raises.
        """
        LOGGER.info(
            "Scheduler run started for domain '%s' with %d stage(s)",
            target.domain,
            len(self._stages),
        )

        run = SchedulerRun(target_domain=target.domain)
        current_data: object = target

        for stage in self._stages:
            stage_result = self._run_stage(stage=stage, data=current_data)
            run.stage_results.append(stage_result)

            if stage_result.succeeded():
                current_data = stage_result.output
                LOGGER.info("Scheduler: stage '%s' succeeded", stage.name)

            elif stage_result.was_skipped():
                LOGGER.warning(
                    "Scheduler: stage '%s' was skipped after %d attempt(s); "
                    "downstream stages will receive the previous stage's output.",
                    stage.name,
                    stage_result.attempts,
                )
                # current_data stays unchanged – downstream stage receives prior output

            else:
                # outcome is FAILED and skip_on_failure was False
                LOGGER.error(
                    "Scheduler: stage '%s' failed fatally after %d attempt(s). "
                    "Aborting remaining %d stage(s).",
                    stage.name,
                    stage_result.attempts,
                    len(self._stages) - self._stages.index(stage) - 1,
                )
                run.final_output = None
                return run

        run.final_output = current_data
        LOGGER.info(
            "Scheduler run finished. succeeded=%s skipped=%d failed=%d",
            run.succeeded(),
            len(run.skipped_stages()),
            len(run.failed_stages()),
        )
        return run

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _run_stage(self, stage: Stage, data: object) -> StageResult:
        """Apply retry policy to a single stage and return a StageResult."""
        max_attempts, retry_delay_seconds, skip_on_failure = _resolve_policy(
            stage.name, self._config
        )

        LOGGER.info(
            "Scheduler: executing stage '%s' (max_attempts=%d, skip_on_failure=%s)",
            stage.name,
            max_attempts,
            skip_on_failure,
        )

        output, attempts_used, last_error = _attempt_stage(
            stage=stage,
            data=data,
            max_attempts=max_attempts,
            retry_delay_seconds=retry_delay_seconds,
            sleep_fn=self._sleep_fn,
        )

        if output is not None:
            return StageResult(
                stage_name=stage.name,
                outcome=StageOutcome.SUCCESS,
                output=output,
                attempts=attempts_used,
            )

        # All attempts exhausted
        LOGGER.error(
            "Stage '%s' exhausted all %d attempt(s). Last error: %s",
            stage.name,
            max_attempts,
            last_error,
        )

        if skip_on_failure:
            return StageResult(
                stage_name=stage.name,
                outcome=StageOutcome.SKIPPED,
                output=None,
                attempts=attempts_used,
                last_error=last_error,
            )

        return StageResult(
            stage_name=stage.name,
            outcome=StageOutcome.FAILED,
            output=None,
            attempts=attempts_used,
            last_error=last_error,
        )


# ---------------------------------------------------------------------------
# Config loader helper (no config values hardcoded in module)
# ---------------------------------------------------------------------------


def build_scheduler_config(raw: dict[str, object]) -> SchedulerConfig:
    """Build a :class:`SchedulerConfig` from a raw YAML mapping.

    Expected YAML shape::

        scheduler:
          default_max_attempts: 3
          default_retry_delay_seconds: 1.0
          default_skip_on_failure: true
          stage_policies:
            ReconStage:
              max_attempts: 2
              retry_delay_seconds: 0.5
              skip_on_failure: true
            ScanStage:
              max_attempts: 4
              retry_delay_seconds: 2.0
              skip_on_failure: false

    Parameters
    ----------
    raw:
        The ``scheduler`` sub-mapping extracted from the full settings dict.
    """
    if not isinstance(raw, dict):
        raise TypeError("scheduler config must be a YAML mapping")

    default_max_attempts = _require_positive_int(raw, "default_max_attempts")
    default_retry_delay_seconds = _require_non_negative_float(
        raw, "default_retry_delay_seconds"
    )
    default_skip_on_failure = _require_bool(raw, "default_skip_on_failure")

    stage_policies: dict[str, StagePolicy] = {}
    policies_raw = raw.get("stage_policies", {})
    if not isinstance(policies_raw, dict):
        raise TypeError("scheduler.stage_policies must be a YAML mapping")

    for stage_name, policy_raw in policies_raw.items():
        if not isinstance(stage_name, str) or not stage_name.strip():
            raise ValueError("stage_policies keys must be non-empty strings")
        if not isinstance(policy_raw, dict):
            raise TypeError(
                f"scheduler.stage_policies.{stage_name} must be a YAML mapping"
            )
        stage_policies[stage_name.strip()] = StagePolicy(
            stage_name=stage_name.strip(),
            max_attempts=_require_positive_int(policy_raw, "max_attempts"),
            retry_delay_seconds=_require_non_negative_float(
                policy_raw, "retry_delay_seconds"
            ),
            skip_on_failure=_require_bool(policy_raw, "skip_on_failure"),
        )

    return SchedulerConfig(
        default_max_attempts=default_max_attempts,
        default_retry_delay_seconds=default_retry_delay_seconds,
        default_skip_on_failure=default_skip_on_failure,
        stage_policies=stage_policies,
    )


# ---------------------------------------------------------------------------
# Private config parsing helpers (module-local, never hardcoded)
# ---------------------------------------------------------------------------


def _require_positive_int(mapping: dict[str, object], key: str) -> int:
    value = mapping.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"scheduler config '{key}' must be an integer, got {value!r}")
    if value < 1:
        raise ValueError(f"scheduler config '{key}' must be >= 1, got {value}")
    return value


def _require_non_negative_float(mapping: dict[str, object], key: str) -> float:
    value = mapping.get(key)
    if isinstance(value, bool):
        raise TypeError(
            f"scheduler config '{key}' must be a float or int, got {value!r}"
        )
    if isinstance(value, int):
        value = float(value)
    if not isinstance(value, float):
        raise TypeError(
            f"scheduler config '{key}' must be a float or int, got {value!r}"
        )
    if value < 0:
        raise ValueError(f"scheduler config '{key}' must be >= 0, got {value}")
    return value


def _require_bool(mapping: dict[str, object], key: str) -> bool:
    value = mapping.get(key)
    if not isinstance(value, bool):
        raise TypeError(f"scheduler config '{key}' must be a boolean, got {value!r}")
    return value
