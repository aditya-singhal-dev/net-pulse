"""Bound and poll user-triggered diagnostic jobs without blocking Streamlit."""

from concurrent.futures import ThreadPoolExecutor
from threading import BoundedSemaphore
from typing import Any, Callable

import streamlit as st


@st.cache_resource
def _job_pool() -> tuple[ThreadPoolExecutor, BoundedSemaphore]:
    return ThreadPoolExecutor(max_workers=2, thread_name_prefix="netpulse-tool"), BoundedSemaphore(2)


def is_running(key: str) -> bool:
    return f"{key}_job" in st.session_state


def submit(key: str, work: Callable[..., Any], *args: Any, **kwargs: Any) -> None:
    if is_running(key):
        return
    pool, slots = _job_pool()
    if not slots.acquire(blocking=False):
        st.warning("Other diagnostics are running. Try again when a slot is free.")
        return
    try:
        future = pool.submit(work, *args, **kwargs)
    except BaseException:
        slots.release()
        raise
    future.add_done_callback(lambda _: slots.release())
    st.session_state[f"{key}_job"] = future
    st.session_state.pop(f"{key}_result", None)
    st.rerun()


@st.fragment(run_every=1)
def _watch(key: str) -> None:
    future = st.session_state[f"{key}_job"]
    if future.done():
        del st.session_state[f"{key}_job"]
        try:
            st.session_state[f"{key}_result"] = (future.result(), None)
        except Exception as exc:
            st.session_state[f"{key}_result"] = (None, str(exc) or type(exc).__name__)
        st.rerun()
    st.info("Diagnostic in progress…")


def result(key: str) -> Any:
    if is_running(key):
        _watch(key)
        return None
    value, error = st.session_state.get(f"{key}_result", (None, None))
    if error is not None:
        st.error(error)
    return value
